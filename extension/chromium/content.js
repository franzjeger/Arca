// Content script: detect login forms and offer autofill.
//
// For login identifiers and password fields we attach a small key badge. Clicking it
// asks the background worker (which relays to the desktop app via the native
// host) for logins matching the current site, and renders a picker. Selecting
// one fills the username + password fields.
//
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (window.__sybrPasswordsInjected) return;
  window.__sybrPasswordsInjected = true;

  // Closed by default: untrusted page scripts have no business reading suggested accounts,
  // usernames or titles from `.sybr-panel.shadowRoot`. Only internal test mocks
  // (via an unforgeable message to the background worker) can override this.
  let shadowMode = "closed";
  try {
    api.runtime?.sendMessage?.({ cmd: "getShadowRootMode" }, (response) => {
      if (response?.mode === "open") shadowMode = "open";
    });
  } catch {}

  /** Visible in the sense a user means it. `offsetParent !== null` — the old
      test — is false for any element inside a `position: fixed` ancestor,
      which is precisely how login modals and appliance web UIs are built, so
      capture silently skipped exactly the fields people sign in with. */
  function isShown(el) {
    if (!el.isConnected) return false;
    if (typeof el.checkVisibility === "function") return el.checkVisibility({ visibilityProperty: true, opacityProperty: true });
    return el.getClientRects().length > 0;
  }

  /** querySelectorAll through open shadow roots. Web-component login pages
      (UniFi and friends) keep their inputs inside shadow DOM, where a plain
      document query finds nothing at all. Closed roots stay unreachable —
      nothing can be done about those. */
  function queryAllDeep(root, selector) {
    const out = Array.from(root.querySelectorAll(selector));
    for (const host of root.querySelectorAll("*")) {
      if (host.shadowRoot) out.push(...queryAllDeep(host.shadowRoot, selector));
    }
    return out;
  }

  /** The element the user actually interacted with: shadow-DOM events arrive
      at the document retargeted to the HOST element, and the real input is
      only on the composed path. */
  function eventTarget(e) {
    return e.composedPath?.()[0] ?? e.target;
  }

  /** Find the most likely username field associated with a password input. */
  /** Text-shaped inputs a username can actually go in. A checkbox, a submit
      button or a password box is not one, however its name reads. */
  const USERNAME_INPUT_TYPES = new Set(["text", "email", "tel", "url", "search"]);

  /** Whether `el` may be treated as `pw`'s username field.

      The tier selectors match on name/id/type alone, and several of those
      match the password field itself: `name="user_password"` hits the "user"
      tier, and a "show password" toggle turns the password box into
      `type=text`, which hits the last tier. With nothing before it on the
      page, that field was returned as its OWN username field — fill then wrote
      the username into the password box and left the real one empty, and
      capture read the password back out as the username, offering to save
      (and then storing) the password in place of the account name. The same
      selectors also match `<input type="checkbox" name="remember_user">`,
      whose value is the string "on". */
  function canHoldUsername(el, pw) {
    return (
      el !== pw &&
      !knownPasswordFields.has(el) &&
      USERNAME_INPUT_TYPES.has(el.type)
    );
  }

  function findUsernameField(pw) {
    // A shadow-DOM input's form is inside the same root; fall back to that
    // root (not document) so the search stays in the user's actual dialog.
    const scope = pw.form ?? pw.getRootNode?.() ?? document;
    // Tiers, strongest signal first, each resolved on its own. They used to be
    // one union ranked purely by document order, which made the list a no-op:
    // on "Email / Company code / Password" the bare text box nearest the
    // password won and the username landed in Company code. Within a tier:
    // the nearest one before the password, else the first one anywhere.
    const tiers = [
      'input[autocomplete="username"]',
      'input[type="email"]',
      'input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]',
      'input[type="text"]',
    ];
    for (const selector of tiers) {
      const candidates = queryAllDeep(scope, selector).filter(
        (el) => isShown(el) && canHoldUsername(el, pw),
      );
      if (!candidates.length) continue;
      const before = candidates.filter(
        (el) =>
          pw.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING,
      );
      return before.length ? before[before.length - 1] : candidates[0];
    }
    return null;
  }

  // Password inputs Arca has badged, tracked by element rather than selector:
  // a "show password" toggle flips type to text, and treating the field as
  // gone offered a save before the form was ever submitted, then blinded the
  // real submit's capture.
  const knownPasswordFields = new WeakSet();

  // What the user typed into an identifier-first box (Google/Microsoft/Okta
  // style). By the password step that box is hidden or static text, so capture
  // could never resolve a username and those logins were never offered.
  let lastIdentifier = null;
  const IDENTIFIER_FRESH_MS = 10 * 60 * 1000;
  function rememberedIdentifier() {
    return lastIdentifier && Date.now() - lastIdentifier.ts < IDENTIFIER_FRESH_MS
      ? lastIdentifier.value
      : "";
  }

  /** Filled, shown password inputs in `scope`, including badged ones a toggle
      has flipped to type=text. */
  function filledPasswordFields(scope) {
    return queryAllDeep(
      scope ?? document,
      'input[type="password"], input[type="text"]',
    ).filter(
      (el) =>
        (el.type === "password" || knownPasswordFields.has(el)) &&
        el.value &&
        isShown(el),
    );
  }

  /** Set a value in a way React/Vue/Angular controlled inputs will notice. */
  function setNativeValue(el, value) {
    const proto =
      el.tagName === "TEXTAREA"
        ? window.HTMLTextAreaElement.prototype
        : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /** Copy text to the clipboard from a user gesture. The async Clipboard API is
      the modern path; the hidden-textarea + execCommand fallback covers contexts
      that deny it (e.g. an unfocused document). Returns whether it landed. */
  async function copyText(text) {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_e) {
      /* fall through to the legacy path */
    }
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch (_e) {
      return false;
    }
  }

  let panel = null;
  let panelHost = null;
  let panelAnchor = null;
  let panelObserver = null;
  let panelFrame = null;
  let pickerSheet = null;
  let matchRequest = 0;
  let suggestionAnchor = null;

  // A click on a passkey row approves the sign-in; the desktop asks nothing
  // more. But the row lives in the page's DOM, where the page can fade it,
  // restyle its host, or paint its own layer over it with pointer-events: none
  // and steer a click through. IntersectionObserver v2 reports whether the
  // browser really painted a row unobscured and at full opacity, so only a row
  // seen that way for SEEN_MS before the click counts as the user's pick.
  // Anything less — including a browser that cannot tell (Firefox) — still
  // signs in; the desktop app asks first.
  const SEEN_MS = 500;
  const canTellSeen =
    typeof IntersectionObserverEntry === "function" &&
    "isVisible" in IntersectionObserverEntry.prototype;
  const seenSince = new WeakMap();
  let panelSight = null;

  function watchSight(root) {
    if (!canTellSeen) return;
    panelSight = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isVisible) seenSince.delete(entry.target);
          else if (!seenSince.has(entry.target)) seenSince.set(entry.target, entry.time);
        }
      },
      { trackVisibility: true, delay: 100 },
    );
    for (const row of root.querySelectorAll(".sybr-row")) panelSight.observe(row);
  }

  /** Has the browser shown `row` unobscured and unfaded for SEEN_MS, until now? */
  function seenLongEnough(row) {
    const since = seenSince.get(row);
    return since !== undefined && performance.now() - since >= SEEN_MS;
  }

  function closePanel(dismiss = true) {
    if (dismiss) {
      matchRequest++;
      suggestionAnchor = null;
    }
    if (panelFrame !== null) cancelAnimationFrame(panelFrame);
    panelFrame = null;
    panelObserver?.disconnect();
    panelObserver = null;
    panelSight?.disconnect();
    panelSight = null;
    panelHost?.remove();
    panelHost = null;
    panel = null;
    panelAnchor = null;
  }

  function visualViewportRect() {
    const viewport = window.visualViewport;
    return viewport
      ? {
          left: viewport.offsetLeft,
          top: viewport.offsetTop,
          width: viewport.width,
          height: viewport.height,
        }
      : { left: 0, top: 0, width: innerWidth, height: innerHeight };
  }

  function fieldInView(field) {
    if (!isShown(field)) return false;
    const rect = field.getBoundingClientRect();
    const viewport = visualViewportRect();
    let left = viewport.left, top = viewport.top;
    let right = left + viewport.width, bottom = top + viewport.height;
    for (let parent = field.parentElement || field.getRootNode().host; parent;
      parent = parent.parentElement || parent.getRootNode().host) {
      const style = getComputedStyle(parent);
      const bounds = parent.getBoundingClientRect();
      if (/auto|scroll|hidden|clip/.test(style.overflowX)) {
        left = Math.max(left, bounds.left); right = Math.min(right, bounds.right);
      }
      if (/auto|scroll|hidden|clip/.test(style.overflowY)) {
        top = Math.max(top, bounds.top); bottom = Math.min(bottom, bounds.bottom);
      }
    }
    const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
    return rect.width > 0 && rect.height > 0 && x >= left && x < right && y >= top && y < bottom;
  }

  function positionPanel() {
    panelFrame = null;
    if (!panel || !panelAnchor?.isConnected || !fieldInView(panelAnchor)) {
      closePanel();
      return;
    }
    const viewport = visualViewportRect();
    const anchorRect = panelAnchor.getBoundingClientRect();
    // Width and maximum height affect wrapping, so apply them once, measure,
    // then run the final geometry calculation with the real rendered height.
    const initial = globalThis.__arcaPickerLayout(
      anchorRect,
      { height: Math.min(panel.scrollHeight + 2, 280) },
      viewport,
    );
    panelHost.style.setProperty("width", `${initial.width}px`, "important");
    const layout = globalThis.__arcaPickerLayout(
      anchorRect,
      { height: Math.min(panel.scrollHeight + 2, 280) },
      viewport,
    );
    panel.style.maxHeight = `${Math.min(layout.maxHeight, 280)}px`;
    panelHost.style.setProperty("left", `${layout.left}px`, "important");
    panelHost.style.setProperty("top", `${layout.top}px`, "important");
    panelHost.dataset.placement = layout.placement;
    // Follow layout shifts and CSS transitions too, not just window scrolling.
    replaceAll();
    schedulePanelPosition();
  }

  function schedulePanelPosition() {
    if (!panel || panelFrame !== null) return;
    panelFrame = requestAnimationFrame(positionPanel);
  }

  function openPanel(anchor, content) {
    closePanel(false);
    if (!anchor.isConnected || !isShown(anchor)) return;
    suggestionAnchor = anchor;
    panelHost = document.createElement("div");
    panelHost.className = "sybr-panel";
    for (const [property, value] of Object.entries({
      all: "initial", position: "fixed", margin: "0", padding: "0", border: "0",
      background: "transparent", overflow: "visible", inset: "auto",
      "z-index": "2147483647", "box-sizing": "border-box",
    })) panelHost.style.setProperty(property, value, "important");
    const root = panelHost.attachShadow({ mode: shadowMode });
    if (typeof CSSStyleSheet === "function" && "adoptedStyleSheets" in root) {
      if (!pickerSheet) {
        pickerSheet = new CSSStyleSheet();
        pickerSheet.replaceSync(globalThis.__arcaPickerStyles);
      }
      root.adoptedStyleSheets = [pickerSheet];
    } else {
      const style = document.createElement("style");
      style.textContent = globalThis.__arcaPickerStyles;
      root.appendChild(style);
    }
    panel = document.createElement("div");
    panel.className = "sybr-panel-content";
    const header = document.createElement("div");
    header.className = "sybr-panel-header";
    const title = document.createElement("span");
    title.textContent = "Arca";
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.textContent = "×";
    dismiss.setAttribute("aria-label", "Close suggestions");
    dismiss.addEventListener("click", () => closePanel());
    header.append(title, dismiss);
    panel.appendChild(header);
    panelAnchor = anchor;
    panel.appendChild(content);
    root.appendChild(panel);
    mountOverlay(panelHost);
    positionPanel();
    watchSight(panel);
    // Fonts, wrapping and async row content can change the height after the
    // first layout. Observe both ends of the relationship and reposition.
    if (typeof ResizeObserver === "function") {
      panelObserver = new ResizeObserver(schedulePanelPosition);
      panelObserver.observe(panel);
      panelObserver.observe(anchor);
    }
  }

  function mountOverlay(host) {
    // The top layer escapes transformed/clipped page ancestors and native
    // modal dialogs. Older browsers fall back to an untransformed root child.
    if (typeof host.showPopover === "function") host.popover = "manual";
    document.documentElement.appendChild(host);
    if (host.popover) host.showPopover();
  }

  // Capture scrolls from nested containers as well as the window. The visual
  // viewport listeners cover browser zoom and the on-screen keyboard.
  window.addEventListener("scroll", schedulePanelPosition, {
    passive: true,
    capture: true,
  });
  window.addEventListener("resize", schedulePanelPosition, { passive: true });
  window.visualViewport?.addEventListener("scroll", schedulePanelPosition, {
    passive: true,
  });
  window.visualViewport?.addEventListener("resize", schedulePanelPosition, {
    passive: true,
  });

  function note(text) {
    const div = document.createElement("div");
    div.className = "sybr-note";
    div.textContent = text;
    return div;
  }

  // Avoid overlapping queries (each spawns the native host once).
  let pendingMatches = null;
  // Only nag once per page that the app is locked, on automatic triggers.
  let lockedHintShown = false;

  /** The first VISIBLE password field on the page, or null. Used to decide, at
      click time, whether an identifier-field pick should also fill a password
      (two-step pages reveal the password field after the identifier step). */
  function visiblePasswordField(anchor = null) {
    if (!anchor) {
      return (
        queryAllDeep(document, 'input[type="password"]').find(isShown) ??
        queryAllDeep(document, 'input[type="text"]').find(
          (el) => knownPasswordFields.has(el) && isShown(el),
        ) ??
        null
      );
    }
    const scope = anchor.form ?? anchor.getRootNode?.() ?? document;
    const local = queryAllDeep(scope, 'input[type="password"]').filter(isShown);
    const preferred = (fields) =>
      fields.find((field) =>
        (field.getAttribute("autocomplete") || "")
          .toLowerCase()
          .includes("current-password"),
      ) ?? fields[0];
    // A form or a shadow root IS the widget: everything in it belongs together.
    if (scope !== document) return local.length ? preferred(local) : null;
    // The document is not. A page with no <form> at all — an ordinary React
    // sign-in — put every widget's password box into this one list, and the
    // pick was then the first `current-password` anywhere on the page: a
    // sign-in identifier bound to a DIFFERENT widget's password box, so the
    // user picked an account and watched the password land somewhere else,
    // leaving the box they were typing in empty.
    //
    // Stay in the anchor's own tree first — a light-DOM field must never claim
    // a box inside some component's shadow root, and comparing positions
    // across trees is not even defined. Then resolve by proximity, mirroring
    // the username side: the password is the nearest box FOLLOWING the
    // identifier being filled.
    const root = anchor.getRootNode?.() ?? document;
    const siblings = local.filter(
      (field) => (field.getRootNode?.() ?? document) === root,
    );
    const following = siblings.filter(
      (field) =>
        anchor.compareDocumentPosition(field) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    );
    if (following.length) return preferred(following);
    // Nothing after it: only an unambiguous single field may be claimed, never
    // one of several belonging to some other widget.
    return siblings.length === 1 ? siblings[0] : null;
  }

  // Cached match list for the current page, so filtering as the user types
  // doesn't spawn the native host on every keystroke. Keyed by URL; only a
  // non-empty (unlocked) result is cached.
  let cache = null; // { url, items }
  const cachedItems = () =>
    cache && cache.url === location.href ? cache.items : null;

  /** Rank an item against the typed query: username prefix beats username
      substring beats title. -1 = no match. */
  function score(item, q) {
    const u = (item.username || "").toLowerCase();
    const t = (item.title || "").toLowerCase();
    if (u.startsWith(q)) return 0;
    if (u.includes(q)) return 1;
    if (t.startsWith(q)) return 2;
    if (t.includes(q)) return 3;
    return -1;
  }

  /** Filter + rank so the most likely account floats to the top as you type. */
  function rank(items, query) {
    const q = (query || "").trim().toLowerCase();
    if (!q) return items;
    return items
      .map((it) => ({ it, s: score(it, q) }))
      .filter((x) => x.s >= 0)
      .sort(
        (a, b) =>
          a.s - b.s ||
          (a.it.username || a.it.title || "").localeCompare(
            b.it.username || b.it.title || "",
          ),
      )
      .map((x) => x.it);
  }

  /// Ask the WebAuthn shim (main world) to answer the page's live conditional
  /// request with this passkey. Resolves false when there is nothing live.
  ///
  /// A window message is the only channel the isolated and main worlds share,
  /// and the page can read and forge it, so it names the credential and nothing
  /// more. The gate still wants a real gesture before anything is signed, and
  /// the caller records the pick with the relay directly.
  function usePasskey(credentialId) {
    return new Promise((resolve) => {
      const id = `use-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const onReply = (e) => {
        if (e.source !== window) return;
        const d = e.data;
        if (!d || d.__sybrPasskey !== "use-result" || d.id !== id) return;
        window.removeEventListener("message", onReply);
        clearTimeout(timer);
        resolve({ ok: !!d.ok, reason: d.reason || "request_failed" });
      };
      window.addEventListener("message", onReply);
      // The ceremony includes an approval prompt and a biometric, so the
      // deadline is generous; it exists so a shim that never answers cannot
      // leave "Signing in…" on screen for ever.
      const timer = setTimeout(() => {
        window.removeEventListener("message", onReply);
        resolve({ ok: false, reason: "timeout" });
      }, 90000);
      window.postMessage(
        { __sybrPasskey: "use", id, credentialId: credentialId || null },
        location.origin,
      );
    });
  }

  /// Fetch the credential for `item` and put it in the page.
  ///
  /// Its own function because two paths need it now: picking a row, and
  /// finishing the job after an unlock the user asked for. The second one used
  /// to stop at re-rendering the list, which meant unlocking to autofill did
  /// everything except autofill.
  async function fillFrom(item, anchor, isIdentifier, pwField) {
    let fill;
    try {
      // The desktop app only releases it for a matching origin while unlocked;
      // the password is never in `item`.
      fill = await api.runtime.sendMessage({
        cmd: "fill",
        id: item.id,
        url: location.href,
      });
    } catch (e) {
      openPanel(anchor, note(`Could not fill: ${String(e)}`));
      return false;
    }
    const cred = fill && fill.ok ? fill.response : null;
    if (cred && cred.type === "credentials") {
      const userField = isIdentifier ? anchor : findUsernameField(anchor);
      if (userField && cred.username) setNativeValue(userField, cred.username);
      if (pwField && cred.password) setNativeValue(pwField, cred.password);
      closePanel();
      return true;
    }
    // The app tells us WHICH failure it was; the host passes it through instead
    // of listing all three in one sentence. "locked" is the only one with a fix
    // from here, so it gets the button rather than a full stop.
    const reason = (cred && cred.message) || "";
    if (reason === "locked" || reason === "not_running") {
      openPanel(anchor, unlockPrompt(anchor, isIdentifier));
      return false;
    }
    openPanel(anchor, note(fillFailureText(reason)));
    return false;
  }

  /** Build one selectable row for `item`. */
  function buildRow(item, anchor, isIdentifier) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "sybr-row";
    const isPasskey = item.kind === "passkey";
    row.innerHTML =
      `<span class="sybr-line"><span class="sybr-title"></span>` +
      `<span class="sybr-kind"></span></span><span class="sybr-user"></span>`;
    row.querySelector(".sybr-title").textContent = item.title || item.url;
    row.querySelector(".sybr-user").textContent = item.username || "";
    const kindEl = row.querySelector(".sybr-kind");
    kindEl.textContent = isPasskey ? "Passkey" : "Password";
    kindEl.classList.add(
      isPasskey ? "sybr-kind-passkey" : "sybr-kind-password",
    );
    row.addEventListener("click", async (e) => {
      // A real click, from a real person — the same rule the unlock row has
      // had. The picker lives in the page's own DOM, and `focus` opens it
      // automatically, so without this a script on the page could focus the
      // password box, dispatch a click at `.sybr-row`, and read the filled
      // credential straight back out of the input. No human is involved in
      // any of that.
      if (!e.isTrusted) return;
      // This click is what OPENED the panel below; letting it bubble to the
      // document dismisser would close the panel this handler just put up
      // (the "Signing in with your passkey…" note never appeared).
      e.stopPropagation();
      try {
        // A passkey is not typed into a field — it signs the site's own
        // WebAuthn challenge. Showing one that cannot be used is worse than
        // not showing it.
        if (isPasskey) {
          // Read before the note below replaces this row.
          const seen = seenLongEnough(row);
          openPanel(anchor, note("Signing in with your passkey…"));
          // This trusted click on a row the browser vouched was visible,
          // recorded in the world the page cannot reach, is the only thing
          // that lets the relay tell the desktop the user picked this account.
          // Without it the ceremony still runs, and the desktop asks.
          if (seen && typeof window.__sybrPasskeyPicked === "function") {
            window.__sybrPasskeyPicked(item.credential_id);
          }
          const used = await usePasskey(item.credential_id);
          if (used.ok) {
            closePanel();
            return;
          }
          if (used.reason === "no_request" && isIdentifier && !visiblePasswordField(anchor)) {
            // The site's first step needs an account name before it can ask
            // for a passkey. No password is requested or filled here.
            if (item.username) setNativeValue(anchor, item.username);
            closePanel();
            return;
          }
          const failures = {
            account_mismatch: "This page requested a passkey for a different account. Choose that account or switch accounts on the site.",
            request_cancelled: "The site cancelled this passkey request. Start passkey sign-in on the site again.",
            locked: "Unlock Arca, then choose your passkey again.",
            passkeys_disabled: "Passkey handling is disabled in Arca settings.",
            site_never: "Passkeys are disabled for this site in the Arca extension settings.",
            timeout: "Arca did not finish the passkey request. Try passkey sign-in again.",
          };
          openPanel(
            anchor,
            note(failures[used.reason] || (used.reason === "no_request"
              ? 'Choose “Sign in with a passkey” on this site to start its passkey request.'
              : "Arca could not complete passkey sign-in. Start it again on the site.")),
          );
          return;
        }

        const pwField = isIdentifier ? visiblePasswordField(anchor) : anchor;
        if (isIdentifier && !pwField) {
          // Pure identifier step (no password field yet): fill just the
          // username. It's metadata already in `item`; no credential request
          // is made.
          if (item.username) setNativeValue(anchor, item.username);
          closePanel();
          return;
        }
        await fillFrom(item, anchor, isIdentifier, pwField);
      } catch (error) {
        openPanel(anchor, note(`Could not fill: ${String(error)}`));
      }
    });
    return row;
  }

  /// Plain words for the app's failure code.
  ///
  /// Each one names what to do, because a password manager that says "failed"
  /// at the moment you are trying to sign in has told you nothing you did not
  /// already know.
  function fillFailureText(reason) {
    switch (reason) {
      case "origin_mismatch":
        // The single most important one to state precisely: it means the saved
        // entry is for a DIFFERENT site, which is Arca refusing to leak a
        // credential to a lookalike rather than a bug.
        return "That login is saved for a different website, so Arca will not fill it here.";
      case "not_found":
        return "That entry is no longer in the vault. Try searching again.";
      case "internal":
        return "Arca hit an internal error. Check the app.";
      default:
        return reason
          ? `Arca could not fill this: ${reason}`
          : "Arca could not fill this.";
    }
  }

  /// The locked-vault panel, as something you can act on.
  ///
  /// It used to read "Open and unlock Arca to autofill." — an instruction, at
  /// the exact moment the user had already said what they wanted by clicking
  /// the badge. Now the click brings Arca forward, it asks for Touch ID, and
  /// the suggestions appear here by themselves.
  function unlockPrompt(anchor, isIdentifier) {
    const wrap = document.createElement("div");
    const row = document.createElement("button");
    row.className = "sybr-row";
    row.innerHTML =
      `<span class="sybr-line"><span class="sybr-title"></span>` +
      `<span class="sybr-kind"></span></span><span class="sybr-user"></span>`;
    row.querySelector(".sybr-title").textContent = "Start / unlock Arca to autofill";
    row.querySelector(".sybr-user").textContent = "Authenticate in Arca to continue";
    const kindEl = row.querySelector(".sybr-kind");
    kindEl.textContent = "Locked";
    kindEl.classList.add("sybr-kind-password");
    row.addEventListener("click", (e) => {
      // A real click, from a real person. A page can dispatch a synthetic one
      // at this button, and while unlocking still needs the user's fingerprint,
      // a page that can summon Touch ID sheets at will is a nuisance worth
      // refusing outright.
      if (!e.isTrusted) return;
      // Keep the "Unlocking Arca…" panel this opens from being dismissed by
      // the very click that asked for it.
      e.stopPropagation();
      void requestUnlock(anchor, isIdentifier);
    });
    wrap.appendChild(row);
    return wrap;
  }

  /// Rate limit on asking Arca to come forward, in ms. Without it, a page that
  /// re-focuses its password field in a loop becomes a window-stealing machine.
  const UNLOCK_COOLDOWN_MS = 5000;
  let lastUnlockRequest = 0;

  async function requestUnlock(anchor, isIdentifier) {
    const now = Date.now();
    if (now - lastUnlockRequest < UNLOCK_COOLDOWN_MS) return;
    lastUnlockRequest = now;

    openPanel(anchor, note("Unlocking Arca…"));
    let res;
    try {
      res = await api.runtime.sendMessage({ cmd: "requestUnlock" });
    } catch (e) {
      openPanel(anchor, note(`Could not reach Arca: ${String(e)}`));
      return;
    }
    const out = res && res.ok ? res.response : null;
    if (!out || out.type !== "unlock_requested") {
      openPanel(anchor, note((out && out.message) || "Arca is not running."));
      return;
    }

    // Poll rather than wait for a push: the unlock happens in another
    // application, behind a biometric prompt the user may also ignore. Give up
    // quietly after a while instead of leaving a spinner on their page.
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 700));
      // Gone from the page, or the user moved on. Stop.
      if (!anchor.isConnected) return;
      let probe;
      try {
        probe = await api.runtime.sendMessage({
          cmd: "listLogins",
          url: location.href,
        });
      } catch {
        return;
      }
      const resp = (probe && probe.ok && probe.response) || {};
      if (resp.app_connected) {
        cache = null;
        lockedHintShown = false;
        const items = Array.isArray(resp.items) ? resp.items : [];
        // Exactly one login for this site: finish the job. You clicked "unlock
        // to autofill" on this field — being handed a list of one to click
        // again is asking the same question twice.
        const only = items.filter((i) => i.kind !== "passkey");
        if (only.length === 1) {
          cache = { url: location.href, items };
          const pwField = isIdentifier ? visiblePasswordField(anchor) : anchor;
          if (await fillFrom(only[0], anchor, isIdentifier, pwField)) return;
        }
        await showMatches(anchor, false, isIdentifier);
        return;
      }
    }
    openPanel(anchor, note("Arca is still locked."));
  }

  /** Visible password inputs in the same form as `el`, in document order. */
  function passwordFieldsIn(el) {
    const scope = el.form || el.getRootNode?.() || document;
    return queryAllDeep(scope, 'input[type="password"]').filter(
      (f) => f === el || isShown(f),
    );
  }

  /** Whether this field is asking for a NEW password rather than a stored one.
   *
   * `autocomplete` is the field telling us directly, and is trusted both ways —
   * "current-password" is an explicit no. The two-field fallback catches the
   * many sign-up forms that set neither, where a password box and a confirm box
   * appear together. */
  function isNewPasswordField(el) {
    if (!el || el.type !== "password") return false;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    if (ac.includes("new-password")) return true;
    if (ac.includes("current-password")) return false;
    return passwordFieldsIn(el).length >= 2;
  }

  /** Resolve a confirm-password click back to the primary new-password box. */
  function generationTargetFor(el) {
    if (!isNewPasswordField(el)) return null;
    const fields = passwordFieldsIn(el);
    const ac = (f) => (f.getAttribute("autocomplete") || "").toLowerCase();
    const explicit = fields.find((f) => ac(f).includes("new-password"));
    if (explicit) return explicit;
    // No labels — the common case. Start from the field the user clicked. It
    // used to take the FIRST non-current field in document order, which on an
    // unlabelled [current, new, confirm] form is the CURRENT box: generating
    // then filled all three and the change failed on "current password
    // incorrect". Walk away from the anchor only when its position says it is
    // not the primary: the trailing confirm box, or the leading current box.
    const candidates = fields.filter((f) => !ac(f).includes("current-password"));
    const i = candidates.indexOf(el);
    if (i < 0) return candidates[0] ?? el;
    if (i === candidates.length - 1 && candidates.length >= 2) {
      return candidates[i - 1];
    }
    if (i === 0 && candidates.length >= 3) return candidates[1];
    return el;
  }

  /** The confirmation box(es) to fill alongside `anchor`.
   *
   * Only fields AFTER the anchor, and never one marked current-password. On a
   * change-password form (current, new, confirm) the user clicks the new field,
   * so this fills the confirm and leaves the current one alone — overwriting it
   * would replace the one value the form needs to verify them. */
  function confirmationFieldsFor(anchor) {
    const all = passwordFieldsIn(anchor);
    const i = all.indexOf(anchor);
    if (i < 0) return [];
    return all.slice(i + 1).filter((f) => {
      const ac = (f.getAttribute("autocomplete") || "").toLowerCase();
      return !ac.includes("current-password");
    });
  }

  // The last password Arca itself generated and filled, so save-on-submit can
  // offer it even on forms captureCandidate refuses (see generatedCandidate).
  let generatedFill = null;

  /** A row offering a freshly generated password. */
  function buildGenerateRow(anchor) {
    const row = document.createElement("button");
    row.className = "sybr-row";
    row.innerHTML =
      `<span class="sybr-line"><span class="sybr-title"></span>` +
      `<span class="sybr-kind"></span></span><span class="sybr-user"></span>`;
    row.querySelector(".sybr-title").textContent = "Use a strong password";
    row.querySelector(".sybr-user").textContent = "20 characters, random";
    const kindEl = row.querySelector(".sybr-kind");
    kindEl.textContent = "Generate";
    kindEl.classList.add("sybr-kind-password");
    row.addEventListener("click", () => generateInto(anchor));
    return row;
  }

  /** The panel shown right after generating: the value itself — so it is not a
      secret the user is asked to trust blind — with a copy button, and a line
      saying what happens on submit. Showing it exposes nothing new: we just
      filled this exact value into the page's own field, which the page can read
      anyway; the reveal is only for the human. */
  function buildGeneratedNote(password) {
    const wrap = document.createElement("div");
    wrap.className = "sybr-generated";

    const row = document.createElement("div");
    row.className = "sybr-generated-row";
    const value = document.createElement("span");
    value.className = "sybr-generated-value";
    value.textContent = password;
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "sybr-generated-copy";
    copy.textContent = "Copy";
    let revert = null;
    copy.addEventListener("click", async () => {
      const ok = await copyText(password);
      copy.textContent = ok ? "Copied" : "Press ⌘C";
      if (revert) clearTimeout(revert);
      revert = setTimeout(() => {
        copy.textContent = "Copy";
      }, 1500);
    });
    row.append(value, copy);

    const msg = document.createElement("div");
    msg.className = "sybr-generated-msg";
    msg.textContent = "Arca will offer to save this when you submit the form.";

    wrap.append(row, msg);
    return wrap;
  }

  /** Ask Arca for a password and put it in the form. */
  async function generateInto(anchor) {
    const target = generationTargetFor(anchor);
    if (!target) return;
    let res;
    try {
      res = await api.runtime.sendMessage({
        cmd: "generatePassword",
        length: 20,
        symbols: true,
      });
    } catch (e) {
      openPanel(anchor, note(`Could not generate: ${String(e)}`));
      return;
    }
    const out = res && res.ok ? res.response : null;
    if (!out || out.type !== "generated_password" || !out.password) {
      openPanel(
        anchor,
        note((out && out.message) || "Arca could not generate a password."),
      );
      return;
    }
    setNativeValue(target, out.password);
    // The confirmation box too. A generated password the user has to retype by
    // hand is one they will delete and replace with something memorable, which
    // is the whole problem this is here to solve.
    confirmationFieldsFor(target).forEach((f) =>
      setNativeValue(f, out.password),
    );
    // Remember what we filled so submit can offer to save it. captureCandidate
    // reads the DOM back with sign-in-shaped rules that reject exactly this kind
    // of form (two password boxes; often no username field — a token-based
    // password reset has none), so without this the promise below is a lie: the
    // generated password becomes the live account password and is stored
    // nowhere. We know the value and target directly, so we don't need to guess.
    generatedFill = {
      url: location.href,
      password: out.password,
      usernameEl: findUsernameField(target),
    };
    // Show the value and say where it went — a random string appearing in a
    // masked box is alarming if you can't read it and don't know it's kept.
    // Submitting is what saves it (via the save-on-submit prompt, which the
    // generatedFill above now reaches even on username-less reset forms).
    openPanel(anchor, buildGeneratedNote(out.password));
  }

  /** Render the (filtered, ranked) picker. On an identifier field, filter by
      what's typed so far; empty result closes the panel. */
  function renderPicker(anchor, items, isIdentifier) {
    const filtered = isIdentifier ? rank(items, anchor.value) : items;
    const offerGenerate = isNewPasswordField(anchor);
    if (filtered.length === 0 && !offerGenerate) {
      closePanel();
      return;
    }
    const list = document.createElement("div");
    // First: on a sign-up form the stored logins are the less likely answer,
    // and they are still right there underneath.
    if (offerGenerate) list.appendChild(buildGenerateRow(anchor));
    filtered.forEach((it) =>
      list.appendChild(buildRow(it, anchor, isIdentifier)),
    );
    openPanel(anchor, list);
  }

  // Only retry this read-only lookup. Credential fills, saves and passkey
  // ceremonies must never be replayed after an ambiguous transport failure.
  async function lookupMatches(url) {
    let result;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        result = await api.runtime.sendMessage({ cmd: "listLogins", url });
      } catch (error) {
        result = { ok: false, error: String(error) };
      }
      if (result?.ok) return result;
      // Reloading an extension invalidates scripts already in open tabs.
      // Waiting cannot repair that context; tell the user to reload the page.
      if (/context invalidated/i.test(result?.error || "")) break;
      if (attempt === 0) await new Promise((resolve) => setTimeout(resolve, 250));
    }
    return result || { ok: false, error: "The extension returned no response." };
  }

  function connectionFailure(anchor, isIdentifier, error) {
    const wrap = document.createElement("div");
    const invalidated = /context invalidated/i.test(error || "");
    wrap.appendChild(note(invalidated
      ? "Arca was updated. Reload this page to reconnect."
      : "Arca could not complete the connection. Try again."));
    if (error) wrap.appendChild(note(String(error).slice(0, 500)));
    if (!invalidated) {
      const retry = document.createElement("button");
      retry.type = "button";
      retry.className = "sybr-row";
      retry.textContent = "Try again";
      retry.addEventListener("click", (event) => {
        if (!event.isTrusted) return;
        event.stopPropagation();
        void showMatches(anchor, false, isIdentifier);
      });
      wrap.appendChild(retry);
    }
    return wrap;
  }

  // Show matching logins. `auto` = triggered by focus (stay quiet when there's
  // nothing useful); manual (badge click) always gives feedback.
  // `isIdentifier` = the anchor is a username/email field (not a password
  // field). Whether a pick fills only the username or also the password is
  // decided at click time by whether a password field is visible, so a field
  // badged during the identifier step still does a full fill once the password
  // step appears.
  async function showMatches(anchor, auto, isIdentifier = false) {
    const request = ++matchRequest;
    const url = location.href;
    suggestionAnchor = anchor;
    const current = () => request === matchRequest && location.href === url &&
      anchor.isConnected && isShown(anchor);
    // Filter from cache without a round-trip when we already have the page's
    // matches (this is the type-ahead path).
    const have = cachedItems();
    if (have) {
      renderPicker(anchor, have, isIdentifier);
      bindTypeAhead(anchor, isIdentifier);
      return;
    }

    try {
      if (!auto) openPanel(anchor, note("Searching your vault…"));

      let result;
      try {
        // Share the lookup, not its target. A quick Tab must move suggestions
        // to the latest field even when the native host is still waking up.
        if (!pendingMatches || pendingMatches.url !== url) {
          pendingMatches = { url, promise: lookupMatches(url) };
        }
        const lookup = pendingMatches;
        try { result = await lookup.promise; }
        finally { if (pendingMatches === lookup) pendingMatches = null; }
      } catch (e) {
        if (current() && !auto) openPanel(anchor, connectionFailure(anchor, isIdentifier, String(e)));
        return;
      }
      if (!current()) return;

      if (!result || !result.ok) {
        if (!auto) {
          openPanel(
            anchor,
            connectionFailure(anchor, isIdentifier, result?.error),
          );
        }
        return;
      }

      const resp = result.response || {};
      const items = Array.isArray(resp.items) ? resp.items : [];

      if (items.length === 0) {
        if (!resp.app_connected) {
          // Locked / not running. We only nag automatically once per page load.
          // identifierFields requires strong login signals (autocomplete=username
          // or explicit login names), so it is safe to prompt here.
          const nag = !auto || !lockedHintShown;
          if (nag) {
            if (auto) lockedHintShown = true;
            openPanel(anchor, unlockPrompt(anchor, isIdentifier));
          }
        } else if (isNewPasswordField(anchor)) {
          // Nothing stored, and the field is asking for a new password: this is
          // a sign-up. Offering to generate one is the useful answer, and it is
          // worth showing on focus rather than only on a badge click — the
          // moment someone is inventing a password is the moment to intervene.
          const list = document.createElement("div");
          list.appendChild(buildGenerateRow(anchor));
          openPanel(anchor, list);
        } else if (!auto) {
          openPanel(anchor, note("No matching logins for this site."));
        } else {
          closePanel();
        }
        return;
      }

      cache = { url, items };
      renderPicker(anchor, items, isIdentifier);
      bindTypeAhead(anchor, isIdentifier);
    } catch (_) { if (current()) closePanel(); }
  }

  /** Re-filter the picker as the user types in an identifier/username field. */
  function bindTypeAhead(anchor, isIdentifier) {
    if (!isIdentifier || anchor.dataset.sybrFilterBound) return;
    anchor.dataset.sybrFilterBound = "1";
    anchor.addEventListener("input", () => {
      const items = cachedItems();
      // Only re-render while this field is focused, so filtering never fights
      // typing in another field.
      const root = anchor.getRootNode?.();
      const active = root && "activeElement" in root
        ? root.activeElement
        : document.activeElement;
      if (items && active === anchor) {
        renderPicker(anchor, items, true);
      }
    });
  }

  // Placement callbacks for every attached badge, re-run on scroll/resize AND
  // on DOM mutation so a badge whose field gets hidden (e.g. a two-step page
  // swapping the identifier view for the password view) hides with it instead
  // of floating over the new screen.
  const placements = new Map();
  const replaceAll = () => {
    for (const [field, { host, place }] of placements) {
      if (!field.isConnected) { host.remove(); placements.delete(field); }
      else place();
    }
  };
  window.addEventListener("scroll", replaceAll, { passive: true, capture: true });
  window.addEventListener("resize", replaceAll, { passive: true });
  window.visualViewport?.addEventListener("scroll", replaceAll, { passive: true });
  window.visualViewport?.addEventListener("resize", replaceAll, { passive: true });

  function attachBadge(field, isIdentifier = false) {
    if (field.dataset.sybrAttached) return;
    field.dataset.sybrAttached = "1";

    // The badge lives in a SHADOW ROOT, and that is the whole point.
    //
    // As a plain element it inherited the page's own button styling: our rule
    // is a single class selector, so any site with a `button { padding: ... }`
    // beats it. On Microsoft's sign-in that turned a 22px key into a 105px
    // white slab parked beside the field. A shadow root is the only way to say
    // "these styles, and nothing the page has to say about it".
    const host = document.createElement("div");
    host.className = "sybr-badge-host";
    // The HOST can be reached by page CSS too, so its own geometry is set
    // inline and marked important rather than left to a stylesheet.
    for (const [prop, value] of [
      ["all", "initial"],
      ["inset", "auto"],
      ["position", "fixed"],
      ["z-index", "2147483646"],
      ["width", "22px"],
      ["height", "22px"],
      ["margin", "0"],
      ["padding", "0"],
      ["border", "0"],
      ["background", "transparent"],
      ["pointer-events", "auto"],
    ]) {
      host.style.setProperty(prop, value, "important");
    }
    // Closed: the page has no business reaching in and restyling it.
    const shadow = host.attachShadow({ mode: "closed" });
    shadow.innerHTML =
      "<style>" +
      ":host { all: initial; }" +
      "button {" +
      "  width: 22px; height: 22px; padding: 0; margin: 0;" +
      "  display: flex; align-items: center; justify-content: center;" +
      "  line-height: 1; box-sizing: border-box;" +
      "  border: 1px solid rgba(0,0,0,0.12); border-radius: 6px;" +
      "  background: #ffffff; color: #0a84ff;" +
      "  box-shadow: 0 1px 4px rgba(0,0,0,0.18);" +
      "  cursor: pointer; opacity: 0.9;" +
      "}" +
      "button:hover { opacity: 1; }" +
      "svg { width: 14px; height: 14px; display: block; }" +
      "@media (prefers-color-scheme: dark) {" +
      "  button { background: #2c2c2e; color: #64a8ff;" +
      "           border-color: rgba(255,255,255,0.14);" +
      "           box-shadow: 0 1px 4px rgba(0,0,0,0.4); }" +
      "}" +
      "</style>";

    if (!isIdentifier) knownPasswordFields.add(field);

    const badge = document.createElement("button");
    badge.type = "button";
    badge.title = "Autofill from Arca";
    // Inline SVG key (currentColor): renders identically on every platform,
    // unlike the key emoji which falls back to a dark monochrome glyph on
    // Windows.
    badge.innerHTML =
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<circle cx="8" cy="15" r="4"/><path d="M10.85 12.15 19 4"/><path d="m18 5 2 2"/><path d="m15 8 2 2"/></svg>';
    shadow.appendChild(badge);

    const place = () => {
      const rect = field.getBoundingClientRect();
      const viewport = visualViewportRect();
      const right = viewport.left + viewport.width;
      const bottom = viewport.top + viewport.height;
      // Hide when the field is gone or not rendered. isShown, not
      // offsetParent: a field inside a fixed-position login modal has a null
      // offsetParent while being exactly the field the user is typing in.
      if (
        !fieldInView(field) ||
        (rect.width === 0 && rect.height === 0) ||
        rect.right <= viewport.left ||
        rect.left >= right ||
        rect.bottom <= viewport.top ||
        rect.top >= bottom
      ) {
        host.style.setProperty("display", "none", "important");
        return;
      }
      host.style.setProperty("display", "block", "important");
      // Viewport coords (position: fixed) — no scroll offsets. Vertically
      // centered on the field, tucked just inside its right edge.
      const top = Math.min(
        Math.max(rect.top + rect.height / 2 - 11, viewport.top + 2),
        bottom - 24,
      );
      const left = Math.min(
        Math.max(rect.right - 28, viewport.left + 2),
        right - 24,
      );
      host.style.setProperty("top", `${top}px`, "important");
      host.style.setProperty("left", `${left}px`, "important");
    };

    badge.addEventListener("mousedown", (e) => e.preventDefault());
    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      showMatches(field, false, isIdentifier); // manual: always give feedback
    });

    mountOverlay(host);
    placements.set(field, { host, place });
    place();

    // Suggest automatically when the user focuses the field — like a native
    // autofill prompt.
    field.addEventListener("focus", () =>
      showMatches(field, true, isIdentifier),
    );
    if (field.getRootNode().activeElement === field && isShown(field)) {
      void showMatches(field, true, isIdentifier);
    }
    if (isIdentifier) {
      const remember = () => {
        if (field.value) lastIdentifier = { value: field.value, ts: Date.now() };
      };
      field.addEventListener("input", remember);
      field.addEventListener("change", remember);
      return;
    }

    // Bind each identifier once, even if several password fields share it.
    const userField = findUsernameField(field);
    if (userField && !userField.dataset.sybrAttached) attachBadge(userField, true);
  }

  /** Likely username/email inputs on identifier-first pages (Google/Microsoft
      style two-step sign-in). Deliberately requires a strong login signal — an
      explicit `autocomplete=username`, or a login-specific name/id — so plain
      newsletter/contact email boxes don't get badged. */
  function identifierFields() {
    const LOGIN_RE =
      /(^|[-_.\s])(user(name)?|login|loginfmt|identifier|brukernavn)([-_.\s]|$)/i;
    const words = (text) => (text || "").replace(/([a-z])([A-Z])/g, "$1 $2");
    return queryAllDeep(
      document,
      'input',
    ).filter((el) => {
      if (el.dataset.sybrAttached || !isShown(el) || el.disabled || el.readOnly ||
          !["text", "email", "tel"].includes(el.type) || knownPasswordFields.has(el)) return false;
      const autocomplete = (el.autocomplete || "").toLowerCase().split(/\s+/);
      if (autocomplete.some((token) => ["one-time-code", "new-password", "current-password"].includes(token))) return false;
      if (
        autocomplete.includes("username")
      )
        return true;
      const hints = [el.name, el.id, el.getAttribute("aria-label"), el.placeholder,
        ...Array.from(el.labels || [], (label) => label.textContent)].map(words).join(" ");
      if (LOGIN_RE.test(hints)) return true;
      // Generic email/phone fields need sign-in context, so newsletters,
      // contact forms and one-time codes do not acquire login suggestions.
      if (!/(e-?mail|e-?post|phone|telefon)/i.test(hints) && el.type !== "email") return false;
      const scope = el.form || el.closest('[role="dialog"], section, fieldset') || el.getRootNode();
      const context = [scope.id, scope.getAttribute?.("name"), scope.getAttribute?.("action"),
        ...Array.from(scope.querySelectorAll('h1,h2,h3,legend,button,input[type="submit"]'),
          (node) => node.textContent || node.value)].map(words).join(" ");
      return /sign[\s_-]*in|log[\s_-]*in|logg[\s_-]*inn|innlogging/i.test(context) &&
        !/newsletter|subscribe|nyhetsbrev/i.test(context);
    });
  }

  function scan() {
    queryAllDeep(
      document,
      'input[type="password"]:not([data-sybr-attached])',
    ).forEach((pw) => attachBadge(pw));

    // Each widget is independent: an unrelated password form elsewhere must
    // not disable the username-only step the user is signing into.
    identifierFields().forEach((el) => attachBadge(el, true));
    replaceAll();
  }

  // Dismiss before the site's click handler runs. A Next button may replace
  // its own form and focus the password step during that handler; closing at
  // the end of the click would immediately dismiss the new field's picker.
  document.addEventListener("pointerdown", (e) => {
    const path = e.composedPath();
    if (suggestionAnchor && !path.includes(suggestionAnchor) && !path.includes(panelHost) &&
        !path.some((node) => node.classList?.contains("sybr-badge-host"))) closePanel();
  }, true);
  document.addEventListener("focusin", (e) => {
    const field = eventTarget(e);
    if (field instanceof HTMLInputElement && !field.dataset.sybrAttached) scan();
    if (suggestionAnchor && field !== suggestionAnchor && !e.composedPath().includes(panelHost)) closePanel();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closePanel();
  });

  scan();
  // Watch for dynamically rendered login forms (SPAs).
  new MutationObserver((records) => {
    if (records.some((record) => !record.target.closest?.('.sybr-panel,.sybr-badge-host') &&
        (record.type === "attributes" || [...record.addedNodes, ...record.removedNodes].some(
          (node) => !node.classList?.contains("sybr-panel") && !node.classList?.contains("sybr-badge-host"))))) scan();
  }).observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["class", "style", "hidden", "type", "autocomplete", "disabled", "readonly"],
  });

  // (Passkey relay lives in passkey-relay.js, injected at document_start so it's
  // listening before the main-world shim can post an early WebAuthn request.)

  // ---- save-on-submit -----------------------------------------------------
  // Offer to save a new/changed login when the user submits a sign-in form.
  const bareHost = (u) => {
    try {
      return new URL(u, location.href).hostname.replace(/^www\./, "");
    } catch (_e) {
      return "";
    }
  };
  /** Same normalized host. Subdomains are separate trust boundaries. */
  const sameSite = (urlA, urlB) => {
    const a = bareHost(urlA);
    const b = bareHost(urlB);
    return !!a && !!b && a === b;
  };

  /** A password field's semantic hints, including the names used by Portainer
      (`current_password`, `new_password`, `confirm_password`). */
  function passwordHint(el) {
    return [
      el.getAttribute("autocomplete") || "",
      el.name || "",
      el.id || "",
      el.getAttribute("aria-label") || "",
      el.getAttribute("placeholder") || "",
    ]
      .join(" ")
      .toLowerCase();
  }

  const isCurrentPassword = (el) =>
    passwordHint(el).includes("current-password") ||
    /(?:current|old)[-_ ]*pass(?:word)?/.test(passwordHint(el));
  const isConfirmedPassword = (el) =>
    /(?:confirm|repeat|retype|verify)[-_ ]*pass(?:word)?/.test(
      passwordHint(el),
    );
  const isNewPassword = (el) =>
    passwordHint(el).includes("new-password") ||
    /(?:new|change)[-_ ]*pass(?:word)?/.test(passwordHint(el));

  /** Pick the new value out of a multi-password form without ever mistaking
      the current password for the replacement. Strong field hints win. For
      unlabelled forms, the repeated equal pair is the only safe fallback. */
  function changedPasswordField(pws) {
    const confirmations = pws.filter(isConfirmedPassword);
    const explicitlyNew = pws.filter(
      (field) => isNewPassword(field) && !isConfirmedPassword(field),
    );
    let target = explicitlyNew.length === 1 ? explicitlyNew[0] : null;

    if (!target) {
      const candidates = pws.filter((field) => !isCurrentPassword(field));
      const repeatedValues = [
        ...new Set(
          candidates
            .map((field) => field.value)
            .filter(
              (value) =>
                value &&
                candidates.filter((field) => field.value === value).length >= 2,
            ),
        ),
      ];
      if (repeatedValues.length !== 1) return null;
      target =
        candidates.find(
          (field) =>
            field.value === repeatedValues[0] && !isConfirmedPassword(field),
        ) ?? null;
    }

    if (!target?.value) return null;
    // If the form identifies a confirmation field, a mismatch is a failed or
    // incomplete change and must never become a save proposal.
    if (
      confirmations.some(
        (field) => field !== target && field.value !== target.value,
      )
    )
      return null;
    return target;
  }

  /** Capture credentials from a scope. A normal sign-in requires one password
      plus a username. A password-change/sign-up form requires a confidently
      identified new value; its username may be absent because account settings
      and emailed reset links already know which account is changing.

      The scope is a FORM when there is one and the DOCUMENT when there is not:
      SPA logins are a button wired to fetch, often with no <form> element at
      all, and those pages are exactly where the prompt used to never appear. */
  function captureCandidate(scope) {
    const pws = filledPasswordFields(scope);
    if (!pws.length) return null;
    const multiPassword = pws.length > 1;
    const passwordEl = multiPassword ? changedPasswordField(pws) : pws[0];
    if (!passwordEl) return null;
    const userEl = findUsernameField(passwordEl);
    const username = (userEl && userEl.value) || rememberedIdentifier();
    if (!multiPassword && !username) return null;
    const generated = generatedFill?.password === passwordEl.value;
    return {
      url: location.href,
      username,
      password: passwordEl.value,
      multiPassword,
      generated,
    };
  }

  /** A save candidate for a password Arca just generated and filled.
   *
   * Unlike captureCandidate this does NOT require a single password field or a
   * filled username: generate is offered precisely on sign-up / reset forms —
   * two password boxes, and frequently no username input at all (identity comes
   * from an emailed token) — which captureCandidate is built to reject. We know
   * the exact value we put in, so we offer it directly. Guarded so a stale value
   * from an earlier form isn't re-saved: it must still sit in a visible password
   * field. The username is best-effort and may be empty; the app accepts that
   * (an empty username is stored as-is, and only an empty PASSWORD is refused). */
  function generatedCandidate() {
    if (!generatedFill) return null;
    const stillFilled = queryAllDeep(document, 'input[type="password"]').some(
      (el) => isShown(el) && el.value === generatedFill.password,
    );
    if (!stillFilled) return null;
    const userEl = generatedFill.usernameEl;
    return {
      url: generatedFill.url,
      username: (userEl && userEl.value) || rememberedIdentifier(),
      password: generatedFill.password,
      // Lets the offer skip the "form gone / same site" gates: a sign-up or
      // reset lands on a LOGIN page, often on another host, and the value is
      // the account's live password either way.
      generated: true,
    };
  }

  let saveBar = null;
  function closeSaveBar() {
    saveBar?.remove();
    saveBar = null;
  }
  function showSaveBar(candidate, action, storedUsername = "") {
    closeSaveBar();
    const host = bareHost(candidate.url);
    let needsUnlock = action === "locked";
    let saving = false;
    // Name the account an update overwrites. With no username on the page (a
    // token reset) the app targets the site's single stored login, and the user
    // must see WHICH one before agreeing — that is the difference between a
    // reset landing on the right account and silently clobbering another.
    const describe = (verdict, who) =>
      verdict === "locked"
        ? `Unlock Arca to save the login for ${host}?`
        : verdict === "update"
          ? `Update the password for ${who ? `${who} on ` : ""}${host} in Arca?`
          : `Save login${who ? ` for ${who}` : ""} on ${host} to Arca?`;
    const buttonLabel = (verdict) =>
      verdict === "locked"
        ? "Unlock & Save"
        : verdict === "update"
          ? "Update"
          : "Save";
    saveBar = document.createElement("div");
    saveBar.className = "sybr-savebar";
    const text = document.createElement("span");
    text.className = "sybr-savebar-text";
    text.textContent = describe(action, storedUsername || candidate.username);
    const yes = document.createElement("button");
    yes.className = "sybr-savebar-yes";
    yes.textContent = buttonLabel(action);
    const no = document.createElement("button");
    no.className = "sybr-savebar-no";
    no.textContent = "Not now";
    const done = () => {
      api.runtime.sendMessage({ cmd: "clearPending" }).catch(() => {});
      closeSaveBar();
    };
    yes.addEventListener("click", async (e) => {
      // Same rule as the picker rows: only a human click may summon a Touch ID
      // prompt, and only a human click may commit a password to the vault. The
      // bar is in the page's DOM, so a synthetic click here would let a page
      // decide what Arca stores for its own origin.
      if (!e.isTrusted) return;
      if (saving) return;
      saving = true;
      yes.disabled = true;
      try {
        if (needsUnlock) {
          text.textContent = "Unlocking Arca…";
          const opened = await unlockAndWait();
          if (!opened) {
            text.textContent = "Arca is still locked.";
            return;
          }
          // The probe never got to ask while locked; ask now so a login that
          // turns out to be stored already is a quiet no-op, not a duplicate.
          const probe = await api.runtime
            .sendMessage({ cmd: "saveProbe", ...candidate })
            .catch(() => null);
          const verdict =
            probe && probe.ok && probe.response ? probe.response.action : null;
          if (verdict === "known") {
            done();
            return;
          }
          if (verdict === "disabled") {
            text.textContent = "Saving logins is disabled in Arca.";
            yes.remove();
            return;
          }
          if (verdict !== "new" && verdict !== "update") {
            text.textContent = "Arca could not verify this login. Try again.";
            return;
          }
          needsUnlock = false;
          // "Unlock & Save" was agreed to blind: while locked the app could
          // not say whether this is a new login or an update, let alone WHICH
          // stored account an update overwrites. Now that it can, an update
          // is shown for what it is and waits for a second, informed click —
          // the same bar an unlocked vault would have shown in the first
          // place. A new login is what the user already agreed to save.
          if (verdict === "update") {
            text.textContent = describe(
              "update",
              probe.response.username || candidate.username,
            );
            yes.textContent = buttonLabel("update");
            return;
          }
        }
        const result = await api.runtime.sendMessage({
          cmd: "saveLogin",
          ...candidate,
        });
        if (result && result.ok && result.response?.type === "saved") {
          done();
          return;
        }
        const reason =
          (result && result.response && result.response.message) ||
          (result && result.error) ||
          "";
        // The probe and the click are separate moments. If the vault locks in
        // between them, the old code swallowed this response, closed the bar
        // and claimed success while writing nothing. Keep the candidate (and
        // therefore the password) alive and make the next deliberate click
        // unlock before retrying.
        needsUnlock = /locked|not running|unreachable/i.test(reason);
        text.textContent = needsUnlock
          ? "Arca locked before the password was saved. Unlock and try again."
          : `Arca did not save the password${reason ? `: ${reason}` : "."}`;
        yes.textContent = needsUnlock ? "Unlock & Retry" : "Try again";
      } catch (error) {
        text.textContent = `Arca did not save the password: ${String(error)}`;
        yes.textContent = "Try again";
      } finally {
        saving = false;
        if (saveBar) yes.disabled = false;
      }
    });
    no.addEventListener("click", done);
    saveBar.append(text, yes, no);
    document.body.appendChild(saveBar);
  }

  /// Bring Arca forward for unlock and wait until it reports unlocked.
  /// Shared shape with requestUnlock's polling; separate because there is no
  /// anchor field here to re-render suggestions under.
  async function unlockAndWait() {
    const res = await api.runtime
      .sendMessage({ cmd: "requestUnlock" })
      .catch(() => null);
    const out = res && res.ok ? res.response : null;
    if (!out || out.type !== "unlock_requested") return false;
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 700));
      const probe = await api.runtime
        .sendMessage({ cmd: "listLogins", url: location.href })
        .catch(() => null);
      const resp = (probe && probe.ok && probe.response) || {};
      if (resp.app_connected) return true;
    }
    return false;
  }

  async function offerSave(candidate) {
    if (!candidate || !candidate.password) return;
    let probe;
    try {
      probe = await api.runtime.sendMessage({ cmd: "saveProbe", ...candidate });
    } catch (_e) {
      return;
    }
    const action =
      probe && probe.ok && probe.response ? probe.response.action : null;
    // "locked" gets the bar too. It used to be silently dropped, and with
    // lock-on-blur or a short idle timeout the vault is USUALLY locked at the
    // moment you sign in somewhere — which made save-on-submit look like it
    // did not exist at all.
    if (action === "new" || action === "update" || action === "locked") {
      showSaveBar(candidate, action, probe.response.username || "");
    }
  }

  // Stash the candidate for after navigation; for SPA logins that DON'T
  // navigate, offer only after a short delay AND only once the login form is
  // gone — a success signal, so a failed/mistyped login can't prompt to
  // overwrite a good stored password. Navigation-based logins tear down the
  // timer; the post-navigation reshow (below) handles those.
  //
  // Rate-limited: Enter in the password field followed by the page's own
  // submit event is two triggers for one sign-in, and two save bars.
  let lastStash = 0;
  let lastStashKey = "";
  let settleTimer = null;
  const SETTLE_DEADLINE_MS = 15000;
  /** Whether the submitted value is still sitting in a visible password box.
      A successful SPA password change commonly keeps the form mounted but
      clears its values, so `visiblePasswordField()` alone never settles. */
  function candidatePasswordStillVisible(candidate) {
    return queryAllDeep(
      document,
      'input[type="password"], input[type="text"]',
    ).some(
      (field) =>
        (field.type === "password" || knownPasswordFields.has(field)) &&
        isShown(field) &&
        field.value === candidate.password,
    );
  }

  /** Two or more password boxes on the page: a change/sign-up form is (still)
      up, so a submitted change has not gone through. */
  function changeFormStillUp() {
    return (
      queryAllDeep(
        document,
        'input[type="password"], input[type="text"]',
      ).filter(
        (field) =>
          (field.type === "password" || knownPasswordFields.has(field)) &&
          isShown(field),
      ).length >= 2
    );
  }

  function stashAndMaybeOffer(candidate) {
    if (!candidate) return;
    const now = Date.now();
    // Rate-limit the SAME candidate only. A different one inside the window
    // (generate P1, click generate again → P2, submit) must replace the stash,
    // or the post-navigation offer carries P1 while the account has P2.
    const key = `${candidate.username}\n${candidate.password}`;
    if (now - lastStash < 2000 && key === lastStashKey) return;
    lastStash = now;
    lastStashKey = key;
    api.runtime
      .sendMessage({ cmd: "capturePending", ...candidate })
      .catch(() => {});
    // Wait for the form to go away — the success signal — by polling, not the
    // single 1.5 s sample that missed every SPA login slower than that. A
    // generated password is offered at the deadline even with the form still
    // up: its value is live regardless, and losing it is the worse outcome.
    if (settleTimer !== null) clearTimeout(settleTimer);
    const started = now;
    const tick = () => {
      settleTimer = null;
      if (
        !visiblePasswordField() ||
        (candidate.multiPassword && !candidatePasswordStillVisible(candidate))
      ) {
        void offerSave(candidate);
        return;
      }
      if (Date.now() - started >= SETTLE_DEADLINE_MS) {
        if (candidate.generated) void offerSave(candidate);
        return;
      }
      settleTimer = setTimeout(tick, 500);
    };
    settleTimer = setTimeout(tick, 1500);
  }

  // Trigger 1: a real form submission.
  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;
      stashAndMaybeOffer(captureCandidate(form) ?? generatedCandidate());
    },
    true,
  );

  // Trigger 2: Enter in a password field. On fetch-based logins this is the
  // submission — no submit event ever fires.
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key !== "Enter") return;
      // composedPath, not e.target: from inside shadow DOM the event arrives
      // retargeted to the host element and the real input never matched.
      const el = eventTarget(e);
      if (!(el instanceof HTMLInputElement) || el.type !== "password") return;
      stashAndMaybeOffer(
        captureCandidate(el.form ?? el.getRootNode?.() ?? document) ??
          generatedCandidate(),
      );
    },
    true,
  );

  // Trigger 3: a click on something submit-shaped while a filled password
  // field is on the page. Deliberately BROAD on the button and strict on the
  // page state: the candidate still requires exactly one filled password field
  // and a username, the offer still waits for the form to disappear, and the
  // app's save_probe still decides whether there is anything worth saving. A
  // false trigger here costs a no-op probe, not a wrong prompt.
  document.addEventListener(
    "click",
    (e) => {
      const target = eventTarget(e);
      const button =
        target instanceof Element
          ? target.closest('button, input[type="submit"], [role="button"]')
          : null;
      if (!button) return;
      // Arca's own picker rows, generated-password panel and save bar are
      // buttons too; a click there is not the page being submitted.
      if (button.closest(".sybr-panel, .sybr-savebar")) return;
      const scope = button.closest("form") ?? document;
      stashAndMaybeOffer(captureCandidate(scope) ?? generatedCandidate());
    },
    true,
  );

  // After a navigation: if a login was just submitted and we now appear signed
  // in (same site, no password field), offer to save the stashed candidate.
  (async () => {
    let pending;
    try {
      pending = await api.runtime.sendMessage({ cmd: "consumePending" });
    } catch (_e) {
      return;
    }
    const cand = pending && pending.ok ? pending.candidate : null;
    if (!cand) return;
    // Reading the candidate consumes it. Every gate below can decline to offer
    // on THIS document — a login that lands on an interstitial and redirects
    // again, most of all — and the password used to be destroyed by the first
    // look at it, so the prompt never came on the page where it belonged. Put
    // it back (with its original age, so the TTL still expires on time) unless
    // it has actually been offered.
    let offered = false;
    const offer = (candidate) => {
      offered = true;
      void offerSave(candidate);
    };
    try {
      // A generated password skips both gates: sign-up and reset forms land on
      // a LOGIN page (which has a password field), frequently on another host
      // (connect.visma.com fronting the app it signs you into). The bar names
      // the site it saves for, and the value is the live password either way.
      if (cand.generated) {
        offer(cand);
        return;
      }
      // A password-change form may redirect to a sign-in form on the SAME
      // site. Seeing another password field there does not mean the change
      // failed; the navigation itself is the success signal. Unlike a
      // generated password we do not cross hosts for a manually captured
      // value. The one landing page that DOES mean failure is the change form
      // itself, re-rendered by the server with an error ("current password
      // incorrect"): two or more password boxes again. Offering there would
      // overwrite the good stored password with a value the site just
      // rejected.
      if (cand.multiPassword && sameSite(cand.url, location.href)) {
        if (!changeFormStillUp()) offer(cand);
        return;
      }
      if (sameSite(cand.url, location.href) && !visiblePasswordField()) {
        offer(cand);
      }
    } finally {
      if (!offered) {
        api.runtime
          .sendMessage({ cmd: "capturePending", ...cand })
          .catch(() => {});
      }
    }
  })();
})();
