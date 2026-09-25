// Isolated-world relay for the main-world WebAuthn shim (passkey.js).
//
// Runs at document_start (like the shim), so an early passkey call — e.g.
// conditional-UI autofill during page load — has a listener ready immediately
// and never stalls waiting for the (document_idle) content script.
//
// SECURITY: the origin used for the app's rp_id<->origin anti-phishing check is
// taken from THIS isolated content script's `location.origin` (which the page
// cannot spoof), never from the page-posted message payload. The hostname the
// per-site passkey policy is keyed by comes from the same place.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (window.__sybrPasskeyRelay) return;
  window.__sybrPasskeyRelay = true;

  /// Is this content script still attached to a live extension?
  ///
  /// `runtime.id` goes undefined the moment the extension is reloaded or
  /// updated, while this script keeps running in the page. It is the only
  /// signal available from in here, and it is a reliable one.
  function contextAlive() {
    try {
      return !!(api && api.runtime && api.runtime.id);
    } catch (_e) {
      return false;
    }
  }

  /// The extension version this script belongs to, for the shim's staleness
  /// check. Unreadable once orphaned, which is itself the answer.
  function currentVersion() {
    try {
      return api.runtime.getManifest().version;
    } catch (_e) {
      return null;
    }
  }

  /** Fire-and-forget message; a sleeping worker must not throw into the page. */
  function tell(message) {
    try {
      const p = api.runtime.sendMessage(message);
      if (p && typeof p.catch === "function") p.catch(() => {});
    } catch (_e) {
      /* extension context torn down */
    }
  }

  // Real user input, watched in the capture phase so it is seen before the
  // page's own handlers — which may call credentials.get() synchronously.
  //
  // Two records are kept, because a ceremony can run in either place:
  //   • `localGesture`, for a ceremony fired in THIS document. Answered without
  //     a round trip, so a synchronous click handler cannot lose a race against
  //     our own message to the background worker.
  //   • the worker's per-tab ledger, for a ceremony fired in a document the
  //     user never clicked in — Entra's /common/bridge/fido, which the browser
  //     navigates to and which fires get() on load.
  const GESTURE_WINDOW_MS = 3000;

  // When this document came into being. The gate needs it to tell an ARRIVAL
  // page — one the browser just navigated to, which fires its ceremony on
  // load — from a page that has been sitting open and fires one on a timer.
  // Taken here at document_start, before any page script has run.
  const documentBorn = Date.now();

  /// One-use approvals minted by the gate and spent by the forwarding path.
  ///
  /// WHY THIS EXISTS. The shim asks the gate and then, if allowed, posts the
  /// ceremony itself. Nothing forced those two steps to be related: a page
  /// script could post `{__sybrPasskey:"request", kind:"create"}` straight at
  /// this listener and it was forwarded to the desktop app, which raised a
  /// Touch ID prompt. The gate was enforced only because the honest caller
  /// chose to consult it.
  ///
  /// Approvals live HERE, in the isolated world, and never travel through
  /// postMessage — so a page cannot forge one, only ask the gate itself, which
  /// applies the same rules it always did.
  ///
  /// Each approval is for one kind of ceremony. The gate judges a create more
  /// strictly than a get, so an approval given to a get must not buy a create.
  const APPROVAL_TTL_MS = 15000;
  let approvals = [];
  const mintApproval = (kind) => {
    const now = Date.now();
    approvals = approvals.filter((a) => now - a.at <= APPROVAL_TTL_MS).slice(-4);
    approvals.push({ kind, at: now });
  };
  const spendApproval = (kind) => {
    const now = Date.now();
    approvals = approvals.filter((a) => now - a.at <= APPROVAL_TTL_MS);
    const i = approvals.findIndex((a) => a.kind === kind);
    if (i < 0) return false;
    approvals.splice(i, 1);
    return true;
  };

  /// The passkey the user chose in Arca's own picker, and when.
  ///
  /// The desktop app takes that choice as the approval for the sign-in, so it
  /// has to be a fact the page cannot state. content.js records it here on a
  /// trusted click; this world is shared by the extension's content scripts and
  /// unreachable from page script. The page's request can say which credential
  /// it wants, never that the user picked it.
  const PICK_TTL_MS = 15000;
  let pick = null;
  window.__sybrPasskeyPicked = (credentialId) => {
    pick = { id: Array.from(credentialId || []), at: Date.now() };
  };
  /// Spend the pick. True only when it is fresh and names the one credential
  /// the request is for; taken either way, so one click approves one ceremony.
  const takePick = (allowCredentials) => {
    const p = pick;
    pick = null;
    if (!p || !p.id.length || Date.now() - p.at > PICK_TTL_MS) return false;
    if (!Array.isArray(allowCredentials) || allowCredentials.length !== 1) return false;
    const want = allowCredentials[0];
    return (
      Array.isArray(want) &&
      want.length === p.id.length &&
      want.every((b, i) => b === p.id[i])
    );
  };

  const isBytes = (v) =>
    Array.isArray(v) && v.every((b) => Number.isInteger(b) && b >= 0 && b <= 255);

  /// The client data the authenticator signs over.
  ///
  /// Built here, not in the page: the signature covers its hash, and the
  /// relying party trusts the `origin` inside it. Taken from the page it would
  /// say whatever the page wrote, and a script on sub.example.com could sign in
  /// to example.com as example.com. Only the challenge comes from the page, as
  /// it does in the browser's own WebAuthn.
  function clientDataJSON(type, challenge) {
    let s = "";
    for (const b of challenge) s += String.fromCharCode(b);
    const b64url = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return new TextEncoder().encode(
      JSON.stringify({ type, challenge: b64url, origin: location.origin, crossOrigin: false }),
    );
  }

  const REPORT_THROTTLE_MS = 500;
  let localGesture = 0;
  let sawLocal = false;
  let lastReport = 0;

  for (const type of ["pointerdown", "keydown", "touchstart"]) {
    window.addEventListener(
      type,
      (e) => {
        // Only input the BROWSER generated. `dispatchEvent` from page script
        // produces an event with `isTrusted === false`, and without this check
        // a page could manufacture its own "the user clicked" and satisfy the
        // gate's gesture rule on its own.
        if (!e.isTrusted) return;
        localGesture = Date.now();
        sawLocal = true;
        // A burst of keystrokes must not be a burst of worker messages; the
        // ledger only needs to know that a gesture happened, not how many.
        if (localGesture - lastReport > REPORT_THROTTLE_MS) {
          lastReport = localGesture;
          tell({ cmd: "gesture" });
        }
      },
      true,
    );
  }

  window.addEventListener("message", async (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.__sybrPasskey !== "request") return;

    if (d.kind === "providerAvailability") {
      let available = false;
      try {
        if (contextAlive()) {
          const result = await api.runtime.sendMessage({
            cmd: "passkeyProviderAvailable", host: location.hostname,
            url: location.href || location.origin,
          });
          available = !!result?.available;
        }
      } catch (_) { /* preserve the browser's native capability result */ }
      window.postMessage({ __sybrPasskey: "response", id: d.id,
        ok: available, version: currentVersion(), stale: !contextAlive(),
      }, location.origin);
      return;
    }

    if (d.kind === "availability") {
      let available = false;
      try {
        if (contextAlive()) {
          const result = await api.runtime.sendMessage({ cmd: "passkeyAvailable",
            host: location.hostname, url: location.href || location.origin });
          available = !!result?.available;
        }
      } catch (_) { /* an unavailable extension leaves the browser in charge */ }
      window.postMessage({ __sybrPasskey: "response", id: d.id, ok: available }, location.origin);
      return;
    }

    // May Arca answer this ceremony at all? Settled before anything reaches the
    // native host, so a declined gate never even wakes the desktop app.
    if (d.kind === "gate") {
      // Orphan check FIRST. Reloading the extension leaves this script running
      // in the page with a dead `chrome.runtime`, still wrapping WebAuthn with
      // whatever rules shipped that day. Telling the shim to retire is what
      // finally stops a tab that has been open since before a fix.
      if (!contextAlive()) {
        window.postMessage(
          {
            __sybrPasskey: "response",
            id: d.id,
            ok: false,
            reason: "extension_reloaded",
            stale: true,
          },
          location.origin,
        );
        return;
      }

      const fresh =
        localGesture > 0 && Date.now() - localGesture <= GESTURE_WINDOW_MS;
      if (fresh) localGesture = 0; // one gesture, one ceremony
      const kind = d.payload && d.payload.isCreate ? "create" : "get";
      let res = null;
      try {
        res = await api.runtime.sendMessage({
          cmd: "passkeyGate",
          host: location.hostname,
          localGesture: fresh,
          // A create is judged more strictly than a get: it may only ride a
          // carried gesture when this document is a fresh arrival nobody has
          // touched — Microsoft navigates to login.microsoft.com/…/fido/create
          // and that page fires create() on load. Everything else needs a
          // click right here. Sign-in is looser: Entra fires get() in a
          // document nobody clicked in, which is what the ledger exists for.
          isCreate: kind === "create",
          // Once the user has touched THIS document the in-document rule
          // governs alone, so a gesture carried from the page that navigated
          // here is not allowed to widen the old 3s window to the ledger's.
          sawLocal,
          // How long this document has existed. A ceremony fired moments
          // after load is the page finishing what a click elsewhere started;
          // one fired after the page has sat there for a while is not.
          documentAgeMs: Date.now() - documentBorn,
        });
      } catch (_e) {
        res = null;
      }
      if (res && res.allow) mintApproval(kind);
      window.postMessage(
        {
          __sybrPasskey: "response",
          id: d.id,
          ok: !!(res && res.allow),
          reason: (res && res.reason) || "gate_unavailable",
          // Carried on every gate answer so the shim can notice an update even
          // when the context is still alive: a new version answering means the
          // code in this page is a generation behind.
          version: (res && res.version) || currentVersion(),
          stale: !res && !contextAlive(),
        },
        location.origin,
      );
      return;
    }

    if (d.kind !== "create" && d.kind !== "get") return;
    // Nothing reaches the desktop app without an approval the gate minted
    // above. Spent here, so one approval carries one ceremony.
    if (!spendApproval(d.kind)) {
      window.postMessage(
        {
          __sybrPasskey: "response",
          id: d.id,
          ok: false,
          error: "no_gate_approval",
        },
        location.origin,
      );
      tell({ cmd: "log", line: `relay refused ungated ${d.kind} on ${location.hostname}` });
      return;
    }

    const p = d.payload || {};
    if (!isBytes(p.challenge)) {
      window.postMessage(
        { __sybrPasskey: "response", id: d.id, ok: false, error: "bad_request" },
        location.origin,
      );
      return;
    }
    // Before any await, so a second request cannot take this pick meanwhile.
    const picked = d.kind === "get" && takePick(p.allowCredentials);
    const clientData = clientDataJSON(
      d.kind === "create" ? "webauthn.create" : "webauthn.get",
      p.challenge,
    );
    let result;
    try {
      // Every field named. The page's payload is a request, not a message to
      // pass on: the origin, the client data hash and `picked` are ours.
      const message =
        d.kind === "create"
          ? {
              cmd: "passkeyCreate",
              origin: location.origin,
              rpId: p.rpId,
              userName: p.userName,
              userHandle: p.userHandle,
              excludeCredentials: p.excludeCredentials,
            }
          : {
              cmd: "passkeyGet",
              origin: location.origin,
              rpId: p.rpId,
              allowCredentials: p.allowCredentials,
              clientDataHash: Array.from(
                new Uint8Array(await crypto.subtle.digest("SHA-256", clientData)),
              ),
              picked,
            };
      result = await api.runtime.sendMessage(message);
    } catch (_e) {
      result = null;
    }
    const resp = result && result.ok ? result.response : null;
    const reply = { __sybrPasskey: "response", id: d.id, ok: false };
    if (resp && resp.type === "passkey_credential") {
      reply.ok = true;
      reply.credentialId = resp.credential_id;
      reply.attestationObject = resp.attestation_object;
    } else if (resp && resp.type === "error") {
      reply.error = resp.message;
    } else if (resp && resp.type === "passkey_assertion") {
      reply.ok = true;
      reply.credentialId = resp.credential_id;
      reply.authenticatorData = resp.authenticator_data;
      reply.signature = resp.signature;
      reply.userHandle = resp.user_handle;
    }
    // The page hands the relying party exactly the bytes that were signed.
    if (reply.ok) reply.clientDataJSON = Array.from(clientData);
    window.postMessage(reply, location.origin);
  });
})();
