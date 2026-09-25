// Passkey provider (main world). Runs at document_start in the page's own JS
// context so it can wrap the WebAuthn API. When a relying party calls
// navigator.credentials.create/get with a `publicKey` request, we hand it to
// the Arca desktop app (via the isolated content script -> background
// -> native host -> loopback bridge), which does the ES256 authenticator work,
// and return a WebAuthn-shaped result. If we can't service it (app locked, no
// matching passkey, only non-ES256 requested, error), we fall back to the
// browser's native handler so security keys / phone / built-in still work.
//
// This is the cross-platform path (works on Linux + every Chromium browser),
// independent of any OS credential-provider framework.

(() => {
  const creds = navigator.credentials;
  if (!creds || !creds.create || !creds.get || window.__sybrPasskeyHooked) return;
  window.__sybrPasskeyHooked = true;

  const realCreate = creds.create.bind(creds);
  const realGet = creds.get.bind(creds);

  // Every path that hands a ceremony back to the browser goes through here.
  //
  // Without it the fallbacks are indistinguishable: a missing gesture, a locked
  // vault, no passkey for the site, and a per-site "never" all look exactly the
  // same from the outside — the browser's own dialog. `console.debug` keeps it
  // out of the way (DevTools → Verbose) while making the reason one filter away.
  function fallback(kind, reason, options, real) {
    console.debug(`[Arca] passkey ${kind} → browser (${reason})`);
    return real(options);
  }

  /** The other outcome: Arca produced the credential itself. */
  function answered(kind, detail) {
    console.debug(`[Arca] passkey ${kind} → answered by Arca`, detail);
  }

  // May Arca answer THIS ceremony?
  //
  // The gesture is deliberately not tracked in this world any more. A ceremony
  // frequently runs in a document the user never clicked in: Microsoft Entra
  // navigates from login.microsoftonline.com to
  // login.microsoft.com/common/bridge/fido and fires get() on load, so an
  // in-page timestamp is necessarily zero and every M365 sign-in fell through
  // to the browser — on Linux, into the QR / security-key dialog, because there
  // is no platform authenticator to catch it quietly.
  //
  // The isolated relay now records gestures in a per-tab ledger in the
  // background worker, where they outlive the navigation, and answers this gate
  // from the ledger plus the site's own policy. The gesture is still consumed:
  // one gesture, one ceremony, which is what stops a page re-firing get() in a
  // loop from becoming a stream of prompts.
  // Short, because nothing human is on the other end — but long enough to
  // absorb a cold service-worker start, since timing out here means wrongly
  // handing a ceremony Arca could have answered back to the browser.
  const GATE_TIMEOUT_MS = 3000;

  // A shim outlives the extension that installed it.
  //
  // Reloading or updating the extension does NOT evict code already injected
  // into an open tab: this function object keeps wrapping WebAuthn in every tab
  // that was open at the time, running rules that shipped before the fix you
  // just made. That is how the GitHub prompt loop kept coming back after it had
  // been fixed, and why "close the tab" was the only cure anyone could find.
  //
  // So the shim retires itself the moment it learns it is out of date. Two
  // signals, because the two ways it goes stale look different from in here:
  //   • the relay reports a different extension version than the one this shim
  //     first saw -> the extension was updated underneath us;
  //   • the relay reports its context is gone -> the extension was reloaded and
  //     this tab's isolated half is orphaned.
  // Retirement is permanent and total: no gate, no messaging, no 3-second
  // stall on every ceremony. The browser's own handler takes over, which is
  // exactly what would happen if Arca had never been installed.
  let retired = false;
  let seenVersion = null;

  function noteVersion(r) {
    if (r.stale) {
      retired = true;
      console.debug("[Arca] passkey shim retired: the extension was reloaded");
      return;
    }
    if (!r.version) return;
    if (seenVersion === null) {
      seenVersion = r.version;
    } else if (seenVersion !== r.version) {
      retired = true;
      console.debug(
        `[Arca] passkey shim retired: extension ${seenVersion} -> ${r.version}`,
      );
    }
  }

  /// `kind` is "create" or "get" — the gate treats them differently, and the
  /// caller must not be able to get a create past the create rules by asking
  /// for a get.
  async function mayClaim(kind) {
    if (retired) return { allow: false, reason: "shim_retired" };
    const r = await ask("gate", { isCreate: kind === "create" }, GATE_TIMEOUT_MS);
    noteVersion(r);
    if (retired) return { allow: false, reason: "shim_retired" };
    return { allow: !!r.ok, reason: r.reason || "gate_timeout" };
  }

  // Request/response correlation with the isolated content script.
  let seq = 0;
  const pending = new Map();
  window.addEventListener("message", (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.__sybrPasskey !== "response") return;
    const request = pending.get(d.id);
    if (request) {
      pending.delete(d.id);
      clearTimeout(request.timer);
      request.resolve(d);
    }
  });
  function ask(kind, payload, timeoutMs = 180000, signal) {
    return new Promise((resolve) => {
      const id = `${seq++}`;
      const cancel = () => {
        if (!pending.has(id)) return;
        pending.delete(id);
        clearTimeout(timer);
        window.postMessage({ __sybrPasskey: "request", kind: "cancel", id }, window.location.origin);
        signal?.removeEventListener("abort", cancel);
        resolve({ ok: false, error: signal?.aborted ? "request_aborted" : "unlock_cancelled" });
      };
      // Safety timeout: fall back if the app never answers. The ceremony calls
      // get a long one because a real answer waits on the user typing a master
      // password; the gate gets a short one because nothing human is involved
      // and a stalled gate would freeze the site's sign-in button instead.
      const timer = setTimeout(cancel, timeoutMs);
      const finish = result => { signal?.removeEventListener("abort", cancel); resolve(result); };
      pending.set(id, { resolve: finish, timer });
      if (signal?.aborted) { cancel(); return; }
      signal?.addEventListener("abort", cancel, { once: true });
      window.postMessage(
        { __sybrPasskey: "request", kind, id, payload },
        window.location.origin,
      );
    });
  }

  // Sites probe support before calling create(). Include the available Arca
  // provider in that probe; checking for an existing key would prevent first
  // registration. This never approves a ceremony or changes signed UV flags.
  async function providerAvailable() {
    if (retired) return false;
    const result = await ask("providerAvailability", {}, GATE_TIMEOUT_MS);
    noteVersion(result);
    return !retired && !!result.ok;
  }
  const PKC = globalThis.PublicKeyCredential;
  if (PKC) {
    const nativeAvailable = PKC.isUserVerifyingPlatformAuthenticatorAvailable;
    if (typeof nativeAvailable === "function") {
      PKC.isUserVerifyingPlatformAuthenticatorAvailable = async function () {
        const native = await nativeAvailable.call(PKC);
        return native || await providerAvailable();
      };
    }
    const nativeCapabilities = PKC.getClientCapabilities;
    if (typeof nativeCapabilities === "function") {
      PKC.getClientCapabilities = async function () {
        const caps = await nativeCapabilities.call(PKC);
        if (!await providerAvailable()) return caps;
        return { ...caps, userVerifyingPlatformAuthenticator: true };
      };
    }
  }

  const toArr = (buf) => (buf ? Array.from(new Uint8Array(buf)) : []);
  const fromArr = (arr) => new Uint8Array(arr || []).buffer;
  const b64url = (buf) => {
    let s = "";
    for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  // The client data is not built in this world. Everything here is the page's
  // to rewrite, and the signature covers the client data's hash; the isolated
  // relay builds it from the challenge and hands back the bytes it signed.

  // Build the object the relying party's own JavaScript receives.
  //
  // A bare object literal is NOT enough, and the way it fails is invisible from
  // here: the ceremony completes, Arca reports success, and the *site* throws
  // while handling the result. Microsoft Entra is the case that exposed it —
  // the same credential signs in fine when the phone answers over the QR
  // transport, because then the browser hands the site a real
  // PublicKeyCredential.
  //
  // So two things beyond the plain fields:
  //   • `toJSON()`, which WebAuthn L3 defines and modern RP code calls to
  //     serialise the credential. Missing, it is a TypeError inside the site.
  //   • the real prototypes, so `instanceof PublicKeyCredential` holds. Every
  //     member of those prototypes is a brand-checked accessor that would throw
  //     on a foreign object, which is exactly why each one is shadowed by an own
  //     property below — reads hit ours, never theirs.
  function shapedCredential(kind, rawId, response, extras) {
    const asJSON =
      kind === "create"
        ? () => ({
            id: b64url(rawId),
            rawId: b64url(rawId),
            type: "public-key",
            authenticatorAttachment: "platform",
            clientExtensionResults: {},
            response: {
              clientDataJSON: b64url(response.clientDataJSON),
              attestationObject: b64url(response.attestationObject),
              transports: ["internal"],
            },
          })
        : () => ({
            id: b64url(rawId),
            rawId: b64url(rawId),
            type: "public-key",
            authenticatorAttachment: "platform",
            clientExtensionResults: {},
            response: {
              clientDataJSON: b64url(response.clientDataJSON),
              authenticatorData: b64url(response.authenticatorData),
              signature: b64url(response.signature),
              userHandle: response.userHandle
                ? b64url(response.userHandle)
                : null,
            },
          });

    const cred = {
      id: b64url(rawId),
      rawId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => ({}),
      toJSON: asJSON,
    };
    Object.assign(cred, extras || {});

    const ResponseCtor =
      kind === "create"
        ? globalThis.AuthenticatorAttestationResponse
        : globalThis.AuthenticatorAssertionResponse;
    try {
      if (typeof ResponseCtor === "function") {
        Object.setPrototypeOf(response, ResponseCtor.prototype);
      }
      if (typeof globalThis.PublicKeyCredential === "function") {
        Object.setPrototypeOf(cred, globalThis.PublicKeyCredential.prototype);
      }
    } catch (_e) {
      // A plain object still works for sites that only read the fields; losing
      // `instanceof` is better than losing the credential.
    }
    return cred;
  }

  navigator.credentials.create = async function (options) {
    const pk = options && options.publicKey;
    if (!pk) return realCreate(options);
    const mediation = options && options.mediation;
    // Conditional/silent CREATE is the browser's background "upgrade this
    // password login to a passkey" flow (sites like GitHub fire it after every
    // password sign-in). Servicing it would pop an approval + register a fresh
    // passkey on each login — endless prompts and duplicate keys. Only handle
    // the explicit, user-initiated (modal) registration.
    if (mediation === "conditional" || mediation === "silent") {
      return fallback("create", `mediation:${mediation}`, options, realCreate);
    }
    // Only a user-initiated registration (a real "add a passkey" click) reaches
    // Arca; a page-load / background auto-fired create() defers to the browser
    // so it can never surprise-register a passkey.
    const gate = await mayClaim("create");
    if (!gate.allow) {
      return fallback("create", gate.reason, options, realCreate);
    }
    try {
      // We only implement ES256. If the RP requires something else, defer.
      const algs = (pk.pubKeyCredParams || []).map((p) => p.alg);
      if (algs.length && !algs.includes(-7)) {
        return fallback("create", "alg_not_es256", options, realCreate);
      }

      const resp = await ask("create", {
        challenge: toArr(pk.challenge),
        rpId: (pk.rp && pk.rp.id) || window.location.hostname,
        userName: (pk.user && pk.user.name) || "",
        userHandle: toArr(pk.user && pk.user.id),
        excludeCredentials: (pk.excludeCredentials || []).map((c) => toArr(c.id)),
      }, undefined, options.signal);
      if (resp.error === "request_aborted") throw new DOMException("Passkey request aborted", "AbortError");
      if (resp.error === "unlock_cancelled") throw new DOMException("Arca unlock cancelled or unavailable", "NotAllowedError");
      if (!resp.ok) {
        // Spec-correct duplicate handling: the RP listed credentials we already
        // hold in excludeCredentials, so the authenticator must answer
        // InvalidStateError. The site then knows a passkey exists and STOPS
        // asking - no prompt, no new key, no browser fallback.
        if (resp.error === "excluded") {
          throw new DOMException(
            "The user attempted to register an authenticator that contains one of the credentials already registered with the relying party.",
            "InvalidStateError",
          );
        }
        return fallback(
          "create",
          `app:${resp.error || "no_response"}`,
          options,
          realCreate,
        );
      }

      const response = {
        clientDataJSON: fromArr(resp.clientDataJSON),
        attestationObject: fromArr(resp.attestationObject),
        getTransports: () => ["internal"],
        getPublicKeyAlgorithm: () => -7,
        getPublicKey: () => null,
        getAuthenticatorData: () => null,
      };
      const rawId = fromArr(resp.credentialId);
      answered("create", {
        rpId: (pk.rp && pk.rp.id) || window.location.hostname,
        credentialId: b64url(rawId),
      });
      return shapedCredential("create", rawId, response);
    } catch (e) {
      // InvalidStateError is a deliberate, spec-mandated answer (credential
      // already registered) — it must reach the page, not trigger a fallback.
      if (e && (e.name === "InvalidStateError" || e.name === "NotAllowedError" || e.name === "AbortError")) throw e;
      return fallback(
        "create",
        `exception:${(e && e.name) || "unknown"}`,
        options,
        realCreate,
      );
    }
  };

  // ---- conditional autofill: shared with the browser, not surrendered -----
  //
  // The gate above fixes the PAGE-driven flow: click "sign in with a passkey",
  // the site navigates to its bridge document, that document fires get(), and
  // the per-tab gesture ledger lets Arca answer it.
  //
  // This is the other half — the PICKER-driven flow. A conditional get() is the
  // page saying "offer passkeys in the autofill UI". Handing it straight to the
  // browser was right for not prompting on page load, and wrong in one respect:
  // it left nothing for Arca's own picker to answer, so a passkey row could
  // only ever print a sentence telling the user to go find a button.
  //
  // The request is raced instead. The browser still receives it, so iCloud
  // Keychain and security keys behave exactly as before; in parallel Arca holds
  // the challenge, and picking one of our rows answers it and aborts the
  // browser's copy. Whoever the user actually chose wins.
  let liveConditional = null;

  function conditionalGet(options, pk, mediation) {
    // Our controller is chained to the page's in both directions: the page
    // aborting must still reach the browser, and ours firing must not cancel
    // anything else the page owns.
    const controller = new AbortController();
    const pageSignal = options.signal;
    let rejectArca;
    if (pageSignal) {
      if (pageSignal.aborted) {
        return fallback("get", `mediation:${mediation}`, options, realGet);
      }
      pageSignal.addEventListener("abort", abort, { once: true });
    }
    function abort() {
      rejectArca?.(new DOMException("Passkey request cancelled", "AbortError"));
      controller.abort();
    }

    let settle;
    const fromArca = new Promise((resolve, reject) => { settle = resolve; rejectArca = reject; });
    liveConditional?.cancel();
    const request = { pk, settle, done: false, busy: false, cancel: abort, signal: controller.signal };
    liveConditional = request;
    const clear = () => {
      if (liveConditional === request) liveConditional = null;
    };
    const timeout = Number(pk.timeout) > 0 ? setTimeout(() => {
      rejectArca(new DOMException("Passkey request timed out", "NotAllowedError"));
      controller.abort();
    }, Math.min(Number(pk.timeout), 2147483647)) : null;

    const browser = fallback(
      "get",
      `mediation:${mediation}`,
      { ...options, signal: controller.signal },
      realGet,
    ).then(
      (credential) => {
        clear();
        return credential;
      },
      async (error) => {
        // No built-in authenticator / native autofill refusal does not mean
        // Arca has no passkey. Keep its explicit picker available for this
        // challenge; page cancellation and the site's timeout still apply.
        if (mediation === "conditional" && !controller.signal.aborted && liveConditional === request &&
            ["NotAllowedError", "NotSupportedError"].includes(error.name)) {
          const available = await ask("availability", {}, GATE_TIMEOUT_MS);
          if (available.ok && !controller.signal.aborted && liveConditional === request) return fromArca;
        }
        clear();
        throw error;
      },
    );

    return Promise.race([browser, fromArca]).finally(() => {
      request.done = true;
      if (timeout !== null) clearTimeout(timeout);
      clear();
      pageSignal?.removeEventListener("abort", abort);
      // Arca answered: dismiss the browser's competing request as well.
      controller.abort();
    });
  }

  /// Answer the live conditional request with the passkey the user picked.
  ///
  /// Return a specific refusal so the picker can distinguish a username-only
  /// first step from a cancelled request or an unavailable vault.
  async function useConditional(credentialId) {
    const request = liveConditional;
    const refused = (reason) => ({ ok: false, reason });
    if (!request || request.done) return refused("no_request");
    if (request.busy) return refused("in_progress");
    const allowed = (request.pk.allowCredentials || []).map((c) => toArr(c.id));
    if (credentialId?.length && allowed.length && !allowed.some((id) =>
      id.length === credentialId.length && id.every((byte, index) => byte === credentialId[index]))) {
      return refused("account_mismatch");
    }
    request.busy = true;
    const current = () => liveConditional === request && !request.done;
    try {
      // The same gate a modal ceremony passes. A page posting messages at us
      // cannot conjure a prompt; only a real gesture in this tab can.
      const gate = await mayClaim("get");
      if (!gate.allow) {
        console.debug(`[Arca] passkey use → refused (${gate.reason})`);
        return refused(gate.reason);
      }
      if (!current()) return refused("request_cancelled");

      const pk = request.pk;
      const rpId = pk.rpId || window.location.hostname;
      const resp = await ask("get", {
        challenge: toArr(pk.challenge),
        rpId,
        // The row the user picked, not "whatever matches this site" — with two
        // passkeys for one site the choice has to mean something. Whether it
        // WAS picked is for the relay to say, from the click it saw itself.
        allowCredentials:
          credentialId && credentialId.length
            ? [credentialId]
            : (pk.allowCredentials || []).map((c) => toArr(c.id)),
      }, undefined, request.signal);
      if (!current()) return refused("request_cancelled");
      if (!resp.ok) {
        console.debug(`[Arca] passkey use → app said no (${resp.error || "no_response"})`);
        return refused(resp.error || "no_response");
      }

      const uh = resp.userHandle && resp.userHandle.length ? fromArr(resp.userHandle) : null;
      const response = {
        clientDataJSON: fromArr(resp.clientDataJSON),
        authenticatorData: fromArr(resp.authenticatorData),
        signature: fromArr(resp.signature),
        userHandle: uh,
      };
      const rawId = fromArr(resp.credentialId);
      answered("get", {
        rpId,
        credentialId: b64url(rawId),
        via: "picker",
        userHandle: uh ? b64url(uh) : null,
        userVerified: !!(new Uint8Array(response.authenticatorData)[32] & 0x04),
      });
      request.done = true;
      request.settle(shapedCredential("get", rawId, response));
      return { ok: true };
    } catch (e) {
      console.debug(`[Arca] passkey use → exception:${(e && e.name) || "unknown"}`);
      return refused("request_failed");
    } finally { request.busy = false; }
  }

  // The picker lives in the isolated world and cannot call in here directly;
  // window messages are the one channel both worlds share.
  window.addEventListener("message", async (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.__sybrPasskey !== "use") return;
    const result = await useConditional(d.credentialId);
    window.postMessage(
      { __sybrPasskey: "use-result", id: d.id, ...result },
      window.location.origin,
    );
  });

  navigator.credentials.get = async function (options) {
    const pk = options && options.publicKey;
    if (!pk) return realGet(options);
    const mediation = options && options.mediation;
    // Conditional / silent mediation is *passive* passkey autofill: the page
    // probes on load or field-focus to offer credentials, it is NOT an explicit
    // "use my passkey" action. Servicing it ourselves would pop an approval /
    // Touch ID prompt just for visiting the page — and again every time the page
    // re-arms autofill. Defer these to the browser's native handler; Arca only
    // answers the modal flow the user actively triggers (default/required).
    if (mediation === "conditional" || mediation === "silent") {
      return conditionalGet(options, pk, mediation);
    }
    // Even a default-mediation get() must NOT prompt unless the user actually
    // asked for a sign-in. GitHub's login page auto-fires a default get() on
    // page load (not conditional), which reaching Arca pops a prompt while the
    // user is just visiting — the reported nag. So require an unspent gesture
    // somewhere in this tab: a real "sign in with a passkey" click has one,
    // whether it happened here or on the page that navigated here; a page-load
    // auto-fire in a tab the user has not touched does not.
    const gate = await mayClaim("get");
    if (!gate.allow) {
      return fallback("get", gate.reason, options, realGet);
    }
    try {
      const resp = await ask("get", {
        challenge: toArr(pk.challenge),
        rpId: pk.rpId || window.location.hostname,
        allowCredentials: (pk.allowCredentials || []).map((c) => toArr(c.id)),
      }, undefined, options.signal);
      if (resp.error === "request_aborted") throw new DOMException("Passkey request aborted", "AbortError");
      if (resp.error === "account_selection_cancelled" || resp.error === "unlock_cancelled") {
        throw new DOMException("Arca authentication cancelled or unavailable", "NotAllowedError");
      }
      if (!resp.ok) {
        return fallback(
          "get",
          `app:${resp.error || "no_response"}`,
          options,
          realGet,
        );
      }

      const uh = resp.userHandle && resp.userHandle.length ? fromArr(resp.userHandle) : null;
      const response = {
        clientDataJSON: fromArr(resp.clientDataJSON),
        authenticatorData: fromArr(resp.authenticatorData),
        signature: fromArr(resp.signature),
        userHandle: uh,
      };
      const rawId = fromArr(resp.credentialId);
      // The success path logs too, so "Arca answered and the site rejected it"
      // is visible rather than inferred from the absence of a fallback line.
      // Everything here is data the relying party is about to be handed anyway.
      answered("get", {
        rpId: pk.rpId || window.location.hostname,
        credentialId: b64url(rawId),
        allowCredentials: (pk.allowCredentials || []).map((c) => b64url(c.id)),
        userHandle: uh ? b64url(uh) : null,
        userVerified: !!(new Uint8Array(response.authenticatorData)[32] & 0x04),
      });
      return shapedCredential("get", rawId, response);
    } catch (e) {
      if (e?.name === "NotAllowedError" || e?.name === "AbortError") throw e;
      return fallback(
        "get",
        `exception:${(e && e.name) || "unknown"}`,
        options,
        realGet,
      );
    }
  };
})();
