import { useEffect, useRef, useState } from "react";
import { api, errorMessage, isApiError, type VaultStatus } from "../lib/api";
import { KeyIcon, LockIcon, TouchIdIcon } from "./icons";

export function LockScreen({
  status,
  autoLocked = false,
  onUnlocked,
}: {
  status: VaultStatus;
  /// The vault locked by itself. Suppresses the automatic Touch ID prompt.
  autoLocked?: boolean;
  onUnlocked: () => void;
}) {
  const creating = !status.exists;
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // First-run fork: "restore" is the yes-branch of "do you already have a
  // vault?". Creating a new vault mints a new vault key, after which sync
  // refuses the real vault on Drive as foreign — so someone with an existing
  // vault must never be funnelled into Create as the only door.
  const [restoring, setRestoring] = useState(false);
  const [account, setAccount] = useState<string | null>(null);

  const connectGoogle = async () => {
    setError(null);
    setBusy(true);
    try {
      setAccount(await api.syncConnect());
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const restore = async () => {
    if (!password) return;
    setError(null);
    setBusy(true);
    try {
      await api.syncBootstrap(password);
      setPassword("");
      onUnlocked();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = async () => {
    setError(null);
    if (restoring) {
      await restore();
      return;
    }
    if (creating) {
      if (password.length < 8) {
        setError("Use at least 8 characters for your master password.");
        return;
      }
      if (password !== confirm) {
        setError("Passwords don't match.");
        return;
      }
    } else if (!password) {
      return;
    }
    setBusy(true);
    try {
      if (creating) await api.createVault(password);
      else await api.unlock(password);
      setPassword("");
      setConfirm("");
      onUnlocked();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  // After quick unlock FAILS past the biometric (stale device key, keychain
  // trouble), stop offering Touch ID entirely until a password unlock allows repair
  // in Settings — more prompts can only fail the same way. A storm of re-prompts here is
  // exactly the failure mode this guards against.
  const [quickBroken, setQuickBroken] = useState(false);

  const autoTried = useRef(false);
  const quickPending = useRef(false);
  const quick = async (auto = false) => {
    // React state updates are asynchronous; claim the attempt synchronously
    // so a click and a focus event cannot each request a system prompt.
    if (quickPending.current) return;
    quickPending.current = true;
    autoTried.current = true;
    setBusy(true);
    if (!auto) setError(null);
    try {
      await api.quickUnlock();
      onUnlocked();
    } catch (e) {
      const code = isApiError(e) ? e.code : "";
      if (code === "unlock_in_progress") {
        // Another entry point owns the prompt; its unlock event refreshes us.
      } else if (code === "biometric_failed" || code === "unlock_cancelled") {
        // The user cancelled/failed the prompt itself. Quiet on the automatic
        // attempt; show the reason on a manual retry.
        if (!auto) setError(errorMessage(e));
      } else {
        // Touch ID SUCCEEDED but the unlock itself failed (stale device key
        // etc.). Always surface this and stop prompting — only the master
        // password can get past it; macOS repair is then available in Settings.
        setQuickBroken(true);
        setError(errorMessage(e));
      }
    } finally {
      quickPending.current = false;
      setBusy(false);
    }
  };

  // Prompt for Touch ID only when the user came to Arca — never after Arca
  // locked itself.
  //
  // It used to fire the moment the lock screen mounted, which sounded like the
  // system lock screen and behaves nothing like it: the system only shows one
  // when you are standing in front of it. Ours mounted when the idle timer
  // expired, which is by definition while you were doing something else, so a
  // Touch ID sheet jumped in front of whatever you were working on and asked
  // you to authenticate to an app you had not opened. Repeatedly. It was the
  // single most irritating thing Arca did.
  //
  // `autoLocked` is the whole distinction: no request from you, no demand from
  // us. The Touch ID button below is the way in when you do want one.
  //
  // The password field stays available, and none of this re-triggers on
  // clicking into it: typing your password must not spawn biometric prompts.
  const canBiometric =
    !creating &&
    status.quickUnlockAvailable &&
    status.biometricAvailable &&
    !quickBroken;

  // The USB key (Linux). No prompt is involved, so none of the Touch ID
  // etiquette above applies: a key that is plugged in IS the user's standing
  // request to be let in, and the automatic attempt costs them nothing. It
  // still waits for focus — the vault should not spring open in the
  // background while the window sits behind something else — and it still
  // fires once, so a stale key does not produce an error on every focus.
  const keyFile = !creating && status.keyFile?.enrolled ? status.keyFile : null;
  const keyPresent = !!keyFile?.present;
  const keyTried = useRef(false);
  const keyPending = useRef(false);
  const useKey = async (auto: boolean) => {
    if (keyPending.current) return;
    keyPending.current = true;
    keyTried.current = true;
    setBusy(true);
    if (!auto) setError(null);
    try {
      await api.keyfileUnlock();
      onUnlocked();
    } catch (e) {
      // Automatic attempts stay quiet: "plug in your key" is already the hint
      // on screen. A click gets the reason.
      if (!auto) setError(errorMessage(e));
    } finally {
      keyPending.current = false;
      setBusy(false);
    }
  };
  useEffect(() => {
    if (!keyPresent) return;
    const attempt = () => {
      if (keyTried.current || !document.hasFocus()) return;
      void useKey(true);
    };
    attempt();
    window.addEventListener("focus", attempt);
    return () => window.removeEventListener("focus", attempt);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keyPresent]);
  useEffect(() => {
    // Locked by the idle timer or by losing focus: stay quiet. You did not ask
    // for anything, so nothing asks you for a fingerprint — not while the
    // window sits in front of you, and not when you come back to it either.
    // The button below is right there when you do want in.
    // A plugged-in USB key answers first and silently; it would be absurd to
    // raise a Touch ID sheet over a vault the key is about to open.
    if (!canBiometric || autoLocked || keyPresent) return;
    const attempt = () => {
      if (autoTried.current || !document.hasFocus()) return;
      autoTried.current = true;
      void quick(true);
    };
    attempt();
    // A window that opens unfocused still gets its prompt, once, when it is
    // brought forward — that IS the user arriving.
    window.addEventListener("focus", attempt);
    return () => window.removeEventListener("focus", attempt);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canBiometric, autoLocked, keyPresent]);

  return (
    <div className="flex flex-1 items-center justify-center bg-canvas">
      <div className="w-80">
        <div className="mb-6 flex flex-col items-center gap-3">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent/15 ring-1 ring-accent/30">
            <LockIcon className="h-8 w-8 text-accent" />
          </div>
          <h1 className="text-[17px] font-semibold text-neutral-100">
            {restoring
              ? "Restore your vault"
              : creating
                ? "Create your vault"
                : "Unlock Arca"}
          </h1>
          <p className="text-center text-[12px] leading-relaxed text-neutral-500">
            {restoring
              ? account
                ? `Signed in as ${account}. Enter the master password of your existing vault to download and unlock it.`
                : "Sign in with the Google account your vault syncs to, then unlock it with its master password."
              : creating
                ? "Your master password encrypts everything locally. It is never stored or sent anywhere. If you forget it, the vault cannot be recovered."
                : keyFile
                  ? keyPresent
                    ? `Your USB key (${keyFile.volumeLabel}) is plugged in.`
                    : `Plug in your USB key (${keyFile.volumeLabel}), or enter your master password.`
                  : canBiometric
                    ? "Use quick unlock, or enter your master password."
                    : "Enter your master password to continue."}
          </p>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
          className="space-y-2.5"
        >
          {restoring && !account ? (
            <button
              type="button"
              disabled={busy}
              onClick={() => void connectGoogle()}
              className="w-full rounded-lg bg-accent py-2.5 text-[14px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
            >
              {busy ? "Waiting for the browser…" : "Sign in with Google"}
            </button>
          ) : (
            <input
              type="password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Master password"
              className="w-full rounded-lg bg-fill/5 px-3 py-2.5 text-[14px] text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60"
            />
          )}
          {creating && !restoring && (
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Confirm master password"
              className="w-full rounded-lg bg-fill/5 px-3 py-2.5 text-[14px] text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60"
            />
          )}

          {error && <p className="px-1 text-[12px] text-red-400">{error}</p>}

          {(!restoring || account) && (
            <button
              type="submit"
              disabled={busy}
              className="w-full rounded-lg bg-accent py-2.5 text-[14px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
            >
              {busy
                ? "Please wait…"
                : restoring
                  ? "Restore Vault"
                  : creating
                    ? "Create Vault"
                    : "Unlock"}
            </button>
          )}
        </form>

        {/* The fork. A screen that only offers Create quietly manufactures a
            second vault key for people who already have a vault, and their
            first contact with sync becomes a refusal. */}
        {creating && (
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setError(null);
              setPassword("");
              setRestoring(!restoring);
            }}
            className="mt-3 w-full rounded-lg bg-fill/5 py-2.5 text-[14px] font-medium text-neutral-100 ring-1 ring-line/15 hover:bg-fill/10 disabled:opacity-60"
          >
            {restoring
              ? "Back — create a new vault instead"
              : "I already have a vault — restore from Google Drive"}
          </button>
        )}

        {/* A real button, not a grey footnote. With the automatic prompt gone
            this is the everyday way in, and eleven-point secondary text is
            where features go to be never found. */}
        {keyFile && (
          <button
            type="button"
            disabled={busy}
            onClick={() => void useKey(false)}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-fill/5 py-2.5 text-[14px] font-medium text-neutral-100 ring-1 ring-line/15 hover:bg-fill/10 disabled:opacity-60"
          >
            <KeyIcon className="h-4 w-4" />
            Unlock with USB key
          </button>
        )}
        {canBiometric && (
          <button
            type="button"
            disabled={busy}
            onClick={() => void quick(false)}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-fill/5 py-2.5 text-[14px] font-medium text-neutral-100 ring-1 ring-line/15 hover:bg-fill/10 disabled:opacity-60"
          >
            <TouchIdIcon className="h-4 w-4" />
            Use quick unlock
          </button>
        )}
      </div>
    </div>
  );
}
