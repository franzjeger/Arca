import { Dialog } from "./Dialog";
import { useState } from "react";
import { api, errorMessage, type PasskeyVerifyRequest } from "../lib/api";
import { KeyIcon } from "./icons";
import { toastError, type ToastMessage } from "../lib/toast";

/**
 * Approval prompt shown (Windows/Linux) for a passkey ceremony. Two modes,
 * decided by the bridge and not by this dialog: a single confirm button (the
 * default — the open vault was the verification, this click is the presence),
 * or the master password when the user turned that setting on. The bridge
 * thread is parked waiting, so every path must resolve exactly once: approve,
 * or Cancel/dismiss to deny. A wrong password keeps the dialog open for a retry.
 */
export function PasskeyVerifyDialog({
  request,
  onResolved,
  onToast,
}: {
  request: PasskeyVerifyRequest;
  onResolved: () => void;
  onToast: (msg: ToastMessage) => void;
}) {
  // Older builds omitted the flag and always wanted the password.
  const needsPassword = request.requirePassword !== false;
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const cancel = () => {
    api.cancelPasskeyVerification(request.id).catch(() => {});
    onResolved();
  };

  const submit = async () => {
    if (busy || (needsPassword && !password)) return;
    setBusy(true);
    setError(null);
    try {
      const ok =
        needsPassword || password
          ? await api.verifyPasskeyApproval(request.id, password)
          : await api.confirmPasskeyApproval(request.id);
      if (ok) {
        onResolved();
      } else if (needsPassword) {
        setError("Incorrect master password. Try again.");
        setPassword("");
        setBusy(false);
      } else {
        // The bridge insists on the password after all (a race with the
        // setting). Fall through to the password field rather than lie.
        setError("Enter your master password to continue.");
        setBusy(false);
      }
    } catch (e) {
      onToast(toastError(errorMessage(e)));
      setBusy(false);
    }
  };

  return (
    <Dialog label="Verify passkey" onClose={cancel} dismissible={!busy}>
      <div className="w-full max-w-sm rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex flex-col items-center gap-3 px-6 pb-2 pt-6 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/15 ring-1 ring-accent/30">
            <KeyIcon className="h-6 w-6 text-accent" />
          </div>
          <h2 className="text-[15px] font-semibold text-neutral-100">
            {request.isCreate
              ? "Create a new passkey?"
              : "Sign in with your passkey"}
          </h2>
          <p className="text-[13px] leading-relaxed text-neutral-400">
            {!needsPassword && !error ? (
              request.isCreate ? (
                <>
                  Register a{" "}
                  <span className="font-medium text-amber-300">brand-new</span>{" "}
                  passkey for{" "}
                  <span className="font-medium text-neutral-100">{request.site}</span>?
                </>
              ) : (
                <>
                  Sign in to{" "}
                  <span className="font-medium text-neutral-100">{request.site}</span>{" "}
                  with your passkey?
                </>
              )
            ) : request.isCreate ? (
              <>
                Enter your master password to register a{" "}
                <span className="font-medium text-amber-300">brand-new</span>{" "}
                passkey for{" "}
                <span className="font-medium text-neutral-100">
                  {request.site}
                </span>
                .
              </>
            ) : (
              <>
                Enter your master password to sign in to{" "}
                <span className="font-medium text-neutral-100">
                  {request.site}
                </span>
                .
              </>
            )}
          </p>
        </div>

        <form
          className="px-6 pb-5 pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          {(needsPassword || error) && (
            <input
              autoFocus
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Master password"
              className="w-full rounded-lg border border-hairline bg-canvas px-3 py-2.5 text-[14px] text-neutral-100 outline-none focus:border-accent"
            />
          )}
          {error && <p className="mt-2 text-[12px] text-red-400">{error}</p>}
          <div className="mt-4 flex gap-2">
            <button
              type="button"
              onClick={cancel}
              className="flex-1 rounded-lg border border-hairline py-2.5 text-[13px] text-neutral-200 hover:bg-fill/5"
            >
              Cancel
            </button>
            <button
              type="submit"
              autoFocus={!needsPassword}
              disabled={busy || ((needsPassword || !!error) && !password)}
              className="flex-1 rounded-lg bg-accent py-2.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {busy
                ? "Verifying…"
                : needsPassword || error
                  ? "Approve"
                  : request.isCreate
                    ? "Create passkey"
                    : "Sign in"}
            </button>
          </div>
        </form>
      </div>
    </Dialog>
  );
}
