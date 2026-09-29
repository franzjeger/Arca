import { useState } from "react";
import { Dialog } from "./Dialog";
import { api, errorMessage, isApiError } from "../lib/api";
import { LockIcon } from "./icons";

/**
 * Sync found that the master password was changed on another device, and
 * this device pushes nothing until it has the new one. Asked for once, here;
 * "Not now" leaves the status bar's button to come back to it.
 */
export function NewPasswordDialog({
  onDone,
  onClose,
}: {
  onDone: (quickUnlockLost: boolean) => void;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (busy || !password) return;
    setBusy(true);
    setError(null);
    try {
      const { quickUnlockLost } = await api.syncAdoptPassword(password);
      onDone(quickUnlockLost);
    } catch (e) {
      setPassword("");
      setError(
        isApiError(e) && e.code === "invalid_credentials"
          ? "That is not the new master password."
          : errorMessage(e),
      );
      setBusy(false);
    }
  };

  return (
    <Dialog label="Master password changed" onClose={onClose} dismissible={!busy}>
      <div className="w-full max-w-sm rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex flex-col items-center gap-3 px-6 pb-2 pt-6 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/15 ring-1 ring-accent/30">
            <LockIcon className="h-6 w-6 text-accent" />
          </div>
          <h2 className="text-[15px] font-semibold text-neutral-100">
            Master password changed
          </h2>
          <p className="text-[13px] leading-relaxed text-neutral-400">
            It was changed on another device. Enter the new one to keep this
            device in sync.
          </p>
        </div>
        <form
          className="px-6 pb-5 pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <input
            autoFocus
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="New master password"
            className="w-full rounded-lg border border-hairline bg-canvas px-3 py-2.5 text-[14px] text-neutral-100 outline-none focus:border-accent"
          />
          {error && <p className="mt-2 text-[12px] text-red-400">{error}</p>}
          <div className="mt-4 flex gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={busy}
              className="flex-1 rounded-lg border border-hairline py-2.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
            >
              Not now
            </button>
            <button
              type="submit"
              disabled={busy || !password}
              className="flex-1 rounded-lg bg-accent py-2.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {busy ? "Please wait…" : "Continue"}
            </button>
          </div>
        </form>
      </div>
    </Dialog>
  );
}
