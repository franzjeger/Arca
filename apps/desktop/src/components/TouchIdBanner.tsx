import { useState } from "react";
import { api, errorMessage } from "../lib/api";
import { TouchIdIcon } from "./icons";
import { toastError, type ToastMessage } from "../lib/toast";

/**
 * One-time nudge to turn on Touch ID quick unlock, shown after unlocking when
 * biometrics are available but quick unlock isn't set up yet. Dismissal is
 * remembered so it doesn't nag on every launch.
 */
export function TouchIdBanner({
  onEnabled,
  onToast,
}: {
  onEnabled: () => void;
  onToast: (msg: ToastMessage) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [dismissed, setDismissed] = useState(
    () => localStorage.getItem("touchIdHintDismissed") === "1",
  );

  if (dismissed) return null;

  const dismiss = () => {
    localStorage.setItem("touchIdHintDismissed", "1");
    setDismissed(true);
  };

  const enable = async () => {
    setBusy(true);
    try {
      await api.enableQuickUnlock();
      onToast("Quick unlock enabled");
      onEnabled();
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-center gap-3 border-b border-hairline bg-accent/10 px-4 py-2.5">
      <TouchIdIcon className="h-5 w-5 shrink-0 text-accent" />
      <div className="min-w-0 flex-1">
        <div className="text-[13px] text-neutral-100">Unlock with your device</div>
        <div className="text-[11px] text-neutral-400">
          Skip typing your master password next time. It is never stored.
        </div>
      </div>
      <button
        onClick={() => void enable()}
        disabled={busy}
        className="shrink-0 rounded-lg bg-accent px-3 py-1.5 text-[12px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
      >
        Enable
      </button>
      <button
        onClick={dismiss}
        disabled={busy}
        className="shrink-0 text-[12px] text-neutral-400 hover:text-neutral-200"
      >
        Not now
      </button>
    </div>
  );
}
