import { Dialog } from "./Dialog";
import { useReauthentication } from "../hooks/useReauthentication";
import { useEffect, useState } from "react";
import { api, errorMessage, type SnapshotSummary } from "../lib/api";
import { toastError, type ToastMessage } from "../lib/toast";

/** "3 minutes ago", "yesterday, 14:02" — snapshots are read as "how far back". */
function describe(createdUnix: number): string {
  const then = new Date(createdUnix * 1000);
  const mins = Math.round((Date.now() - createdUnix * 1000) / 60000);
  const clock = then.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const today = new Date();
  const sameDay = then.toDateString() === today.toDateString();
  if (sameDay) return `today, ${clock}`;
  const yesterday = new Date(today.getTime() - 86400000);
  if (then.toDateString() === yesterday.toDateString())
    return `yesterday, ${clock}`;
  return `${then.toLocaleDateString(undefined, { day: "numeric", month: "short" })}, ${clock}`;
}

/**
 * Roll the vault back to an earlier on-disk version.
 *
 * Deliberately two-step: picking a version only arms it, and the confirm step
 * spells out that the app will lock afterwards. Restoring is itself snapshotted,
 * so a mistake here is recoverable too.
 */
export function RestoreDialog({
  onClose,
  onToast,
}: {
  onClose: () => void;
  onToast: (msg: ToastMessage) => void;
}) {
  const [snapshots, setSnapshots] = useState<SnapshotSummary[] | null>(null);
  const [armed, setArmed] = useState<SnapshotSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const reauthentication = useReauthentication();

  useEffect(() => {
    api
      .listSnapshots()
      .then(setSnapshots)
      .catch((e) => {
        onToast(toastError(errorMessage(e)));
        setSnapshots([]);
      });
  }, [onToast]);

  const restore = async (snap: SnapshotSummary) => {
    setBusy(true);
    try {
      const confirmed = await reauthentication.run("restore an earlier vault version", (password) => api.restoreSnapshot(snap.path, password));
      if (!confirmed) { setBusy(false); return; }
      // The backend emits "vault-locked", so App swaps to the lock screen.
      onToast(`Restored the version from ${describe(snap.createdUnix)}`);
      onClose();
    } catch (e) {
      onToast(toastError(errorMessage(e)));
      setBusy(false);
      setArmed(null);
    }
  };

  return (
    <Dialog label="Earlier vault versions" onClose={onClose} dismissible={!busy}>
      {reauthentication.dialog}
      <div className="flex max-h-[80vh] w-full max-w-md flex-col rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="border-b border-hairline px-5 py-3.5">
          <h2 className="text-[14px] font-semibold text-neutral-100">
            Earlier versions
          </h2>
          <p className="mt-1 text-[11px] leading-snug text-neutral-500">
            Each save keeps a copy of the vault as it was just before. Restoring
            replaces the current vault and locks Arca, so you unlock again with
            the master password that version used.
          </p>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-3">
          {snapshots === null ? (
            <p className="py-6 text-center text-[13px] text-neutral-500">
              Loading…
            </p>
          ) : snapshots.length === 0 ? (
            <p className="py-6 text-center text-[13px] text-neutral-500">
              No earlier versions yet. Arca starts keeping them the next time
              you change something.
            </p>
          ) : (
            <ul className="space-y-1.5">
              {snapshots.map((s) => {
                const isArmed = armed?.path === s.path;
                return (
                  <li
                    key={s.path}
                    className="rounded-lg bg-fill/5 px-3 py-2 ring-1 ring-line/10"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-[13px] text-neutral-100">
                          {describe(s.createdUnix)}
                        </div>
                        <div className="text-[11px] text-neutral-500">
                          {Math.round(s.bytes / 1024)} KB
                        </div>
                      </div>
                      {!isArmed && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => setArmed(s)}
                          className="shrink-0 rounded-lg border border-hairline px-3 py-1.5 text-[12px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                        >
                          Restore
                        </button>
                      )}
                    </div>
                    {isArmed && (
                      <div className="mt-2 border-t border-hairline pt-2">
                        <p className="text-[11px] leading-snug text-amber-300/90">
                          Replace the current vault with this version? Your
                          current state is saved as a new version first, so you
                          can undo this.
                        </p>
                        <div className="mt-2 flex justify-end gap-2">
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => setArmed(null)}
                            className="rounded-lg px-3 py-1.5 text-[12px] text-neutral-400 hover:text-neutral-200"
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => void restore(s)}
                            className="rounded-lg bg-accent px-3 py-1.5 text-[12px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
                          >
                            {busy ? "Restoring…" : "Restore this version"}
                          </button>
                        </div>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <div className="flex shrink-0 justify-end border-t border-hairline px-5 py-3">
          <button
            type="button"
            disabled={busy}
            onClick={onClose}
            className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
          >
            Close
          </button>
        </div>
      </div>
    </Dialog>
  );
}
