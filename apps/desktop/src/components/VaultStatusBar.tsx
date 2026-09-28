import { useBackupStatus } from "../hooks/useBackupStatus";
import { useEffect, useRef, useState } from "react";
import { api, errorMessage } from "../lib/api";
import { syncLabel, useSyncStatus } from "../hooks/useSyncStatus";
import { NewPasswordDialog } from "./NewPasswordDialog";
import type { ToastMessage } from "../lib/toast";

export function VaultStatusBar({ onOpenSettings, conflictCount = 0, onReviewConflicts, onToast }: { onOpenSettings: () => void; conflictCount?: number; onReviewConflicts?: () => void; onToast?: (message: ToastMessage) => void }) {
  const { status, error } = useSyncStatus();
  const [actionError, setActionError] = useState<string | null>(null);
  // Asked once, when sync first finds the change; after "Not now" the button
  // below stays until the new password is in.
  const needsPassword = !!status?.needsPassword;
  const rolledBack = status?.rolledBack ?? [];
  const [askingPassword, setAskingPassword] = useState(false);
  const asked = useRef(false);
  useEffect(() => {
    if (needsPassword && !asked.current) setAskingPassword(true);
    if (!needsPassword) setAskingPassword(false);
    asked.current ||= needsPassword;
  }, [needsPassword]);
  const { status: backup, error: backupError, now } = useBackupStatus();
  const [retrying, setRetrying] = useState(false);
  useEffect(() => { if (status && !status.lastError) setActionError(null); }, [status]);
  // Two missed 15-minute backup intervals warrant attention, including after sleep.
  const backupWarning = (backupError ? "Backup status unavailable." : null) ?? backup?.lastError ?? (backup
    ? !backup.directory ? "Automatic backups are off"
      : backup.lastSuccessUnix === null ? "No successful backup yet"
      : now / 1000 - backup.lastSuccessUnix >= 30 * 60 ? "Last backup is over 30 minutes old"
      : null
    : null);
  const failure = actionError ?? error ?? status?.lastError;
  return <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-t border-hairline px-4 py-2 text-[11px] text-neutral-400">
    {conflictCount > 0 && <button onClick={onReviewConflicts} className="font-medium text-amber-400 hover:underline">Review {conflictCount} sync conflict{conflictCount === 1 ? "" : "s"}</button>}
    <span role="status">{failure ? "Saved locally · Sync needs attention" : syncLabel(status)}</span>
    {failure && <span className="text-amber-400">{failure}</span>}
    {needsPassword && <button className="text-accent hover:underline" onClick={() => setAskingPassword(true)}>Enter new password</button>}
    {rolledBack.length > 0 && <>
      <span role="alert" className="text-amber-400">
        Google Drive had lost the latest changes from {listed(rolledBack)}. Arca has put them back. If this happens again, someone else may have access to your Google account.
      </span>
      <button className="text-accent hover:underline" onClick={() => void api.syncAcknowledgeRollback().catch(() => {})}>OK</button>
    </>}
    {status?.connected && !needsPassword && (failure || status.pending) && <button
      className="text-accent hover:underline disabled:opacity-50"
      disabled={retrying || status.syncing}
      onClick={async () => {
        setRetrying(true); setActionError(null);
        try { await api.syncNow(); }
        catch (cause) { setActionError(errorMessage(cause)); }
        finally { setRetrying(false); }
      }}>Retry sync</button>}
    <span role="status" className={backupWarning ? "text-amber-400" : undefined}>
      {backupWarning ? `Backup: ${backupWarning}` : backup?.lastSuccessUnix != null
        ? `Backed up ${new Date(backup.lastSuccessUnix * 1000).toLocaleString()}`
        : "Checking backup…"}
    </span>
    {backupWarning && <button className="text-accent hover:underline" onClick={onOpenSettings}>Backup settings</button>}
    {askingPassword && <NewPasswordDialog
      onClose={() => setAskingPassword(false)}
      onDone={(quickUnlockLost) => {
        setAskingPassword(false);
        onToast?.(quickUnlockLost
          ? "This device now uses the new master password. Quick unlock is off; turn it back on in Settings."
          : "This device now uses the new master password.");
      }} />}
  </div>;
}

/** "a", "a and b", "a, b and c". */
function listed(names: string[]): string {
  return names.length > 1
    ? `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`
    : names[0] ?? "";
}
