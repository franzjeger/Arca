import { Dialog } from "./Dialog";
import { useReauthentication } from "../hooks/useReauthentication";
import { useState } from "react";
import { api, errorMessage } from "../lib/api";
import { LockIcon } from "./icons";

export function BackupRestoreDialog({
  syncConnected,
  onClose,
  onRestored,
}: {
  syncConnected: boolean;
  onClose: () => void;
  onRestored: () => void;
}) {
  const [path, setPath] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [verified, setVerified] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reauthentication = useReauthentication();

  const choose = async () => {
    setError(null);
    setVerified(false);
    try {
      const selected = await api.pickVaultBackup();
      if (selected) { setPath(selected); setVerified(false); }
    } catch (cause) {
      setError(errorMessage(cause));
    }
  };

  const restore = async () => {
    // Mirror the button's full guard. Enter twice during "Verifying…" used to
    // start two concurrent restores: two saves, two snapshots, two lock events.
    if (busy || syncConnected || !path || !password) return;
    setBusy(true);
    setError(null);
    setVerified(false);
    try {
      const confirmed = await reauthentication.run("replace your current vault with this backup", (currentPassword) => api.restoreVaultBackup(path, password, currentPassword));
      if (!confirmed) { setBusy(false); return; }
      setPassword("");
      onRestored();
    } catch (cause) {
      setError(errorMessage(cause));
      setBusy(false);
    }
  };

  const fileName = path?.split(/[\\/]/).pop();

  return (
    <Dialog label="Restore encrypted backup" onClose={onClose} dismissible={!busy}>
      {reauthentication.dialog}
      <div className="w-full max-w-md rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <LockIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            Restore encrypted backup
          </h2>
        </div>
        <div className="space-y-3 px-5 py-4 text-[13px]">
          <p className="text-neutral-400">
            Arca verifies and decrypts the backup before replacing anything.
            Your current vault is saved as a local snapshot first.
          </p>
          {syncConnected && (
            <p className="rounded-lg bg-amber-500/10 p-3 text-amber-300 ring-1 ring-amber-500/20">
              Disconnect Google Drive sync first, so a restored vault is not
              attached to the wrong remote vault.
            </p>
          )}
          <button
            type="button"
            disabled={busy}
            onClick={() => void choose()}
            className="w-full rounded-lg border border-hairline px-3 py-2 text-left text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
          >
            {fileName ?? "Choose .vault backup…"}
          </button>
          <input
            type="password"
            value={password}
            autoComplete="current-password"
            placeholder="Backup master password"
            onChange={(event) => { setPassword(event.target.value); setVerified(false); }}
            aria-label="Backup master password"
            onKeyDown={(event) => event.key === "Enter" && void restore()}
            className="w-full rounded-lg bg-fill/5 px-3 py-2 text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
          />
          {verified && <p role="status" className="text-[12px] text-green-400">Backup verified: password and encrypted contents are valid. Your current vault is unchanged.</p>}
          {error && <p className="text-[12px] text-red-400">{error}</p>}
        </div>
        <div className="flex justify-end gap-2 border-t border-hairline px-5 py-3">
          <button
            onClick={onClose}
            className="rounded-lg px-4 py-1.5 text-[13px] text-neutral-300 hover:bg-fill/5"
          >
            Cancel
          </button>
          <button
            disabled={busy || !path || !password}
            className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 disabled:opacity-50"
            onClick={async () => {
              if (busy || !path || !password) return;
              setBusy(true); setError(null); setVerified(false);
              try { await api.verifyVaultBackup(path, password); setVerified(true); }
              catch (e) { setError(errorMessage(e)); }
              finally { setBusy(false); }
            }}>Verify only</button>
          <button
            onClick={() => void restore()}
            disabled={busy || syncConnected || !path || !password}
            className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
          >
            {busy ? "Verifying…" : "Restore backup"}
          </button>
        </div>
      </div>
    </Dialog>
  );
}
