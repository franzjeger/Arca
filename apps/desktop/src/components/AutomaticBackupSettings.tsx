import { useBackupStatus } from "../hooks/useBackupStatus";
import { useState } from "react";
import { api, errorMessage } from "../lib/api";

export function AutomaticBackupSettings() {
  const { status, error: statusError } = useBackupStatus();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const action = async (work: () => Promise<void>) => {
    if (busy) return;
    setBusy(true); setError(null); setMessage(null);
    try { await work(); }
    catch (e) { setError(errorMessage(e)); }
    finally { setBusy(false); }
  };
  return <section aria-label="Automatic encrypted backups" className="border-b border-hairline py-3">
    <h3 className="text-[13px] text-neutral-100">Automatic encrypted backups</h3>
    <p className="mt-1 text-[11px] text-neutral-500">Every 15 minutes while Arca runs; keeps 30 recent copies plus daily copies for 30 days. Choose an external drive or a folder that is backed up to another device.</p>
    <p className="mt-2 break-all text-[12px] text-neutral-300">{status ? status.directory ?? "Off · Choose a folder to enable" : "Loading…"}</p>
    {status?.lastSuccessUnix && <p className="mt-1 text-[11px] text-neutral-400">Last successful backup: {new Date(status.lastSuccessUnix * 1000).toLocaleString()}</p>}
    {(error || statusError || status?.lastError) && <p role="alert" className="mt-1 text-[12px] text-amber-400">{error ?? statusError ?? status?.lastError}</p>}
    {message && <p role="status" className="mt-1 text-[12px] text-neutral-300">{message}</p>}
    <div className="mt-2 flex gap-3 text-[12px] text-accent">
      <button disabled={busy} onClick={() => void action(async () => {
        const directory = await api.pickBackupDirectory();
        if (!directory) return;
        await api.configureBackups(directory);
        await api.runBackupNow();
        setMessage("Backup saved and read back successfully.");
      })}>Choose folder…</button>
      {status?.directory && <>
        <button disabled={busy} onClick={() => void action(async () => {
          await api.runBackupNow(); setMessage("Backup saved and read back successfully.");
        })}>{busy ? "Working…" : "Back up now"}</button>
        <button disabled={busy} onClick={() => void action(async () => {
          await api.configureBackups(null); setMessage("Automatic backups disabled. Existing copies are kept.");
        })}>Turn off</button>
      </>}
    </div>
  </section>;
}
