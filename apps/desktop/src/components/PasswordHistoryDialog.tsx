import { useEffect, useState } from "react";
import { api, errorMessage, type PasswordHistoryEntry } from "../lib/api";
import { Dialog } from "./Dialog";

export function PasswordHistoryDialog({ itemId, onClose, onRestored }: {
  itemId: string; onClose: () => void; onRestored: () => void;
}) {
  const [entries, setEntries] = useState<PasswordHistoryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    void api.passwordHistory(itemId).then((list) => {
      if (alive) setEntries(list);
    }).catch((e) => { if (alive) setError(errorMessage(e)); });
    return () => { alive = false; };
  }, [itemId]);
  return <Dialog label="Password history" onClose={onClose} dismissible={!busy}>
    <div className="w-full max-w-lg rounded-2xl border border-hairline bg-panel p-5 shadow-2xl">
      <h2 className="text-[15px] font-semibold text-neutral-100">Password history</h2>
      <p className="mt-2 text-[12px] text-neutral-400">The last 20 password changes made after updating Arca are kept encrypted. Restoring changes only the saved password in Arca; it does not change the password on the website or network.</p>
      {!entries && !error && <p role="status" className="mt-4 text-[13px]">Loading…</p>}
      {entries?.length === 0 && <p className="mt-4 text-[13px] text-neutral-300">No previous passwords yet.</p>}
      <ul className="my-4 max-h-[45vh] overflow-y-auto">
        {entries?.map((entry) => <li key={entry.id} className="flex items-center justify-between gap-4 border-b border-hairline py-3 text-[12px]">
          <span>Replaced {new Date(entry.replacedAt).toLocaleString()}</span>
          <div className="flex shrink-0 gap-3 text-accent">
            <button disabled={busy} onClick={async () => {
              setBusy(true); setError(null);
              try { await api.copyPasswordHistory(itemId, entry.id); setMessage("Previous password copied. Clipboard clearing follows your settings."); }
              catch (e) { setError(errorMessage(e)); }
              finally { setBusy(false); }
            }}>Copy</button>
            <button disabled={busy} onClick={() => setSelected(entry.id)}>Restore…</button>
          </div>
        </li>)}
      </ul>
      {selected && <div className="my-3 rounded-lg bg-fill/5 p-3 text-[12px]">
        <p>Restore this saved password? Your current password will be kept in history.</p>
        <div className="mt-2 flex gap-4 text-accent">
          <button disabled={busy} onClick={async () => {
            setBusy(true); setError(null);
            try { await api.restorePasswordHistory(itemId, selected); onRestored(); }
            catch (e) { setError(errorMessage(e)); setBusy(false); }
          }}>Restore saved password</button>
          <button disabled={busy} onClick={() => setSelected(null)}>Cancel</button>
        </div>
      </div>}
      {error && <p role="alert" className="my-2 text-[12px] text-red-400">{error}</p>}
      {message && <p role="status" className="my-2 text-[12px] text-neutral-300">{message}</p>}
      <div className="flex justify-end"><button disabled={busy} onClick={onClose} className="rounded-lg bg-accent px-4 py-2 text-[13px] text-white">Done</button></div>
    </div>
  </Dialog>;
}
