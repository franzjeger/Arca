import { useEffect, useRef, useState } from "react";
import { api, errorMessage, type ConflictComparison, type ConflictResolution, type ItemSummary } from "../lib/api";
import { Dialog } from "./Dialog";

export const isSyncConflict = (item: ItemSummary) => item.isSyncConflict ?? item.title.endsWith(" (sync conflict)");
const labels: Record<string, string> = {
  title: "Title", username: "Username", password: "Password", url: "Website", totp: "Authenticator secret",
  notes: "Notes", ssid: "Network name", security: "Wi-Fi security", hidden: "Hidden network", body: "Note contents",
  folder: "Folder", credential: "Cryptographic credential", deleted: "Entry status",
};

export function SyncConflictsDialog({ items, onClose, onResolved }: {
  items: ItemSummary[];
  onClose: () => void;
  onResolved: (action: ConflictResolution | "keepCopy") => Promise<void>;
}) {
  const copies = items.filter(isSyncConflict);
  const [copyId, setCopyId] = useState(copies[0]?.id ?? "");
  const copy = items.find((item) => item.id === copyId);
  const [originalId, setOriginalId] = useState(copy?.conflictOf ?? "");
  const [comparison, setComparison] = useState<ConflictComparison | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [revealed, setRevealed] = useState<Record<string, [string, string]>>({});
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const generation = useRef(0);
  const [error, setError] = useState<string | null>(null);
  const candidates = items.filter((item) => item.id !== copyId && item.kind === copy?.kind && (!copy?.conflictOf || item.id === copy.conflictOf));
  const reviewed = comparison && { originalId, copyId, originalRevision: comparison.originalRevision, copyRevision: comparison.copyRevision };

  useEffect(() => {
    const request = ++generation.current;
    setComparison(null); setSelected(new Set()); setRevealed({}); setError(null);
    if (!originalId || !copyId) { setLoading(false); return; }
    setLoading(true);
    api.compareSyncConflict(originalId, copyId)
      .then((value) => { if (generation.current === request) setComparison(value); })
      .catch((cause) => { if (generation.current === request) setError(errorMessage(cause)); })
      .finally(() => { if (generation.current === request) setLoading(false); });
    return () => { generation.current++; };
  }, [originalId, copyId, revision]);
  useEffect(() => {
    if (!Object.keys(revealed).length) return;
    const timer = setTimeout(() => setRevealed({}), 30_000);
    return () => clearTimeout(timer);
  }, [revealed]);

  async function resolve(action: ConflictResolution) {
    if (!reviewed || submitting.current) return;
    submitting.current = true; setBusy(true); setError(null); setRevealed({});
    try {
      await api.resolveSyncConflict(reviewed, action, [...selected]);
      await onResolved(action); onClose();
    } catch (cause) { setError(errorMessage(cause)); }
    finally { submitting.current = false; setBusy(false); }
  }

  return <Dialog label="Resolve sync conflicts" onClose={onClose} dismissible={!busy}>
    <div className="flex max-h-[85vh] w-full max-w-4xl flex-col rounded-2xl border border-hairline bg-panel shadow-2xl">
      <div className="space-y-2 border-b border-hairline px-5 py-4">
        <h2 className="text-[15px] font-semibold text-neutral-100">Resolve sync conflicts</h2>
        <p className="text-[12px] text-neutral-400">Compare changes from two devices. Choose which values to keep. Previous entries are kept in Trash when you replace or combine them.</p>
      </div>
      <div className="min-h-0 space-y-4 overflow-y-auto px-5 py-4">
        {!copies.length ? <p className="text-[13px] text-neutral-400">No unresolved conflicts.</p> : <>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-[12px] text-neutral-300">Conflict copy
              <select value={copyId} disabled={busy} onChange={(event) => {
                const next = items.find((item) => item.id === event.target.value);
                setCopyId(event.target.value); setOriginalId(next?.conflictOf ?? "");
              }} className="mt-1 w-full rounded-lg border border-hairline bg-panel px-3 py-2">
                {copies.map((item) => <option key={item.id} value={item.id}>{item.title} · {item.subtitle}{item.isDeleted ? " · In Trash" : ""}</option>)}
              </select>
            </label>
            <label className="text-[12px] text-neutral-300">Compare with
              <select value={originalId} disabled={busy} onChange={(event) => setOriginalId(event.target.value)} className="mt-1 w-full rounded-lg border border-hairline bg-panel px-3 py-2">
                <option value="">Choose the original entry…</option>
                {candidates.map((item) => <option key={item.id} value={item.id}>{item.title} · {item.subtitle}{item.isDeleted ? " · In Trash" : ""}</option>)}
              </select>
            </label>
          </div>
          {!copy?.conflictOf && <p className="text-[12px] text-neutral-400">This older conflict copy has no saved link to its original. Select the matching entry yourself before comparing.</p>}
          {copy && !candidates.length && <div className="space-y-2 text-[12px]">
            <p role="status" className="text-amber-400">The original entry is no longer available. You can keep this copy as a separate entry.</p>
            <button disabled={busy} className="rounded-lg border border-hairline px-3 py-2 text-neutral-200 disabled:opacity-50" onClick={async () => {
              if (submitting.current) return;
              submitting.current = true; setBusy(true); setError(null);
              try { await api.keepSyncConflictCopy(copyId); await onResolved("keepCopy"); onClose(); }
              catch (cause) { setError(errorMessage(cause)); }
              finally { submitting.current = false; setBusy(false); }
            }}>Keep this copy separately</button>
          </div>}
          {loading && <p role="status" className="text-[13px] text-neutral-400">Loading comparison…</p>}
          {comparison && <div className="overflow-x-auto"><table className="w-full table-fixed text-left text-[12px]">
            <thead><tr className="text-neutral-400"><th className="w-1/4 p-2">Field</th><th className="p-2">Original entry</th><th className="p-2">Conflict copy</th></tr></thead>
            <tbody>{comparison.fields.map((field) => <tr key={field.key} className={`border-t border-hairline ${field.different ? "bg-amber-500/5" : ""}`}>
              <th scope="row" className="p-2 align-top font-medium text-neutral-200">
                {labels[field.key] ?? field.key}
                <span className="mt-1 block text-[10px] font-normal text-neutral-500">{field.different ? "Different" : "Same"}</span>
                {field.revealable && <button type="button" disabled={busy} className="mt-1 text-accent hover:underline" onClick={async () => {
                  if (revealed[field.key]) { setRevealed((old) => { const next = { ...old }; delete next[field.key]; return next; }); return; }
                  if (!reviewed) return;
                  const request = generation.current;
                  try {
                    const value = await api.revealConflictField(reviewed, field.key);
                    if (request === generation.current) setRevealed((old) => ({ ...old, [field.key]: value }));
                  } catch (cause) { if (request === generation.current) setError(errorMessage(cause)); }
                }}>{revealed[field.key] ? "Hide values" : "Reveal values"}</button>}
              </th>
              {([false, true] as const).map((fromCopy, index) => <td key={String(fromCopy)} className="p-2 align-top">
                <label className="flex cursor-pointer items-start gap-2">
                  <input type="radio" name={`conflict-${field.key}`} aria-label={`${labels[field.key] ?? field.key}: ${fromCopy ? "conflict copy" : "original"}`}
                    checked={selected.has(field.key) === fromCopy} disabled={busy}
                    onChange={() => setSelected((old) => { const next = new Set(old); if (fromCopy) next.add(field.key); else next.delete(field.key); return next; })} />
                  <span className="max-h-36 overflow-auto whitespace-pre-wrap break-words text-neutral-300">{(revealed[field.key]?.[index] ?? (fromCopy ? field.copy : field.original)) || "Not set"}</span>
                </label>
              </td>)}
            </tr>)}</tbody>
          </table></div>}
        </>}
        {error && <p role="alert" className="text-[12px] text-red-400">{error}</p>}
      </div>
      <div className="flex flex-wrap justify-end gap-2 border-t border-hairline px-5 py-3 text-[12px]">
        <button disabled={busy} onClick={onClose} className="rounded-lg px-3 py-2 text-neutral-300">Close</button>
        <button disabled={busy || loading || !originalId} onClick={() => setRevision((n) => n + 1)} className="rounded-lg border border-hairline px-3 py-2 text-neutral-300 disabled:opacity-50">Refresh comparison</button>
        <button disabled={busy || !comparison} onClick={() => void resolve("keepBoth")} className="rounded-lg border border-hairline px-3 py-2 text-neutral-200 disabled:opacity-50">Keep both entries</button>
        <button disabled={busy || !comparison} onClick={() => void resolve("keepOriginal")} className="rounded-lg border border-hairline px-3 py-2 text-neutral-200 disabled:opacity-50">Keep original</button>
        <button disabled={busy || !comparison} onClick={() => void resolve("useCopy")} className="rounded-lg border border-hairline px-3 py-2 text-neutral-200 disabled:opacity-50">Use conflict copy</button>
        <button disabled={busy || !comparison} onClick={() => void resolve("merge")} className="rounded-lg bg-accent px-3 py-2 font-medium text-white disabled:opacity-50">{busy ? "Saving…" : "Save selected values"}</button>
      </div>
    </div>
  </Dialog>;
}
