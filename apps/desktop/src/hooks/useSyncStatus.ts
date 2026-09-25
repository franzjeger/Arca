import { useEffect, useState } from "react";
import { api, errorMessage, onSyncStatus, type SyncStatus } from "../lib/api";

export function useSyncStatus() {
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    let revision = 0;
    let unlisten: (() => void) | undefined;
    // Subscribe first so an update cannot fall between the query and listener.
    void onSyncStatus((next) => {
      if (alive) { revision++; setStatus(next); setError(null); }
    }).then(async (stop) => {
      if (!alive) { stop(); return; }
      unlisten = stop;
      const observed = revision;
      const next = await api.syncStatus();
      if (alive && revision === observed) setStatus(next);
    }).catch((cause) => { if (alive) setError(errorMessage(cause)); });
    return () => { alive = false; unlisten?.(); };
  }, []);
  return { status, setStatus, error };
}

export function syncLabel(status: SyncStatus | null): string {
  if (!status) return "Checking sync…";
  if (!status.connected) return "Saved locally · Sync off";
  if (status.syncing) return "Saved locally · Syncing…";
  if (status.lastError) return "Saved locally · Sync needs attention";
  if (status.pending) return "Saved locally · Waiting to sync";
  if (!status.lastSyncUnix) return "Saved locally · Waiting for first sync";
  return `Synced ${new Date(status.lastSyncUnix * 1000).toLocaleString()}`;
}
