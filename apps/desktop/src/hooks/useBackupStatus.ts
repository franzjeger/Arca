import { useEffect, useState } from "react";
import { api, errorMessage, type BackupStatus } from "../lib/api";
import { subscribeBackupStatus } from "../lib/backupUpdates";

export function useBackupStatus() {
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    let alive = true;
    let revision = 0;
    let pending = false;
    const apply = (next: BackupStatus) => {
      setStatus(next); setError(null); setNow(Date.now());
    };
    const unsubscribe = subscribeBackupStatus((next) => {
      revision++;
      if (alive) apply(next);
    });
    const refresh = async () => {
      if (pending) return;
      pending = true;
      const observed = revision;
      try {
        const next = await api.backupStatus();
        if (alive && observed === revision) apply(next);
      } catch (cause) {
        if (alive && observed === revision) setError(errorMessage(cause));
      } finally { pending = false; }
    };
    void refresh();
    const timer = setInterval(() => { setNow(Date.now()); void refresh(); }, 30_000);
    window.addEventListener("focus", refresh);
    return () => {
      alive = false; unsubscribe(); clearInterval(timer);
      window.removeEventListener("focus", refresh);
    };
  }, []);
  return { status, error, now };
}
