import type { BackupStatus } from "./api";

// Configuration commands and all visible backup consumers share these updates.
// No status cache: a newly mounted view still reads the persisted backend state.
const listeners = new Set<(status: BackupStatus) => void>();
export function publishBackupStatus(status: BackupStatus): BackupStatus {
  listeners.forEach((listener) => listener(status));
  return status;
}
export function subscribeBackupStatus(listener: (status: BackupStatus) => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}
