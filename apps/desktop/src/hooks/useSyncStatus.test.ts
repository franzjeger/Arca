import { expect, it } from "vitest";
import { syncLabel } from "./useSyncStatus";
import type { SyncStatus } from "../lib/api";
const status: SyncStatus = { connected: true, account: null, pending: true, syncing: false,
  lastError: null, lastSyncUnix: 100 };
it("does not call pending or failed writes synced even when there is an old success time", () => {
  expect(syncLabel(status)).toContain("Waiting to sync");
  expect(syncLabel({ ...status, lastError: "Offline" })).toContain("needs attention");
  expect(syncLabel({ ...status, syncing: true })).toContain("Syncing");
  expect(syncLabel({ ...status, connected: false })).toContain("Sync off");
});
