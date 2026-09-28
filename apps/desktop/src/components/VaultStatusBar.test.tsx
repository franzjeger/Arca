import { act, render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, type BackupStatus, type SyncStatus } from "../lib/api";
import { VaultStatusBar } from "./VaultStatusBar";
const sync = vi.hoisted(() => ({ status: null as SyncStatus | null }));
vi.mock("../hooks/useSyncStatus", () => ({
  useSyncStatus: () => ({ status: sync.status, error: null }), syncLabel: () => "Sync off",
}));
vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { ...actual.api, backupStatus: vi.fn(), syncAdoptPassword: vi.fn() } };
});
const now = 2_000_000_000;
const healthy: BackupStatus = { directory: "/backups", lastSuccessUnix: now, lastError: null, lastFile: null };
beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(now * 1000); });
afterEach(() => { vi.useRealTimers(); vi.clearAllMocks(); sync.status = null; });
async function show(status: BackupStatus) {
  vi.mocked(api.backupStatus).mockResolvedValue(status);
  const onOpenSettings = vi.fn();
  await act(async () => { render(<VaultStatusBar onOpenSettings={onOpenSettings} />); });
  return onOpenSettings;
}
it("shows disabled backup even if an old success exists and opens settings", async () => {
  const open = await show({ ...healthy, directory: null });
  expect(screen.getByText(/Automatic backups are off/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Backup settings" }));
  expect(open).toHaveBeenCalledOnce();
});
it("distinguishes a configured backup that has never succeeded", async () => {
  await show({ ...healthy, lastSuccessUnix: null });
  expect(screen.getByText(/No successful backup yet/)).toBeInTheDocument();
});
it("ages a healthy backup and clears the warning after a successful backup", async () => {
  await show(healthy);
  expect(screen.getByText(/Backed up/)).toBeInTheDocument();
  await act(async () => { await vi.advanceTimersByTimeAsync(30 * 60 * 1000); });
  expect(screen.getByText(/Last backup is over 30 minutes old/)).toBeInTheDocument();
  vi.mocked(api.backupStatus).mockResolvedValue({ ...healthy, lastSuccessUnix: now + 1800 });
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
  expect(screen.queryByRole("button", { name: "Backup settings" })).not.toBeInTheDocument();
});
it("prioritizes errors and recovers after a failed status read", async () => {
  await show({ ...healthy, lastError: "Backup disk unavailable" });
  expect(screen.getByText(/Backup disk unavailable/)).toBeInTheDocument();
  vi.mocked(api.backupStatus).mockRejectedValue(new Error("IPC failed"));
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
  expect(screen.getByText(/Backup status unavailable/)).toBeInTheDocument();
  vi.mocked(api.backupStatus).mockResolvedValue(healthy);
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
  expect(screen.getByText(/Backed up/)).toBeInTheDocument();
});

it("applies configuration immediately and ignores an older in-flight status reply", async () => {
  const { publishBackupStatus } = await import("../lib/backupUpdates");
  let finish!: (status: BackupStatus) => void;
  vi.mocked(api.backupStatus).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  await act(async () => { render(<VaultStatusBar onOpenSettings={vi.fn()} />); });
  act(() => { publishBackupStatus(healthy); });
  expect(screen.getByText(/Backed up/)).toBeInTheDocument();
  await act(async () => { finish({ ...healthy, directory: null }); });
  expect(screen.queryByText(/Automatic backups are off/)).not.toBeInTheDocument();
  act(() => { publishBackupStatus({ ...healthy, directory: null }); });
  expect(screen.getByText(/Automatic backups are off/)).toBeInTheDocument();
});

it("asks for a master password changed on another device, once, and keeps a way back", async () => {
  vi.useRealTimers();
  vi.mocked(api.backupStatus).mockResolvedValue(healthy);
  sync.status = { pending: true, syncing: false, connected: true, account: null, lastSyncUnix: null, lastError: "changed elsewhere", needsPassword: true };
  const onToast = vi.fn();
  await act(async () => { render(<VaultStatusBar onOpenSettings={vi.fn()} onToast={onToast} />); });
  expect(screen.getByRole("dialog", { name: "Master password changed" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry sync" })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Not now" }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Enter new password" }));

  vi.mocked(api.syncAdoptPassword).mockRejectedValueOnce({ code: "invalid_credentials", message: "Incorrect password" });
  fireEvent.change(screen.getByPlaceholderText("New master password"), { target: { value: "old" } });
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  expect(await screen.findByText("That is not the new master password.")).toBeInTheDocument();

  vi.mocked(api.syncAdoptPassword).mockResolvedValueOnce({ quickUnlockLost: false });
  fireEvent.change(screen.getByPlaceholderText("New master password"), { target: { value: "new" } });
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  await waitFor(() => expect(onToast).toHaveBeenCalledWith("This device now uses the new master password."));
  expect(api.syncAdoptPassword).toHaveBeenLastCalledWith("new");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});
