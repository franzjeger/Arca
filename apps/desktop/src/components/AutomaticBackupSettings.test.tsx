import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { api, type BackupStatus } from "../lib/api";
import { AutomaticBackupSettings } from "./AutomaticBackupSettings";
import { VaultStatusBar } from "./VaultStatusBar";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("../hooks/useSyncStatus", () => ({
  useSyncStatus: () => ({ status: null, error: null }), syncLabel: () => "Sync off",
}));
vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { ...actual.api, backupStatus: vi.fn(), pickBackupDirectory: vi.fn() } };
});

it("updates settings and the main window immediately when backups are enabled or disabled", async () => {
  const off: BackupStatus = { directory: null, lastError: null, lastSuccessUnix: null, lastFile: null };
  const enabled = { ...off, directory: "/external" };
  const saved = { ...enabled, lastSuccessUnix: Math.floor(Date.now() / 1000) };
  vi.mocked(api.backupStatus).mockResolvedValue(off);
  vi.mocked(api.pickBackupDirectory).mockResolvedValue("/external");
  vi.mocked(invoke).mockImplementation(async (command, args) => {
    if (command === "configure_backups") return (args as { directory: string | null }).directory ? enabled : off;
    if (command === "run_backup_now") return saved;
    throw new Error(`Unexpected command: ${command}`);
  });
  await act(async () => { render(<><AutomaticBackupSettings /><VaultStatusBar onOpenSettings={vi.fn()} /></>); });
  expect(screen.getByText(/Automatic backups are off/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Choose folder…" }));
  expect(screen.getByText("/external")).toBeInTheDocument();
  expect(screen.getByText(/Backed up/)).toBeInTheDocument();
  expect(screen.queryByText(/Automatic backups are off/)).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Turn off" }));
  expect(screen.getByText(/Automatic backups are off/)).toBeInTheDocument();
  expect(screen.getByText("Off · Choose a folder to enable")).toBeInTheDocument();
});
