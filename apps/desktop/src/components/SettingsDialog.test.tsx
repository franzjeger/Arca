import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { api, checkForUpdate, type Settings, type VaultStatus } from "../lib/api";
import { SettingsDialog } from "./SettingsDialog";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual,
    onSyncStatus: vi.fn().mockResolvedValue(() => {}),
    checkForUpdate: vi.fn(),
    api: { ...actual.api,
      getSettings: vi.fn(), setSettings: vi.fn(), enableQuickUnlock: vi.fn(),
      appInfo: vi.fn().mockResolvedValue({ version: "0.5.0", build: "test-build", platform: "linux" }),
      syncStatus: vi.fn().mockResolvedValue({ connected: false, pending: true, syncing: false }),
      backupStatus: vi.fn().mockResolvedValue({ directory: null, lastSuccessUnix: null, lastError: null }),
    },
  };
});
const original: Settings = { autoLockSecs: 300, lockOnBlur: false, clipboardClearSecs: 30,
  confirmAutofill: false, savePrompt: true, handlePasskeys: true, passkeyReprompt: false };
beforeEach(() => { vi.clearAllMocks(); vi.mocked(api.getSettings).mockResolvedValue(original); });
function show() { render(<SettingsDialog status={{ hasQuickUnlock: false } as VaultStatus}
  onClose={vi.fn()} onStatusChanged={vi.fn()} onToast={vi.fn()} />); }

it("keeps the persisted security setting visible if saving fails", async () => {
  vi.mocked(api.setSettings).mockRejectedValue({ code: "io", message: "Disk full" });
  show();
  const toggle = await screen.findByRole("switch", { name: "Lock when window loses focus" });
  await userEvent.click(toggle);
  expect(await screen.findByRole("alert")).toHaveTextContent("Disk full");
  expect(toggle).toHaveAttribute("aria-checked", "false");
});

it("prevents overlapping writes and applies changes only after persistence", async () => {
  let finish!: () => void;
  vi.mocked(api.setSettings).mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  show();
  const toggle = await screen.findByRole("switch", { name: "Lock when window loses focus" });
  await userEvent.click(toggle);
  expect(toggle).toBeDisabled();
  expect(toggle).toHaveAttribute("aria-checked", "false");
  await userEvent.click(toggle);
  expect(api.setSettings).toHaveBeenCalledTimes(1);
  await act(async () => finish());
  expect(toggle).toHaveAttribute("aria-checked", "true");
});

it("does not announce up to date after an update check fails", async () => {
  vi.mocked(checkForUpdate).mockRejectedValue(new Error("Offline"));
  show();
  await userEvent.click(await screen.findByRole("button", { name: "Check…" }));
  await waitFor(() => expect(checkForUpdate).toHaveBeenCalledOnce());
  expect(screen.queryByText("Arca is up to date.")).not.toBeInTheDocument();
});


it("keeps an unsuccessful Touch ID upgrade visible for retry", async () => {
  vi.mocked(api.appInfo).mockResolvedValue({ version: "0.5.0", build: "test", platform: "macos", vaultFormat: 5 });
  vi.mocked(api.enableQuickUnlock).mockRejectedValue(new Error("Touch ID cancelled"));
  const onStatusChanged = vi.fn();
  const onToast = vi.fn();
  render(<SettingsDialog status={{ hasQuickUnlock: true, quickUnlockProtected: false } as VaultStatus}
    onClose={vi.fn()} onStatusChanged={onStatusChanged} onToast={onToast} />);
  await userEvent.click(await screen.findByRole("button", { name: "Upgrade protection…" }));
  expect(onStatusChanged).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Upgrade protection…" })).toBeEnabled();
  expect(onToast).not.toHaveBeenCalledWith("Touch ID protection verified and enabled");
  vi.mocked(api.enableQuickUnlock).mockResolvedValue();
  await userEvent.click(screen.getByRole("button", { name: "Upgrade protection…" }));
  expect(onStatusChanged).toHaveBeenCalledOnce();
  expect(onToast).toHaveBeenCalledWith("Touch ID protection verified and enabled");
});

it("sets up a USB key after confirming the master password", async () => {
  vi.mocked(api.appInfo).mockResolvedValue({ version: "0.6.2", build: "test", platform: "linux", vaultFormat: 5 });
  // Enrollment re-confirms the master password; on Linux the hook asks for it.
  api.vaultStatus = vi.fn().mockResolvedValue({ exists: true, unlocked: true, hasQuickUnlock: false,
    quickUnlockAvailable: false, biometricAvailable: false, keyFile: null });
  api.keyfileCandidates = vi.fn().mockResolvedValue([
    { id: "3CCC-1EA9", label: "ESD-USB", device: "/dev/sda1", sizeBytes: 34359738368, mounted: false, hasKey: false },
  ]);
  api.keyfileEnroll = vi.fn().mockResolvedValue({ enrolled: true, present: true, volumeLabel: "ESD-USB",
    volumeId: "3CCC-1EA9", lockOnRemoval: true });
  const onStatusChanged = vi.fn();
  const onToast = vi.fn();
  render(<SettingsDialog status={{ hasQuickUnlock: false, keyFile: null } as VaultStatus}
    onClose={vi.fn()} onStatusChanged={onStatusChanged} onToast={onToast} />);

  await userEvent.click(await screen.findByRole("button", { name: "Set up…" }));
  // The only stick is preselected, so the user just confirms.
  const radio = await screen.findByRole("radio", { name: /ESD-USB/ });
  expect(radio).toBeChecked();
  await userEvent.click(screen.getByRole("button", { name: "Create key" }));

  const field = await screen.findByLabelText("Current master password");
  await userEvent.type(field, "correct horse");
  await userEvent.click(screen.getByRole("button", { name: /confirm/i }));

  await waitFor(() => expect(api.keyfileEnroll).toHaveBeenCalledWith("3CCC-1EA9", true, "correct horse"));
  expect(onStatusChanged).toHaveBeenCalledOnce();
  expect(onToast).toHaveBeenCalledWith("USB key ready on ESD-USB");
});

it("shows the enrolled key next to the keychain toggle, and removes it after confirmation", async () => {
  vi.mocked(api.appInfo).mockResolvedValue({ version: "0.6.2", build: "test", platform: "linux", vaultFormat: 5 });
  api.vaultStatus = vi.fn().mockResolvedValue({ exists: true, unlocked: true, hasQuickUnlock: false,
    quickUnlockAvailable: false, biometricAvailable: false });
  api.keyfileRevoke = vi.fn().mockResolvedValue(undefined);
  const onStatusChanged = vi.fn();
  render(<SettingsDialog status={{ hasQuickUnlock: false,
    keyFile: { enrolled: true, present: false, volumeLabel: "ESD-USB", volumeId: "3CCC-1EA9", lockOnRemoval: true } } as VaultStatus}
    onClose={vi.fn()} onStatusChanged={onStatusChanged} onToast={vi.fn()} />);

  expect(await screen.findByText(/ESD-USB · not plugged in/)).toBeInTheDocument();
  // The keychain / Touch ID path stays available alongside the key.
  expect(screen.getByRole("switch", { name: "Quick unlock (OS keychain)" })).toBeInTheDocument();
  expect(screen.getByRole("switch", { name: "Lock when the USB key is removed" })).toHaveAttribute("aria-checked", "true");

  await userEvent.click(screen.getByRole("button", { name: "Remove…" }));
  await userEvent.type(await screen.findByLabelText("Current master password"), "correct horse");
  await userEvent.click(screen.getByRole("button", { name: /confirm/i }));
  await waitFor(() => expect(api.keyfileRevoke).toHaveBeenCalledWith("correct horse"));
  expect(onStatusChanged).toHaveBeenCalledOnce();
});
