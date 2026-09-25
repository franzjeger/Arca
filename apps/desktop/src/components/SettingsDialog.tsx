import { AutomaticBackupSettings } from "./AutomaticBackupSettings";
import { useReauthentication } from "../hooks/useReauthentication";
import { syncLabel, useSyncStatus } from "../hooks/useSyncStatus";
import { Dialog } from "./Dialog";
import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  api,
  checkForUpdate,
  errorMessage,
  installUpdate,
  type Settings,
  type AppInfo,
  type KeyFileVolume,
  type VaultStatus,
} from "../lib/api";
import { GearIcon } from "./icons";
import { ImportDialog } from "./ImportDialog";
import { RestoreDialog } from "./RestoreDialog";
import { BackupRestoreDialog } from "./BackupRestoreDialog";
import { toastError, type ToastMessage } from "../lib/toast";

const AUTO_LOCK_OPTIONS = [
  { label: "Never", value: 0 },
  { label: "1 minute", value: 60 },
  { label: "5 minutes", value: 300 },
  { label: "15 minutes", value: 900 },
  { label: "30 minutes", value: 1800 },
];

const CLIPBOARD_OPTIONS = [
  { label: "Never", value: 0 },
  { label: "15 seconds", value: 15 },
  { label: "30 seconds", value: 30 },
  { label: "60 seconds", value: 60 },
];

export function SettingsDialog({
  status,
  onClose,
  onStatusChanged,
  onToast,
}: {
  status: VaultStatus;
  onClose: () => void;
  onStatusChanged: () => void;
  onToast: (msg: ToastMessage) => void;
}) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [quickUnlock, setQuickUnlock] = useState(status.hasQuickUnlock);
  const [busy, setBusy] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);
  const settingWrite = useRef(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [info, setInfo] = useState<AppInfo | null>(null);
  useEffect(() => { void api.appInfo().then(setInfo).catch(() => {}); }, []);
  const [importOpen, setImportOpen] = useState(false);
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [backupRestoreOpen, setBackupRestoreOpen] = useState(false);
  // null = not checked yet / up to date; set once an update is actually offered.
  const [update, setUpdate] = useState<{ version: string } | null>(null);
  const [updateChecked, setUpdateChecked] = useState(false);

  useEffect(() => {
    api
      .getSettings()
      .then(setSettings)
      .catch((e) => onToast(toastError(errorMessage(e))));
  }, [onToast]);

  const apply = async (patch: Partial<Settings>) => {
    if (!settings || settingWrite.current) return;
    settingWrite.current = true;
    setSavingSettings(true);
    setSettingsError(null);
    const next = { ...settings, ...patch };
    try {
      await api.setSettings(next);
      setSettings(next);
    } catch (e) {
      setSettingsError(errorMessage(e));
    } finally {
      settingWrite.current = false;
      setSavingSettings(false);
    }
  };

  const [pwOpen, setPwOpen] = useState(false);
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const { status: sync, setStatus: setSync, error: syncError } = useSyncStatus();

  const connectSync = async () => {
    setBusy(true);
    try {
      const account = await api.syncConnect();
      onToast(`Connected to Google (${account})`);
      await api.syncNow();
      setSync(await api.syncStatus());
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };

  const disconnectSync = async () => {
    setBusy(true);
    try {
      await api.syncDisconnect();
      setSync(await api.syncStatus());
      onToast("Google sync disconnected");
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };

  const runSyncNow = async () => {
    setBusy(true);
    try {
      const merged = await api.syncNow();
      const current = await api.syncStatus();
      setSync(current);
      onToast(syncLabel(current));
      if (merged) onStatusChanged();
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };

  const reauthentication = useReauthentication();
  const changePassword = async () => {
    // Enter bypassed the button's disabled state: two biometric prompts and two
    // re-keys of the whole vault from one held key.
    if (busy) return;
    if (newPw.length < 8) {
      onToast("Use at least 8 characters");
      return;
    }
    if (newPw !== confirmPw) {
      onToast("Passwords don't match");
      return;
    }
    setBusy(true);
    try {
      const confirmed = await reauthentication.run("change your master password", (password) => api.changeMasterPassword(newPw, password));
      if (!confirmed) return;
      setNewPw("");
      setConfirmPw("");
      setPwOpen(false);
      onToast("Master password changed");
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };

  const toggleQuickUnlock = async () => {
    setBusy(true);
    try {
      if (quickUnlock) {
        await api.disableQuickUnlock();
        setQuickUnlock(false);
        onToast("Quick unlock disabled");
      } else {
        await api.enableQuickUnlock();
        setQuickUnlock(true);
        onToast("Quick unlock enabled");
      }
      onStatusChanged();
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };

  // USB key. Enrollment picks a removable volume; the backend does the
  // re-authentication, the file, the local wrap and (Linux) the mount.
  const keyFile = status.keyFile?.enrolled ? status.keyFile : null;
  const [keyPickerOpen, setKeyPickerOpen] = useState(false);
  const [keyVolumes, setKeyVolumes] = useState<KeyFileVolume[] | null>(null);
  const [keyVolume, setKeyVolume] = useState<string | null>(null);
  const [keyLockOnRemoval, setKeyLockOnRemoval] = useState(true);
  const loadKeyVolumes = async () => {
    setKeyVolumes(null);
    try {
      const found = await api.keyfileCandidates();
      setKeyVolumes(found);
      // One stick plugged in is the common case; do not make them click it.
      setKeyVolume((current) =>
        found.some((v) => v.id === current) ? current : found.length === 1 ? found[0].id : null,
      );
    } catch (e) {
      setKeyVolumes([]);
      onToast(toastError(errorMessage(e)));
    }
  };
  const openKeyPicker = () => {
    setKeyPickerOpen(true);
    void loadKeyVolumes();
  };
  const enrollKey = async () => {
    if (busy || !keyVolume) return;
    const chosen = keyVolumes?.find((v) => v.id === keyVolume);
    setBusy(true);
    try {
      const result = await reauthentication.run("set up a USB key that unlocks this vault", (password) =>
        api.keyfileEnroll(keyVolume, keyLockOnRemoval, password));
      if (!result) return;
      setKeyPickerOpen(false);
      onStatusChanged();
      const name = result.value.volumeLabel || chosen?.label || "the stick";
      onToast(chosen?.hasKey ? `Using the Arca key already on ${name}` : `USB key ready on ${name}`);
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };
  const revokeKey = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const result = await reauthentication.run("remove the USB key from this vault", (password) =>
        api.keyfileRevoke(password));
      if (!result) return;
      onStatusChanged();
      onToast("USB key removed");
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };
  const setKeyRemovalLock = async (value: boolean) => {
    setBusy(true);
    try {
      await api.keyfileConfigure(value);
      onStatusChanged();
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label="Settings" onClose={onClose} dismissible={!busy && !savingSettings}>
      {reauthentication.dialog}
      <div className="flex max-h-[85vh] w-full max-w-lg flex-col rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <GearIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            Settings
          </h2>
        </div>

        {!settings ? (
          <div className="px-5 py-10 text-center text-[13px] text-neutral-500">
            Loading…
          </div>
        ) : (
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-2">
          <fieldset disabled={savingSettings} className="min-w-0 border-0 p-0">
            {savingSettings && <p role="status" className="py-2 text-[12px] text-neutral-400">Saving settings…</p>}
            {settingsError && <p role="alert" className="py-2 text-[12px] text-red-400">{settingsError} Your previous settings are still active.</p>}
            {syncError && <p role="alert" className="py-2 text-[12px] text-amber-400">Sync status unavailable: {syncError}</p>}
            <SelectRow
              label="Auto-lock when idle"
              value={settings.autoLockSecs}
              options={AUTO_LOCK_OPTIONS}
              onChange={(v) => apply({ autoLockSecs: v })}
            />
            {/* The hint is the point. Turning this on and then finding browser
                autofill broken looks like a bug in autofill, and the error you
                get says "locked" without saying which setting locked it. */}
            <ToggleRow
              label="Lock when window loses focus"
              hint="Strictest option. Filling from the browser still works — Arca holds off locking for a minute after the browser asks it to unlock — but every fill after that minute needs you to unlock again."
              checked={settings.lockOnBlur}
              onChange={(v) => apply({ lockOnBlur: v })}
            />
            <SelectRow
              label="Clear clipboard after copy"
              value={settings.clipboardClearSecs}
              options={CLIPBOARD_OPTIONS}
              onChange={(v) => apply({ clipboardClearSecs: v })}
            />
            <ToggleRow
              label="Quick unlock (OS keychain)"
              hint="Unlock without your master password using the system keychain. The master password is never stored."
              checked={quickUnlock}
              disabled={busy}
              onChange={() => void toggleQuickUnlock()}
            />
            {!keyFile && (
              <Row
                label="Unlock with a USB key"
                hint="Arca puts a key file on a USB stick. While it is plugged in, the vault opens without your master password — for you, for browser autofill and for passkeys. Pull it out and the vault locks. One stick works on all your computers; the file is useless without them, and they are useless without it."
              >
                <button type="button" disabled={busy}
                  className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                  onClick={openKeyPicker}>
                  Set up…
                </button>
              </Row>
            )}
            {keyPickerOpen && !keyFile && (
              <div className="mb-3 rounded-xl border border-hairline bg-fill/5 p-3" role="group" aria-label="Choose a USB stick">
                <div className="mb-2 flex items-center justify-between">
                  <div className="text-[12px] text-neutral-300">Choose the USB stick to put the key on</div>
                  <button type="button" disabled={busy || keyVolumes === null}
                    className="text-[12px] text-accent hover:underline disabled:opacity-50"
                    onClick={() => void loadKeyVolumes()}>
                    Refresh
                  </button>
                </div>
                {keyVolumes === null ? (
                  <p className="py-2 text-[12px] text-neutral-500">Looking for USB drives…</p>
                ) : keyVolumes.length === 0 ? (
                  <p className="py-2 text-[12px] text-neutral-500">No USB stick found. Plug one in and press Refresh.</p>
                ) : (
                  <ul className="space-y-1">
                    {keyVolumes.map((v) => (
                      <li key={v.id}>
                        <label className="flex cursor-pointer items-center gap-2 rounded-lg px-2 py-1.5 text-[13px] text-neutral-100 hover:bg-fill/5">
                          <input type="radio" name="keyfile-volume" value={v.id}
                            checked={keyVolume === v.id}
                            onChange={() => setKeyVolume(v.id)} />
                          <span className="min-w-0 flex-1 truncate">{v.label}{v.hasKey ? " · has an Arca key" : ""}</span>
                          <span className="shrink-0 text-[11px] text-neutral-500">{formatSize(v.sizeBytes)} · {v.device}</span>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
                <label className="mt-2 flex items-center gap-2 text-[12px] text-neutral-300">
                  <input type="checkbox" checked={keyLockOnRemoval}
                    onChange={(e) => setKeyLockOnRemoval(e.target.checked)} />
                  Lock the vault when the key is removed
                </label>
                <div className="mt-3 flex justify-end gap-2">
                  <button type="button" disabled={busy}
                    className="rounded-lg px-3 py-1.5 text-[13px] text-neutral-300 hover:bg-fill/5 disabled:opacity-50"
                    onClick={() => setKeyPickerOpen(false)}>
                    Cancel
                  </button>
                  <button type="button" disabled={busy || !keyVolume}
                    className="rounded-lg bg-accent px-3 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
                    onClick={() => void enrollKey()}>
                    Create key
                  </button>
                </div>
              </div>
            )}
            {keyFile && (
              <>
                <Row
                  label="USB key"
                  hint={`${keyFile.volumeLabel} · ${keyFile.present ? "plugged in" : "not plugged in"}. Unlocks the vault without your master password while inserted. Removing only forgets it on this computer; the key file stays on the stick for your others.`}
                >
                  <button type="button" disabled={busy}
                    className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                    onClick={() => void revokeKey()}>
                    Remove…
                  </button>
                </Row>
                <ToggleRow
                  label="Lock when the USB key is removed"
                  hint="Pulling the stick out locks the vault at once. Turn off to keep it open until the idle timer."
                  checked={keyFile.lockOnRemoval}
                  disabled={busy}
                  onChange={(v) => void setKeyRemovalLock(v)}
                />
              </>
            )}
            {info?.platform === "macos" && quickUnlock && <Row
              label="Touch ID protection"
              hint={status.quickUnlockProtected
                ? "macOS protects the device key itself. Repair if Touch ID no longer unlocks this vault."
                : "Upgrade so macOS requires authentication before releasing the device key. Your master password still works."}
            >
              <button type="button" disabled={busy}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                onClick={async () => {
                  setBusy(true);
                  try {
                    await api.enableQuickUnlock();
                    onStatusChanged();
                    onToast("Touch ID protection verified and enabled");
                  } catch (e) { onToast(toastError(errorMessage(e))); }
                  finally { setBusy(false); }
                }}>
                {status.quickUnlockProtected ? "Repair Touch ID…" : "Upgrade protection…"}
              </button>
            </Row>}
            <Row
              label="Find & merge duplicates"
              hint="Combines logins that share the same site and username. The newest password wins, TOTP codes and notes are kept, and the extras go to the Trash (recoverable)."
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  setBusy(true);
                  api
                    .mergeDuplicates()
                    .then((n) => {
                      onToast(
                        n > 0
                          ? `Merged ${n} duplicate${n === 1 ? "" : "s"} (moved to Trash)`
                          : "No duplicates found",
                      );
                      if (n > 0) onStatusChanged();
                    })
                    .catch((e) => onToast(toastError(errorMessage(e))))
                    .finally(() => setBusy(false));
                }}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
              >
                Merge…
              </button>
            </Row>
            <Row
              label="Sync with Google Drive"
              hint={
                sync?.connected
                  ? `Connected as ${sync.account ?? "Google"}. The encrypted vault syncs to a hidden app folder in your Drive; Google only ever sees ciphertext.${
                      sync.lastSyncUnix
                        ? ` Last sync ${new Date(sync.lastSyncUnix * 1000).toLocaleTimeString()}.`
                        : ""
                    }${sync.lastError ? ` Last error: ${sync.lastError}` : ""}`
                  : "Keep all your devices in sync via your own Google account. Only the encrypted vault file is uploaded; Google can never read your passwords."
              }
            >
              {sync?.connected ? (
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void runSyncNow()}
                    className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                  >
                    Sync now
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void disconnectSync()}
                    className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-400 hover:bg-fill/5 disabled:opacity-50"
                  >
                    Disconnect
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void connectSync()}
                  className="rounded-lg bg-accent px-3 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
                >
                  Sign in with Google
                </button>
              )}
            </Row>
            <Row
              label="Change master password"
              hint="Requires your current master password or system verification. Quick unlock keeps working; other devices need the new password after the next sync/seed."
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => setPwOpen((v) => !v)}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
              >
                {pwOpen ? "Cancel" : "Change…"}
              </button>
            </Row>
            {pwOpen && (
              <div className="mb-2 flex flex-col gap-2 rounded-lg bg-fill/5 p-3 ring-1 ring-line/10">
                <input
                  type="password"
                  placeholder="New master password (min. 8 characters)"
                  value={newPw}
                  autoFocus
                  onChange={(e) => setNewPw(e.target.value)}
                  className="rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
                />
                <input
                  type="password"
                  placeholder="Repeat new master password"
                  value={confirmPw}
                  onChange={(e) => setConfirmPw(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && void changePassword()}
                  className="rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
                />
                <button
                  type="button"
                  disabled={busy || newPw.length === 0}
                  onClick={() => void changePassword()}
                  className="self-end rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
                >
                  Set new password
                </button>
              </div>
            )}
            <ToggleRow
              label="Handle passkeys in Arca"
              hint="Let Arca create and sign in with passkeys in the browser. Turn off to hand all passkey prompts back to the browser / platform (a clean escape if a site's background passkey probes get annoying)."
              checked={settings.handlePasskeys}
              onChange={(v) => apply({ handlePasskeys: v })}
            />
            <ToggleRow
              label="Ask for the master password on every passkey use"
              hint="Off: an unlocked vault plus one click in Arca (the account you pick) signs you in. On: every passkey sign-in and registration also asks for your master password."
              checked={settings.passkeyReprompt}
              onChange={(v) => apply({ passkeyReprompt: v })}
            />
            <ToggleRow
              label="Confirm before autofill"
              hint="Ask for an explicit Allow/Deny in this app before a password is filled into the browser. Off by default; autofill is already limited to the matching site while unlocked."
              checked={settings.confirmAutofill}
              onChange={(v) => apply({ confirmAutofill: v })}
            />
            <ToggleRow
              label="Offer to save new logins"
              hint="When you sign in on a site the vault doesn't know, offer to save it (or update a changed password). On by default."
              checked={settings.savePrompt}
              onChange={(v) => apply({ savePrompt: v })}
            />
            <Row
              label="Import passwords"
              hint="From Safari/Apple Passwords, Chrome, Brave, Edge, Firefox, or any CSV export. Safe to re-import: duplicates are skipped."
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => setImportOpen(true)}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
              >
                Import…
              </button>
            </Row>
            <Row
              label="Export passwords"
              hint="Writes every login to a plaintext CSV (re-importable). Requires your master password or system verification. Keep the file safe and delete it once you're done — anyone who reads it sees all your passwords."
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  setBusy(true);
                  reauthentication.run("export all passwords to a plaintext file", (password) => api.exportLoginsCsv(password))
                    .then((result) => {
                      if (result && result.value !== null) onToast(`Exported ${result.value} logins`);
                    })
                    .catch((e) => onToast(toastError(errorMessage(e))))
                    .finally(() => setBusy(false));
                }}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
              >
                Export…
              </button>
            </Row>
            <Row
              label="Encrypted backup"
              hint="Save the complete encrypted vault, or restore one after its master password has been verified. The current vault is snapshotted before a restore."
            >
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setBusy(true);
                    api
                      .exportVaultBackup()
                      .then((n) => {
                        if (n !== null)
                          onToast(
                            `Backup written (${Math.round(n / 1024)} KB)`,
                          );
                      })
                      .catch((e) => onToast(toastError(errorMessage(e))))
                      .finally(() => setBusy(false));
                  }}
                  className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                >
                  Back up…
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => setBackupRestoreOpen(true)}
                  className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                >
                  Restore…
                </button>
              </div>
            </Row>
            <AutomaticBackupSettings />
            <Row label="About Arca" hint={info ? `Version ${info.version} · ${info.platform}` : "Loading version…"}>
              <span className="text-[11px] text-neutral-400">{info?.build}</span>
            </Row>
            <Row
              label="Updates"
              hint={
                update
                  ? `Version ${update.version} is available. Installing restarts Arca, so the vault locks and any unsaved edit is lost.`
                  : updateChecked
                    ? "Arca is up to date."
                    : "Check whether a newer signed build is available. Nothing installs without your say-so."
              }
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  setBusy(true);
                  if (update) {
                    installUpdate().catch((e) => {
                      onToast(toastError(errorMessage(e)));
                      setBusy(false);
                    });
                    return; // on success the app relaunches
                  }
                  setUpdateChecked(false);
                  checkForUpdate()
                    .then((u) => {
                      setUpdate(u);
                      setUpdateChecked(true);
                      if (!u) onToast("Arca is up to date");
                    })
                    .catch((e) => onToast(toastError(errorMessage(e))))
                    .finally(() => setBusy(false));
                }}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
              >
                {update ? `Install ${update.version}` : "Check…"}
              </button>
            </Row>
            <Row
              label="Earlier versions"
              hint="Arca keeps the vault as it was before each save (the last few, plus one a day for a week). Roll back if something was deleted or a sync merge went wrong."
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => setRestoreOpen(true)}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
              >
                Restore…
              </button>
            </Row>
          </fieldset>
          </div>
        )}
        {restoreOpen && (
          <RestoreDialog
            onClose={() => setRestoreOpen(false)}
            onToast={onToast}
          />
        )}
        {backupRestoreOpen && (
          <BackupRestoreDialog
            syncConnected={sync?.connected ?? false}
            onClose={() => setBackupRestoreOpen(false)}
            onRestored={() => {
              setBackupRestoreOpen(false);
              onToast("Encrypted backup restored");
              onStatusChanged();
            }}
          />
        )}

        <div className="flex shrink-0 justify-end border-t border-hairline px-5 py-3">
          <button
            onClick={onClose}
            disabled={busy || savingSettings}
            className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90"
          >
            Done
          </button>
        </div>
      </div>

      {importOpen && (
        <ImportDialog
          onClose={() => setImportOpen(false)}
          onImported={onStatusChanged}
          onToast={onToast}
        />
      )}
    </Dialog>
  );
}

function formatSize(bytes: number): string {
  if (!bytes) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit++;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

function Row({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-hairline py-3 last:border-b-0">
      <div className="min-w-0">
        <div className="text-[13px] text-neutral-100">{label}</div>
        {hint && (
          <div className="mt-0.5 text-[11px] leading-snug text-neutral-500">
            {hint}
          </div>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function SelectRow({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: number;
  options: { label: string; value: number }[];
  onChange: (v: number) => void;
}) {
  return (
    <Row label={label}>
      <select
        aria-label={label}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="rounded-lg bg-fill/5 px-2.5 py-1.5 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="bg-panel">
            {o.label}
          </option>
        ))}
      </select>
    </Row>
  );
}

function ToggleRow({
  label,
  hint,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <Row label={label} hint={hint}>
      <button
        type="button"
        role="switch"
        aria-label={label}
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative h-6 w-10 rounded-full transition-colors disabled:opacity-50 ${
          checked ? "bg-accent" : "bg-fill/15"
        }`}
      >
        {/* left-0 anchors the knob: without it, WKWebView derives the static
            position from the button's centered content, so the knob renders
            right-of-center regardless of state. */}
        <span
          className={`absolute left-0 top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${
            checked ? "translate-x-[18px]" : "translate-x-0.5"
          }`}
        />
      </button>
    </Row>
  );
}
