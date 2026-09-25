import { publishBackupStatus } from "./backupUpdates";
// Typed bridge to the Rust backend. Every function here corresponds 1:1 to a
// `#[tauri::command]` in src-tauri. Tauri converts camelCase JS argument keys
// to snake_case Rust parameter names automatically.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  open as openDialog,
  save as saveDialog,
} from "@tauri-apps/plugin-dialog";

// ---- types (mirror the Rust DTOs, which serialize camelCase) --------------

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  hasQuickUnlock: boolean;
  quickUnlockAvailable: boolean;
  biometricAvailable: boolean;
  quickUnlockProtected?: boolean;
  /** A USB key file is enrolled for this vault. Absent/null otherwise. */
  keyFile?: KeyFileStatus | null;
}

export interface KeyFileStatus {
  enrolled: boolean;
  /** The enrolled USB stick is plugged in right now. */
  present: boolean;
  volumeLabel: string;
  volumeId: string;
  lockOnRemoval: boolean;
}

/** A removable volume offered at enrollment. */
export interface KeyFileVolume {
  id: string;
  label: string;
  device: string;
  sizeBytes: number;
  mounted: boolean;
  /** The stick already carries an Arca key file (from another computer). */
  hasKey: boolean;
}

export type ItemKind =
  | "login"
  | "passkey"
  | "sshKey"
  | "wifi"
  | "secureNote"
  | "bookmark"
  // An entry written by a NEWER build of Arca than this one. Its contents are
  // kept byte-for-byte and handed back untouched when this build saves, but
  // nothing here can read them. Shown rather than hidden: an entry the user
  // cannot see is an entry they believe they lost.
  | "unknown";

export interface SyncStatus {
  pending: boolean;
  syncing: boolean;
  connected: boolean;
  account: string | null;
  lastSyncUnix: number | null;
  lastError: string | null;
}

export interface AppInfo {
  version: string;
  build: string;
  platform: string;
  vaultFormat: number;
}

export interface BackupStatus {
  directory: string | null;
  lastSuccessUnix: number | null;
  lastError: string | null;
  lastFile: string | null;
}

export interface PasswordHistoryEntry {
  id: string;
  replacedAt: number;
}

export interface ItemSummary {
  isSyncConflict?: boolean;
  conflictOf?: string | null;
  id: string;
  kind: ItemKind;
  title: string;
  subtitle: string;
  letter: string;
  /** Normalized website host ("github.com"; empty when no URL). */
  host: string;
  /** Bookmark folder path, `/`-separated. Empty for other item types. */
  folder: string;
  hasTotp: boolean;
  isDeleted: boolean;
  modifiedAt: number;
}

export interface ConflictField {
  key: string;
  original: string;
  copy: string;
  different: boolean;
  secret: boolean;
  revealable: boolean;
}
export interface ConflictComparison {
  originalRevision: string;
  copyRevision: string;
  fields: ConflictField[];
}
export interface ReviewedConflict {
  originalId: string;
  copyId: string;
  originalRevision: string;
  copyRevision: string;
}
export type ConflictResolution = "keepOriginal" | "useCopy" | "merge" | "keepBoth";

export interface ItemDetail {
  id: string;
  kind: ItemKind;
  title: string;
  username: string;
  url: string;
  notes: string;
  hasPassword: boolean;
  hasTotp: boolean;
  passwordStrength: PasswordStrength | null;
  isDeleted: boolean;
  createdAt: number;
  modifiedAt: number;
  /** Wi-Fi only (empty/false for other kinds). */
  ssid: string;
  security: string;
  hidden: boolean;
  /** Bookmark only: folder path, `/`-separated. Empty means the top of the bar. */
  folder: string;
}

/** A browser profile Arca can read bookmarks from. */
export interface BookmarkSource {
  label: string;
  path: string;
  count: number;
}

export interface WifiInput {
  id: string | null;
  title: string;
  ssid: string;
  password: string;
  /** "WPA" | "WEP" | "nopass". */
  security: string;
  hidden: boolean;
  notes: string;
}

export interface SecureNoteInput {
  id: string | null;
  title: string;
  body: string;
}

export interface BookmarkInput {
  id: string | null;
  title: string;
  url: string;
  folder: string;
  notes: string;
}

export interface SshPublicKey {
  authorizedKey: string;
  fingerprint: string;
  comment: string;
}

export interface SshAgentInfo {
  socket: string;
  available: boolean;
}

export type PasswordStrength = "weak" | "fair" | "strong";

export type SecurityTag = "weak" | "reused" | "breached";

export interface BreachHit {
  id: string;
  count: number;
}

/**
 * Outcome of a breach check. `unchecked` counts logins whose range request
 * failed — they are NOT known to be clean, so the UI must not imply an
 * all-clear when it is non-zero.
 */
export interface BreachReport {
  hits: BreachHit[];
  checked: number;
  unchecked: number;
}

export interface SecurityIssue {
  id: string;
  issues: SecurityTag[];
}

export interface ImportSummary {
  imported: number;
  /** Existing logins whose password changed and was updated in place. */
  updated: number;
  /** Rows identical to an existing login, skipped (safe to re-import). */
  duplicates: number;
  skipped: number;
}

export interface Totp {
  code: string;
  period: number;
  remaining: number;
}

export interface Settings {
  autoLockSecs: number;
  lockOnBlur: boolean;
  clipboardClearSecs: number;
  confirmAutofill: boolean;
  savePrompt: boolean;
  handlePasskeys: boolean;
  /** Ask for the master password on every passkey use (stricter than the
   *  default of "unlocked vault + one click"). */
  passkeyReprompt: boolean;
}

/** Payload of a `fill-consent-request` event: what the app is asking to fill. */
export interface FillConsent {
  id: string;
  site: string;
  account: string;
  title: string;
}

/** Payload of a `passkey-verify-request` event: the site (rp_id) whose passkey
 *  ceremony needs the master password to satisfy user verification. */
export interface PasskeyVerifyRequest {
  id: string;
  site: string;
  /** True when the ceremony registers a NEW passkey (vs signing in). */
  isCreate: boolean;
  /** The bridge wants the master password, not just a click. Absent in
   *  events from older builds, which always wanted the password. */
  requirePassword?: boolean;
}

export interface LoginInput {
  id: string | null;
  title: string;
  username: string;
  password: string;
  url: string;
  totpSecret: string | null;
  notes: string;
}

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

/** One rotated local snapshot of the encrypted vault file. */
export interface SnapshotSummary {
  /** Absolute path; pass back verbatim to `restoreSnapshot`. */
  path: string;
  /** Unix SECONDS (not millis) the snapshot was taken. */
  createdUnix: number;
  bytes: number;
}

/** Error shape the backend returns (`CmdError`). */
export interface ApiError {
  code: string;
  message: string;
}

export function isApiError(e: unknown): e is ApiError {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

export function errorMessage(e: unknown): string {
  if (isApiError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

/** An available update, from `checkForUpdate`. */
export interface UpdateInfo {
  version: string;
  notes: string;
}

/**
 * Ask the update endpoint whether a newer signed build exists. Returns null
 * when up to date. Errors propagate so offline never looks like up to date.
 */
export async function checkForUpdate(): Promise<UpdateInfo | null> {
  const { check } = await import("@tauri-apps/plugin-updater");
  const update = await check();
  if (!update) return null;
  return { version: update.version, notes: update.body ?? "" };
}

/**
 * Download, install, and relaunch into the new version.
 *
 * This RESTARTS the app, so the vault locks and any unsaved edit is lost. Only
 * call it from an explicit user action that says so.
 */
export async function installUpdate(): Promise<void> {
  const { check } = await import("@tauri-apps/plugin-updater");
  const { relaunch } = await import("@tauri-apps/plugin-process");
  const update = await check();
  if (!update) throw new Error("No update is available any more.");
  await update.downloadAndInstall();
  await relaunch();
}

/** True when running inside the Tauri webview (vs. a plain browser). */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

// ---- commands -------------------------------------------------------------

export const api = {
  resolvePasskeyChoice: (id: string, itemId: string | null) => invoke<void>("resolve_passkey_choice", { id, itemId }),
  appInfo: () => invoke<AppInfo>("app_info"),
  passwordHistory: (id: string) => invoke<PasswordHistoryEntry[]>("password_history", { id }),
  copyPasswordHistory: (id: string, revision: string) => invoke<void>("copy_password_history", { id, revision }),
  restorePasswordHistory: (id: string, revision: string) => invoke<void>("restore_password_history", { id, revision }),
  backupStatus: () => invoke<BackupStatus>("backup_status"),
  configureBackups: (directory: string | null) => invoke<BackupStatus>("configure_backups", { directory }).then(publishBackupStatus),
  runBackupNow: () => invoke<BackupStatus>("run_backup_now").then(publishBackupStatus),
  verifyVaultBackup: (path: string, masterPassword: string) => invoke<void>("verify_vault_backup", { path, masterPassword }),
  pickBackupDirectory: async (): Promise<string | null> => {
    await invoke<void>("set_blur_lock_suppressed", { suppressed: true });
    try {
      const path = await openDialog({ directory: true, multiple: false });
      return typeof path === "string" ? path : null;
    } finally {
      await invoke<void>("set_blur_lock_suppressed", { suppressed: false });
    }
  },
  vaultStatus: () => invoke<VaultStatus>("vault_status"),
  compareSyncConflict: (originalId: string, copyId: string) => invoke<ConflictComparison>("compare_sync_conflict", { originalId, copyId }),
  revealConflictField: (reviewed: ReviewedConflict, field: string) => invoke<[string, string]>("reveal_conflict_field", { reviewed, field }),
  resolveSyncConflict: (reviewed: ReviewedConflict, action: ConflictResolution, fields: string[] = []) => invoke<void>("resolve_sync_conflict", { reviewed, action, fields }),
  keepSyncConflictCopy: (copyId: string) => invoke<void>("keep_sync_conflict_copy", { copyId }),

  createVault: (masterPassword: string) =>
    invoke<void>("create_vault", { masterPassword }),

  unlock: (masterPassword: string) =>
    invoke<void>("unlock", { masterPassword }),
  quickUnlock: () => invoke<void>("quick_unlock"),
  enableQuickUnlock: () => invoke<void>("enable_quick_unlock"),
  disableQuickUnlock: () => invoke<void>("disable_quick_unlock"),
  // USB key file. Enroll/revoke re-confirm the master password; the backend
  // enforces that, the hook only supplies it.
  keyfileCandidates: () => invoke<KeyFileVolume[]>("keyfile_candidates"),
  keyfileEnroll: (volumeId: string, lockOnRemoval: boolean, currentPassword?: string) =>
    invoke<KeyFileStatus>("keyfile_enroll", { volumeId, lockOnRemoval, currentPassword }),
  keyfileRevoke: (currentPassword?: string) =>
    invoke<void>("keyfile_revoke", { currentPassword }),
  keyfileConfigure: (lockOnRemoval: boolean) =>
    invoke<KeyFileStatus>("keyfile_configure", { lockOnRemoval }),
  keyfileUnlock: () => invoke<void>("keyfile_unlock"),
  changeMasterPassword: (newPassword: string, currentPassword?: string) =>
    invoke<void>("change_master_password", { newPassword, currentPassword }),
  syncConnect: () => invoke<string>("sync_connect"),
  syncDisconnect: () => invoke<void>("sync_disconnect"),
  syncStatus: () => invoke<SyncStatus>("sync_status"),
  syncNow: () => invoke<boolean>("sync_now"),
  /** First-run restore: adopt the vault in the signed-in Google account. */
  syncBootstrap: (masterPassword: string) =>
    invoke<void>("sync_bootstrap", { masterPassword }),
  mergeDuplicates: () => invoke<number>("merge_duplicates"),
  lock: () => invoke<void>("lock"),
  touch: () => invoke<void>("touch"),

  listItems: (includeDeleted: boolean) =>
    invoke<ItemSummary[]>("list_items", { includeDeleted }),
  /** Search happens against decrypted fields in Rust; only matching ids cross. */
  searchItems: (query: string, includeDeleted: boolean) =>
    invoke<string[]>("search_items", { query, includeDeleted }),
  getItem: (id: string) => invoke<ItemDetail>("get_item", { id }),

  revealField: (id: string, field: "password" | "totp_secret" | "notes") =>
    invoke<string>("reveal_field", { id, field }),
  copyField: (id: string, field: "password" | "totp_secret" | "notes") =>
    invoke<void>("copy_field", { id, field }),
  copyToClipboard: (text: string) =>
    invoke<void>("copy_to_clipboard", { text }),

  upsertItem: (input: LoginInput) => invoke<string>("upsert_item", { input }),
  upsertWifi: (input: WifiInput) => invoke<string>("upsert_wifi", { input }),
  upsertSecureNote: (input: SecureNoteInput) =>
    invoke<string>("upsert_secure_note", { input }),
  upsertBookmark: (input: BookmarkInput) =>
    invoke<string>("upsert_bookmark", { input }),
  moveBookmarks: (ids: string[], folder: string) =>
    invoke<number>("move_bookmarks", { ids, folder }),
  /** SVG string of a "join this network" QR code (passphrase encoded in Rust,
   *  never crossing to the webview as readable text). */
  wifiQr: (id: string) => invoke<string>("wifi_qr", { id }),
  generateSshKey: (comment: string) =>
    invoke<string>("generate_ssh_key", { comment }),
  sshPublicKey: (id: string) => invoke<SshPublicKey>("ssh_public_key", { id }),
  sshAgentInfo: () => invoke<SshAgentInfo>("ssh_agent_info"),
  deleteItem: (id: string) => invoke<void>("delete_item", { id }),
  // Empty on macOS unless Arca has Full Disk Access — reading another app's
  // Application Support directory is refused there. Linux and Windows have no
  // such wall.
  bookmarkSources: () => invoke<BookmarkSource[]>("list_bookmark_sources"),
  /** Returns how many were ADDED; re-importing the same profile adds nothing. */
  importBookmarks: (path: string) =>
    invoke<number>("import_bookmarks", { path }),
  restoreItem: (id: string) => invoke<void>("restore_item", { id }),
  purgeItem: (id: string) => invoke<void>("purge_item", { id }),

  currentTotp: (id: string) => invoke<Totp>("current_totp", { id }),
  securityReport: () => invoke<SecurityIssue[]>("security_report"),
  checkBreaches: () => invoke<BreachReport>("check_breaches"),
  generate: (options: PasswordOptions) =>
    invoke<string>("generate", { options }),

  importLogins: (path: string) =>
    invoke<ImportSummary>("import_logins", { path }),
  openPasswordsApp: () => invoke<void>("open_passwords_app"),

  getSettings: () => invoke<Settings>("get_settings"),
  setSettings: (settings: Settings) =>
    invoke<void>("set_settings", { settings }),

  resolveAutofillConsent: (id: string, approved: boolean) =>
    invoke<void>("resolve_autofill_consent", { id, approved }),

  /** Verify the master password to approve a pending passkey ceremony
   *  (Windows/Linux). Resolves to `true` if the password was correct (and the
   *  ceremony is approved); `false` lets the dialog show a retry hint. */
  verifyPasskeyApproval: (id: string, masterPassword: string) =>
    invoke<boolean>("verify_passkey_approval", { id, masterPassword }),

  /** Cancel a pending passkey verification (user dismissed the dialog). Uses a
   *  dedicated command — NOT resolveAutofillConsent — so the passkey UV channel
   *  is never touched by the presence-only consent path. */
  /** One-click approval; the backend refuses it for password-required prompts. */
  confirmPasskeyApproval: (id: string) =>
    invoke<boolean>("confirm_passkey_approval", { id }),
  cancelPasskeyVerification: (id: string) =>
    invoke<void>("cancel_passkey_verification", { id }),

  openExternal: (url: string) => openUrl(url),

  /**
   * Open a native file picker for a CSV and import it. The file is read in Rust,
   * so exported plaintext passwords never enter the webview. Returns `null` if
   * the user cancels the picker.
   *
   * The picker blurs the main window, which would otherwise trigger
   * lock-on-blur and lock the vault mid-import; we suppress that around the
   * dialog.
   */
  pickAndImportCsv: async (): Promise<ImportSummary | null> => {
    await invoke<void>("set_blur_lock_suppressed", { suppressed: true });
    try {
      const path = await openDialog({
        multiple: false,
        directory: false,
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
      if (typeof path !== "string") return null;
      return await invoke<ImportSummary>("import_logins", { path });
    } finally {
      await invoke<void>("set_blur_lock_suppressed", { suppressed: false });
    }
  },

  /**
   * Native "save as" dialog, then export all logins to a CSV (written in Rust,
   * gated behind a biometric re-auth). Returns the row count, or `null` if the
   * user cancels the dialog. Blur-lock is suppressed around the dialog.
   */
  exportLoginsCsv: async (currentPassword?: string): Promise<number | null> => {
    await invoke<void>("set_blur_lock_suppressed", { suppressed: true });
    try {
      const path = await saveDialog({
        defaultPath: "arca-passwords.csv",
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
      if (typeof path !== "string") return null;
      return await invoke<number>("export_logins_csv", { path, currentPassword });
    } finally {
      await invoke<void>("set_blur_lock_suppressed", { suppressed: false });
    }
  },

  // ---- backup & restore ----------------------------------------------------

  /** Local snapshots of the encrypted vault, newest first (metadata only). */
  listSnapshots: () => invoke<SnapshotSummary[]>("list_snapshots"),

  /**
   * Roll the vault back to a snapshot (biometric-gated). The current state is
   * snapshotted first, so this is undoable. The app ends up LOCKED: a snapshot
   * can predate a master-password change, so it must be unlocked with whatever
   * password it was written with.
   */
  restoreSnapshot: (path: string, currentPassword?: string) => invoke<void>("restore_snapshot", { path, currentPassword }),

  /**
   * Native "save as", then copy the ENCRYPTED vault there as an off-device
   * backup. Returns bytes written, or `null` if the user cancels. Needs no
   * biometric gate: the copy is ciphertext, useless without the master password.
   */
  exportVaultBackup: async (): Promise<number | null> => {
    await invoke<void>("set_blur_lock_suppressed", { suppressed: true });
    try {
      const path = await saveDialog({
        defaultPath: "arca-backup.vault",
        filters: [{ name: "Arca vault", extensions: ["vault"] }],
      });
      if (typeof path !== "string") return null;
      return await invoke<number>("export_vault_backup", { path });
    } finally {
      await invoke<void>("set_blur_lock_suppressed", { suppressed: false });
    }
  },

  /** Pick an encrypted Arca vault without reading its bytes into the webview. */
  pickVaultBackup: async (): Promise<string | null> => {
    await invoke<void>("set_blur_lock_suppressed", { suppressed: true });
    try {
      const path = await openDialog({
        multiple: false,
        directory: false,
        filters: [{ name: "Arca vault", extensions: ["vault"] }],
      });
      return typeof path === "string" ? path : null;
    } finally {
      await invoke<void>("set_blur_lock_suppressed", { suppressed: false });
    }
  },

  /** Verify with the backup's master password, snapshot current state, restore. */
  restoreVaultBackup: (path: string, masterPassword: string, currentPassword?: string) =>
    invoke<void>("restore_vault_backup", { path, masterPassword, currentPassword }),
};

// ---- events ---------------------------------------------------------------

/**
 * Fired when the browser extension asked Arca to unlock — the user clicked a
 * locked field's badge, so a Touch ID prompt is the answer rather than an
 * interruption. This is the one signal that re-enables the automatic prompt
 * after an automatic lock has suppressed it.
 */
export function onUnlockRequested(cb: () => void): Promise<UnlistenFn> {
  return listen("unlock-requested", () => cb());
}

/**
 * Fired when the vault was unlocked WITHOUT the window being involved — the
 * browser extension asked, the OS prompt answered, and the app never came
 * forward. The window may be sitting on its lock screen at that moment, so it
 * has to be told rather than left claiming to be locked.
 */
export function onVaultUnlocked(cb: () => void): Promise<UnlistenFn> {
  return listen("vault-unlocked", () => cb());
}

/**
 * Fired after the app publishes its logins and passkeys to the OS AutoFill
 * store. Worth surfacing because the store ACCEPTS a publish while AutoFill is
 * switched off for Arca and silently discards it — so without this, "nothing
 * shows up in Safari" and "everything published fine" look identical.
 */
export function onAutoFillPublished(
  cb: (info: { count: number; ok: boolean; message: string }) => void,
): Promise<UnlistenFn> {
  return listen<{ count: number; ok: boolean; message: string }>(
    "autofill-published",
    (e) => cb(e.payload),
  );
}

/** Fired by the backend when the vault auto-locks (idle or window blur). */
export function onVaultLocked(
  cb: (reason: string) => void,
): Promise<UnlistenFn> {
  return listen<string>("vault-locked", (e) => cb(e.payload));
}

/**
 * Progress of a running breach check: one step per DISTINCT hash prefix
 * fetched, not per login, so `total` is usually well below the login count.
 */
export function onBreachProgress(
  cb: (done: number, total: number) => void,
): Promise<UnlistenFn> {
  return listen<[number, number]>("breach-progress", (e) =>
    cb(e.payload[0], e.payload[1]),
  );
}

/** Fired after a copied secret is auto-cleared from the clipboard. */
export function onClipboardCleared(cb: () => void): Promise<UnlistenFn> {
  return listen("clipboard-cleared", () => cb());
}

/** Fired after a credential is autofilled into the browser (for visibility). */
export function onAutofilled(cb: (what: string) => void): Promise<UnlistenFn> {
  return listen<string>("autofilled", (e) => cb(e.payload));
}

/** Fired when repeated declines have muted a site's passkey prompts for the
 *  rest of the session. Worth surfacing: going quiet without saying so would
 *  look like a bug the next time the user genuinely tried to sign in. */
export function onPasskeySuppressed(
  cb: (site: string, isCreate: boolean) => void,
): Promise<UnlistenFn> {
  return listen<{ site: string; is_create: boolean }>(
    "passkey-suppressed",
    (e) => cb(e.payload.site, e.payload.is_create),
  );
}

/** Fired when a site tried to register a passkey Arca already holds for that
 *  account, so the ceremony was refused without a prompt. Worth surfacing: the
 *  page shows "you already have a passkey", which is wrong whenever the site
 *  itself lost the credential — and the only way out is to delete Arca's copy
 *  first, which nothing else tells the user. */
export function onPasskeyRegistrationBlocked(
  cb: (site: string) => void,
): Promise<UnlistenFn> {
  return listen<string>("passkey-registration-blocked", (e) => cb(e.payload));
}

/** Fired when a login is saved/updated from the browser (save-on-submit), so
 *  the UI can refresh its item list. */
export function onLoginSaved(cb: (host: string) => void): Promise<UnlistenFn> {
  return listen<string>("login-saved", (e) => cb(e.payload));
}

/** Fired when a passkey is registered ("created") or used to sign in ("used")
 *  via the browser bridge, so the UI can refresh its item list. */
/** Fired when a background sync merged in changes from another device. */
export function onSyncMerged(cb: () => void): Promise<UnlistenFn> {
  return listen("sync-merged", () => cb());
}

export function onPasskeyChanged(
  cb: (rp: string, kind: "created" | "used") => void,
): Promise<UnlistenFn> {
  const created = listen<string>("passkey-created", (e) =>
    cb(e.payload, "created"),
  );
  const used = listen<string>("passkey-used", (e) => cb(e.payload, "used"));
  return Promise.all([created, used]).then(
    (unls) => () => unls.forEach((u) => u()),
  );
}

/**
 * Fired when a fill needs the user's explicit approval (confirm-autofill on).
 * Answer with `api.resolveAutofillConsent(id, approved)`.
 */
export function onFillConsentRequest(
  cb: (req: FillConsent) => void,
): Promise<UnlistenFn> {
  return listen<FillConsent>("fill-consent-request", (e) => cb(e.payload));
}

/**
 * Fired (Windows/Linux) when a passkey ceremony needs user verification. Show a
 * master-password prompt and answer with `api.verifyPasskeyApproval(id, pw)`;
 * cancel with `api.cancelPasskeyVerification(id)`.
 */
export function onPasskeyVerifyRequest(
  cb: (req: PasskeyVerifyRequest) => void,
): Promise<UnlistenFn> {
  return listen<PasskeyVerifyRequest>("passkey-verify-request", (e) =>
    cb(e.payload),
  );
}

export function onSyncStatus(cb: (status: SyncStatus) => void): Promise<UnlistenFn> {
  return listen<SyncStatus>("sync-status", (event) => cb(event.payload));
}

export interface PasskeyChoiceRequest {
  id: string;
  site: string;
  accounts: { id: string; account: string; title: string }[];
}
export function onPasskeyChoiceRequest(cb: (req: PasskeyChoiceRequest) => void): Promise<UnlistenFn> {
  return listen<PasskeyChoiceRequest>("passkey-choice-request", e => cb(e.payload));
}
export function onPasskeyChoiceClosed(cb: (id: string) => void): Promise<UnlistenFn> {
  return listen<string>("passkey-choice-closed", e => cb(e.payload));
}
