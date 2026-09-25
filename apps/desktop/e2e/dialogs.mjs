// Real Chromium keyboard behavior against the application with synthetic IPC.
// No real vault, keychain, Google account or personal browser profile is used.
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { chromium } from 'playwright';
import { createServer } from 'vite';

const server = await createServer({ server: { host: '127.0.0.1', port: 4175, strictPort: true } });
await server.listen();
let browser;
try {
  const executablePath = process.env.CHROME_BIN || ['/usr/bin/chromium', '/usr/bin/google-chrome'].find(existsSync);
  browser = await chromium.launch({ executablePath, headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1000, height: 760 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route(/\/src\/lib\/api\.ts$/, route => route.fulfill({
    contentType: 'application/javascript', body: `
      export * from '/src/lib/api.ts?real';
      const listeners = new Set();
      window.testSync = { connected: true, account: 'test@example.test', pending: true, syncing: false, lastError: null, lastSyncUnix: null };
      window.emitSync = value => { window.testSync = value; listeners.forEach(cb => cb(value)); };
      export const isTauri = () => true;
      export const onSyncStatus = async cb => { listeners.add(cb); return () => listeners.delete(cb); };
      export const onVaultLocked = async () => () => {};
      export const onVaultUnlocked = onVaultLocked, onUnlockRequested = onVaultLocked,
        onAutoFillPublished = onVaultLocked, onClipboardCleared = onVaultLocked,
        onAutofilled = onVaultLocked, onPasskeySuppressed = onVaultLocked,
        onPasskeyRegistrationBlocked = onVaultLocked, onFillConsentRequest = onVaultLocked,
        onPasskeyVerifyRequest = onVaultLocked, onPasskeyChanged = onVaultLocked,
        onLoginSaved = onVaultLocked, onSyncMerged = onVaultLocked;
      export const onPasskeyChoiceRequest = async cb => { window.emitPasskeyChoice = cb; return () => {}; };
      export const onPasskeyChoiceClosed = onVaultLocked;
      const item = { id: 'test-item', kind: 'login', title: 'Example account', subtitle: 'test@example.test',
        letter: 'E', host: 'example.test', folder: '', hasTotp: false, isDeleted: false, modifiedAt: 1 };
      export const api = {
        resolvePasskeyChoice: async (id, itemId) => { window.passkeyChoice = { id, itemId }; },
        vaultStatus: async () => ({ exists: true, unlocked: true, hasQuickUnlock: true, biometricAvailable: false }),
        touch: async () => {}, listItems: async () => window.conflictResolved ? [item] : [item, { ...item, id: 'conflict-copy', title: 'Example account (sync conflict)', isSyncConflict: true, conflictOf: item.id }], securityReport: async () => [],
        exportLoginsCsv: async password => { if (password !== 'correct-master') throw { code: 'reauth_failed', message: 'Current master password was not accepted' }; window.exportConfirmed = true; return 1; },
        compareSyncConflict: async () => ({ originalRevision: 'reviewed-original', copyRevision: 'reviewed-copy', fields: [
          { key: 'username', original: 'original@example.test', copy: 'changed@example.test', secret: false, revealable: false, different: true },
          { key: 'password', original: 'Hidden', copy: 'Hidden', secret: true, revealable: true, different: true },
          { key: 'notes', original: 'Hidden', copy: 'Hidden', secret: true, revealable: true, different: true },
          { key: 'deleted', original: 'Active', copy: 'Active', secret: false, revealable: false, different: false },
        ] }),
        revealConflictField: async (_, field) => field === 'password' ? ['synthetic-old-secret', 'synthetic-new-secret'] : ['Original synthetic notes', 'Changed synthetic notes'],
        resolveSyncConflict: async (reviewed, action, fields) => { window.resolvedComparison = { reviewed, action, fields }; window.conflictResolved = true; },
        getItem: async () => ({ ...item, username: item.subtitle, url: 'https://example.test', notes: '', hasPassword: true, passwordStrength: 'strong', createdAt: 1 }),
        getSettings: async () => ({ autoLockSecs: 300, lockOnBlur: false, clipboardClearSecs: 30, confirmAutofill: false, savePrompt: true, handlePasskeys: true }),
        setSettings: async () => { throw new Error('Test disk failure'); },
        syncStatus: async () => window.testSync,
        appInfo: async () => ({ version: '0.5.0', build: 'synthetic-test', platform: 'linux', vaultFormat: 5 }),
        backupStatus: async () => ({ directory: null, lastSuccessUnix: null, lastError: null }),
        passwordHistory: async () => [{ id: 'previous', replacedAt: 1 }],
        copyPasswordHistory: async () => { window.historyCopied = true; },
        restorePasswordHistory: async () => { window.historyRestored = true; },
        listSnapshots: async () => [],
      };
    `,
  }));
  await page.goto('http://127.0.0.1:4175');
  const settingsButton = page.getByRole('button', { name: 'Settings', exact: true });
  await settingsButton.click();
  const settings = page.getByRole('dialog', { name: 'Settings', exact: true });
  await settings.waitFor();
  // Full Tab loop must stay inside the modal; jsdom cannot exercise this.
  for (let i = 0; i < 45; i++) {
    await page.keyboard.press('Tab');
    assert(await settings.evaluate(el => el.contains(document.activeElement)), 'Tab escaped Settings');
  }
  await settings.getByRole('switch', { name: 'Lock when window loses focus' }).click();
  await settings.getByRole('alert').filter({ hasText: 'Test disk failure' }).waitFor();
  assert.equal(await settings.getByRole('switch', { name: 'Lock when window loses focus' }).getAttribute('aria-checked'), 'false');
  await settings.getByRole('button', { name: 'Export…', exact: true }).click();
  const reauth = page.getByRole('dialog', { name: 'Confirm with master password' });
  await reauth.waitFor();
  assert.equal(await page.evaluate(() => Boolean(window.exportConfirmed)), false);
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press('Tab');
    assert(await reauth.evaluate(el => el.contains(document.activeElement)), 'Tab escaped password confirmation');
  }
  await reauth.getByLabel('Current master password').fill('wrong');
  await reauth.getByRole('button', { name: 'Confirm', exact: true }).click();
  await reauth.getByRole('alert').waitFor();
  assert.equal(await page.evaluate(() => Boolean(window.exportConfirmed)), false);
  await reauth.getByLabel('Current master password').fill('correct-master');
  await reauth.getByRole('button', { name: 'Confirm', exact: true }).click();
  await reauth.waitFor({ state: 'detached' });
  assert(await page.evaluate(() => window.exportConfirmed));
  await settings.getByRole('button', { name: 'Restore…', exact: true }).last().click();
  const nested = page.getByRole('dialog', { name: 'Earlier vault versions' });
  await nested.waitFor();
  for (let i = 0; i < 8; i++) {
    await page.keyboard.press('Tab');
    assert(await nested.evaluate(el => el.contains(document.activeElement)), 'Tab escaped nested dialog');
  }
  await page.keyboard.press('Escape');
  await nested.waitFor({ state: 'detached' });
  assert(await settings.evaluate(el => el.contains(document.activeElement)), 'Nested close lost parent focus');
  await page.keyboard.press('Escape');
  await settings.waitFor({ state: 'detached' });
  assert(await settingsButton.evaluate(el => el === document.activeElement), 'Dialog did not restore opener focus');
  await page.getByText('Example account', { exact: true }).first().click();
  await page.getByRole('button', { name: 'Password history…' }).click();
  const history = page.getByRole('dialog', { name: 'Password history', exact: true });
  await history.getByRole('button', { name: 'Copy', exact: true }).click();
  assert(await page.evaluate(() => window.historyCopied));
  await history.getByRole('button', { name: 'Restore…' }).click();
  await history.getByRole('button', { name: 'Restore saved password' }).click();
  await history.waitFor({ state: 'detached' });
  assert(await page.evaluate(() => window.historyRestored));
  await page.getByRole('button', { name: 'Review 1 sync conflict', exact: true }).click();
  const conflicts = page.getByRole('dialog', { name: 'Resolve sync conflicts' });
  await conflicts.getByLabel('Password: conflict copy').waitFor();
  assert.equal(await conflicts.getByText('synthetic-new-secret').count(), 0);
  await conflicts.getByRole('button', { name: 'Reveal values' }).first().click();
  await conflicts.getByText('synthetic-new-secret').waitFor();
  await conflicts.getByLabel('Password: conflict copy').check();
  for (let i = 0; i < 18; i++) {
    await page.keyboard.press('Tab');
    assert(await conflicts.evaluate(el => el.contains(document.activeElement)), 'Tab escaped conflict comparison');
  }
  if (process.env.ARCA_CONFLICT_SCREENSHOT) await page.screenshot({ path: process.env.ARCA_CONFLICT_SCREENSHOT });
  await conflicts.getByRole('button', { name: 'Save selected values' }).click();
  await conflicts.waitFor({ state: 'detached' });
  const resolved = await page.evaluate(() => window.resolvedComparison);
  assert.equal(resolved.action, 'merge');
  assert.deepEqual(resolved.fields, ['password']);
  assert.equal(resolved.reviewed.copyRevision, 'reviewed-copy');
  assert.equal(await page.getByRole('button', { name: 'Review 1 sync conflict', exact: true }).count(), 0);
  await page.evaluate(() => window.emitSync({ ...window.testSync, lastError: 'Test offline' }));
  await page.getByRole('button', { name: 'Retry sync' }).waitFor();
  await page.evaluate(() => window.emitPasskeyChoice({ id: 'choose-test', site: 'example.test', accounts: [
    { id: 'first', account: 'first@example.test', title: 'Example' },
    { id: 'wanted', account: 'wanted@example.test', title: 'Example' },
  ] }));
  const chooser = page.getByRole('dialog', { name: 'Choose a passkey account' });
  await chooser.waitFor();
  await page.screenshot({ path: '/tmp/arca-account-choice.png' });
  await chooser.getByRole('button', { name: 'wanted@example.test' }).click();
  assert.deepEqual(await page.evaluate(() => window.passkeyChoice), { id: 'choose-test', itemId: 'wanted' });
  await chooser.waitFor({ state: 'hidden' });
  assert.equal(errors.length, 0, errors.join('\n'));
  if (process.env.ARCA_QA_SCREENSHOT) {
    await settingsButton.click();
    await page.screenshot({ path: process.env.ARCA_QA_SCREENSHOT });
    await settings.getByRole("region", { name: "Automatic encrypted backups" }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: process.env.ARCA_QA_SCREENSHOT.replace(/\.png$/, "-backups.png") });
  }
  console.log('Desktop browser checks passed: keyboard dialogs, password confirmation, conflict comparison, history and live sync status.');
} finally {
  await browser?.close();
  await server.close();
}
