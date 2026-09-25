import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../chromium/content.js', import.meta.url), 'utf8');
const helper = source.slice(source.indexOf('  async function lookupMatches('), source.indexOf('  // Show matching logins.'));
let replies, calls, waits;
const context = vm.createContext({
  api: { runtime: { async sendMessage(message) {
    calls.push(message);
    const reply = replies.shift();
    if (reply instanceof Error) throw reply;
    return reply;
  } } },
  setTimeout(fn, ms) { waits.push(ms); fn(); },
  document: { createElement() { return {
    children: [], appendChild(child) { this.children.push(child); },
    addEventListener(name, fn) { this[name] = fn; },
  }; } },
  note: text => ({ textContent: text }),
  showMatches: (...args) => calls.push(args),
});
vm.runInContext(helper, context);
const success = { ok: true, response: { items: [], app_connected: false } };
async function lookup(sequence) {
  replies = [...sequence]; calls = []; waits = [];
  return context.lookupMatches('https://example.test/login');
}
assert.equal(await lookup([success]), success);
assert.equal(calls.length, 1, 'locked vault must not be retried');
for (const failure of [undefined, { ok: false, error: 'Native host has exited.' }, new Error('Message port closed')]) {
  assert.equal(await lookup([failure, success]), success);
  assert.equal(calls.length, 2);
  assert.deepEqual(waits, [250]);
  assert.ok(calls.every(c => c.cmd === 'listLogins'), 'retry only reads metadata');
}
const persistent = { ok: false, error: 'Specified native messaging host not found.' };
assert.equal(await lookup([persistent, persistent, success]), persistent);
assert.equal(calls.length, 2, 'retries are bounded');
const invalidated = new Error('Extension context invalidated.');
assert.match((await lookup([invalidated])).error, /context invalidated/);
assert.equal(calls.length, 1);
const panel = context.connectionFailure('anchor', true, persistent.error);
assert.equal(panel.children[1].textContent, persistent.error, 'preserve concrete error');
assert.equal(panel.children[2].textContent, 'Try again');
calls = [];
panel.children[2].click({ isTrusted: false });
assert.equal(calls.length, 0);
panel.children[2].click({ isTrusted: true, stopPropagation() {} });
assert.deepEqual(calls, [['anchor', false, true]]);
const stale = context.connectionFailure('anchor', true, invalidated.message);
assert.match(stale.children[0].textContent, /Reload this page/);
assert.equal(stale.children.length, 2, 'no futile retry for invalidated script');
console.log('connection recovery: passed');
