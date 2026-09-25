// Focused source-level regression checks for code that runs as a browser
// content script. Keeping this dependency-free lets CI exercise it without a
// synthetic DOM whose Shadow DOM retargeting differs from a real browser.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = fs.readFileSync(
  path.join(here, "../chromium/content.js"),
  "utf8",
);
const backgroundSource = fs.readFileSync(
  path.join(here, "../chromium/background.js"),
  "utf8",
);

let checks = 0;
function check(condition, message) {
  assert.ok(condition, message);
  checks++;
}

check(
  /const target = eventTarget\(e\);[\s\S]{0,180}target\.closest\(/.test(source),
  "submit-shaped clicks must use the composed-path target for Shadow DOM",
);
check(
  /const sameSite = [\s\S]{0,180}return !!a && !!b && a === b;/.test(source),
  "post-navigation credential capture must require an exact normalized host",
);

// A password Arca generates lands on sign-up / reset forms that captureCandidate
// rejects (two password boxes, or no username field). If generate doesn't record
// what it filled and submit doesn't fall back to it, the generated password
// becomes the live account password and is saved nowhere — the reported bug.
check(
  /generatedFill = \{[\s\S]{0,160}password: out\.password,/.test(source),
  "generateInto must record the password it filled for save-on-submit",
);
check(
  (source.match(/\?\?\s*generatedCandidate\(\)/g) || []).length >= 3,
  "all three submit triggers must fall back to the generated-password candidate",
);
check(
  /function generatedCandidate\(\)[\s\S]{0,400}stillFilled/.test(source),
  "generatedCandidate must verify the value is still in a visible field",
);
// Portainer's account form is current/new/confirm with no autocomplete hints
// and no username. Rejecting every multi-password form made manual password
// changes invisible to save-on-submit.
check(
  /function changedPasswordField\(pws\)[\s\S]{0,900}explicitlyNew[\s\S]{0,900}repeatedValues/.test(
    source,
  ),
  "multi-password forms must identify the new field without choosing current",
);
check(
  /const multiPassword = pws\.length > 1[\s\S]{0,420}password: passwordEl\.value,[\s\S]{0,80}multiPassword/.test(
    source,
  ),
  "Portainer-style changes must become save candidates even without a username",
);
check(
  /candidate\.multiPassword && !candidatePasswordStillVisible\(candidate\)/.test(
    source,
  ),
  "a mounted SPA form with cleared password values must count as settled",
);
check(
  /multiPassword: !!msg\.multiPassword/.test(backgroundSource),
  "the pending-save bridge must preserve multi-password form context",
);

// A generated password must be shown (a random string in a masked box the user
// can't read is the other half of the complaint), with a gesture-safe copy.
check(
  /openPanel\(anchor, buildGeneratedNote\(out\.password\)\)/.test(source),
  "generateInto must reveal the generated value, not just a 'filled' note",
);
check(
  /function copyText\([\s\S]{0,200}navigator\.clipboard[\s\S]{0,600}execCommand\("copy"\)/.test(
    source,
  ),
  "copy must use the Clipboard API with an execCommand fallback",
);

// A generated password lands on sign-up / reset forms, and those redirect to a
// LOGIN page — which has a password field, often on another host. Gating the
// offer on "form gone" and "same site" threw the value away in exactly the case
// it was added for.
check(
  /if \(cand\.generated\) \{[\s\S]{0,120}offer\(cand\)/.test(source),
  "a generated password must skip the post-navigation same-site/form gates",
);
check(
  /SETTLE_DEADLINE_MS[\s\S]{0,600}settleTimer = setTimeout\(tick, 500\)/.test(
    source,
  ),
  "save-on-submit must poll for the form to go away, not sample once",
);
check(
  /const key = `\$\{candidate\.username\}\\n\$\{candidate\.password\}`/.test(
    source,
  ),
  "the submit rate-limit must key on the candidate, not drop a newer one",
);
check(
  /button\.closest\("\.sybr-panel, \.sybr-savebar"\)/.test(source),
  "Arca's own panel and save-bar buttons must not count as page submits",
);
// A successful probe is not a successful write: the vault can lock between the
// prompt appearing and the user clicking it. The save bar must inspect the
// actual save response and remain available with the captured password on
// failure, rather than disappearing and pretending the write succeeded.
check(
  /const result = await api\.runtime\.sendMessage\([\s\S]{0,220}result\.response\?\.type === "saved"/.test(
    source,
  ),
  "the save bar must require an explicit saved response before closing",
);
check(
  /needsUnlock = \/locked\|not running\|unreachable\/i\.test\(reason\)[\s\S]{0,300}Unlock & Retry/.test(
    source,
  ),
  "a failed save must retain the candidate and offer an unlock-and-retry path",
);
// "Unlock & Save" is agreed to blind. Once the vault is open and the probe
// says "update", the bar has to name the account it would overwrite and wait
// for a second click, exactly as an unlocked vault would have prompted.
check(
  /if \(verdict === "update"\) \{[\s\S]{0,200}describe\([\s\S]{0,120}probe\.response\.username[\s\S]{0,160}return;/.test(
    source,
  ),
  "an update discovered after unlocking must be shown and re-confirmed",
);
// A server-rendered change form that comes back with an error still has two
// or more password boxes; the submitted value was rejected and must not be
// offered as the account's new password.
check(
  /cand\.multiPassword && sameSite\(cand\.url, location\.href\)[\s\S]{0,80}if \(!changeFormStillUp\(\)\) offer\(cand\)/.test(
    source,
  ),
  "a re-rendered change form after navigation must not prompt to save",
);
// Reading the pending candidate consumes it, and every gate below can decline
// to offer on THIS document — an interstitial that redirects again, most of
// all. The password used to be destroyed by the first look at it.
check(
  /finally \{[\s\S]{0,120}if \(!offered\)[\s\S]{0,200}cmd: "capturePending"/.test(
    source,
  ),
  "a candidate no gate could offer must be put back, not dropped",
);
check(
  /typeof msg\.ts === "number"[\s\S]{0,160}now - ts >= PENDING_TTL_MS/.test(
    backgroundSource,
  ),
  "a re-stashed candidate keeps its original age so the TTL still expires",
);
// MV3 evicts an idle service worker after ~30s. A sign-in that waits on a push
// approval before navigating is idle by that measure, and the Map died with
// the worker holding the only copy of the candidate.
check(
  /async function putPending[\s\S]{0,300}sessionStore\.set/.test(
    backgroundSource,
  ),
  "pending saves must outlive service-worker eviction, like the gesture ledger",
);
// The picker and the save bar live in the page's own DOM, and the picker opens
// on focus: without a trust gate a page script could focus the password box,
// click a row, and read the credential back out of the input.
check(
  /row\.addEventListener\("click", async \(e\) => \{[\s\S]{0,600}if \(!e\.isTrusted\) return;/.test(
    source,
  ),
  "a picker row must refuse a synthetic click",
);
check(
  /may commit a password to the vault[\s\S]{0,220}if \(!e\.isTrusted\) return;/.test(
    source,
  ),
  "the save bar must refuse a synthetic click outright",
);
// `name="user_password"` matched the username tiers, so the password field was
// returned as its own username field.
check(
  /function canHoldUsername\(el, pw\)[\s\S]{0,200}el !== pw &&[\s\S]{0,120}USERNAME_INPUT_TYPES\.has\(el\.type\)/.test(
    source,
  ),
  "a username field must be a text-shaped input that is not the password box",
);
// A document-scoped identifier used to claim the first current-password box
// anywhere on the page, including another widget's or one inside a shadow root.
check(
  /const siblings = local\.filter\([\s\S]{0,140}getRootNode[\s\S]{0,200}DOCUMENT_POSITION_FOLLOWING/.test(
    source,
  ),
  "a form-less identifier binds to the password box that follows it in its own tree",
);
// Ranked tiers, not one union: a bare text input between the username and the
// password used to win over an explicit autocomplete=username.
check(
  /const tiers = \[[\s\S]{0,400}for \(const selector of tiers\)/.test(source),
  "findUsernameField must resolve by selector tier, then proximity",
);
// A "show password" toggle flips type to text. Treating the field as gone
// offered a save before submit, then blinded the real submit's capture.
check(
  /knownPasswordFields = new WeakSet\(\)/.test(source) &&
    /knownPasswordFields\.has\(el\)/.test(source),
  "password fields must be tracked by element so a reveal toggle can't hide them",
);
// Identifier-first sign-ins (Google/Microsoft/Okta) hide the username box by
// the password step, so capture could never resolve one.
check(
  /rememberedIdentifier\(\)/.test(source) && /IDENTIFIER_FRESH_MS/.test(source),
  "the identifier step's value must be remembered for the password step",
);
// On an unlabelled [current, new, confirm] form, generating used to fill the
// CURRENT box and the change failed on "current password incorrect".
check(
  /const i = candidates\.indexOf\(el\);[\s\S]{0,400}return el;/.test(source),
  "generationTargetFor must start from the clicked field",
);

// Suggestions panel must default to closed shadow root so untrusted page scripts
// cannot exfiltrate credentials, accounts or usernames.
check(
  /let shadowMode = "closed";/.test(source) &&
    /attachShadow\(\{\s*mode:\s*shadowMode\s*\}\)/.test(source),
  "suggestion panel must default to a closed shadow root to protect credentials from page scripts",
);

// A passkey pick is the sign-in approval. The Chromium e2e proves the attacks
// fail; these keep the gate in place where Chromium is not installed.
check(
  /trackVisibility: true/.test(source) && /if \(!entry\.isVisible\) seenSince\.delete/.test(source),
  "picker rows must be watched with IntersectionObserver v2 visibility, not mere intersection",
);
check(
  /const seen = seenLongEnough\(row\);[\s\S]{0,700}if \(seen && typeof window\.__sybrPasskeyPicked === "function"\)/.test(
    source,
  ),
  "a passkey pick must be recorded only for a row the browser reported visible",
);

console.log(`content script: ${checks} checks passed`);
