// Styles stay inside the picker shadow root, isolated from website CSS.
(() => {
  globalThis.__arcaPickerStyles = `:host { color-scheme: dark; }
* { box-sizing: border-box; }
button { font: inherit; }
.sybr-panel-content {
  color-scheme: dark;
  box-sizing: border-box;
  max-height: 280px;
  overflow-y: auto;
  background: #1c1c1e;
  color: #f5f5f7;
  border: 1px solid #2e2e30;
  border-radius: 10px;
  box-shadow: 0 8px 28px rgba(0, 0, 0, 0.5);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  font-size: 13px;
  padding: 4px;
}

.sybr-note {
  padding: 10px 12px;
  color: #a1a1a6;
  line-height: 1.4;
}

/* The just-generated password: shown (not masked) so the user can read and
   verify it, with a copy button as a fallback before they submit. */
.sybr-generated {
  padding: 10px 12px;
  color: #a1a1a6;
  line-height: 1.4;
}
.sybr-generated-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.sybr-generated-value {
  flex: 1;
  min-width: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px;
  color: #f5f5f7;
  word-break: break-all;
  user-select: all;
}
.sybr-generated-copy {
  flex: none;
  padding: 4px 10px;
  border: none;
  border-radius: 7px;
  background: #2563eb;
  color: #fff;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
}
.sybr-generated-copy:hover {
  background: #1d4ed8;
}
.sybr-generated-msg {
  margin-top: 8px;
  font-size: 12px;
}

.sybr-row {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  width: 100%;
  padding: 8px 10px;
  border: none;
  border-radius: 7px;
  background: transparent;
  color: inherit;
  text-align: left;
  cursor: pointer;
}
.sybr-row:hover {
  background: rgba(255, 255, 255, 0.06);
}
.sybr-line {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
}
.sybr-title {
  font-weight: 600;
}
.sybr-user {
  color: #8e8e93;
  font-size: 12px;
}
/* Credential-type pill, right-aligned on the title line. */
.sybr-kind {
  margin-left: auto;
  flex: none;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  padding: 1px 7px;
  border-radius: 999px;
  line-height: 1.6;
}
.sybr-kind-password {
  background: rgba(142, 142, 147, 0.24);
  color: #c7c7cc;
}
.sybr-kind-passkey {
  background: rgba(100, 168, 255, 0.22);
  color: #64a8ff;
}


.sybr-panel-header { position: sticky; top: 0; z-index: 1; background: #1c1c1e; display: flex; align-items: center; justify-content: space-between; padding: 0 6px 2px 10px; color: #a1a1a6; font-size: 11px; }
.sybr-panel-header button { border: 0; border-radius: 5px; background: transparent; color: inherit; font-size: 20px; padding: 0 5px; cursor: pointer; }
.sybr-panel-header button:hover, button:focus-visible { background: #363638; outline: 2px solid #64a8ff; }
.sybr-title, .sybr-user { min-width: 0; overflow-wrap: anywhere; }
`;
})();
