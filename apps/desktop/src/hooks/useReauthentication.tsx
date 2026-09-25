import { useEffect, useRef, useState } from "react";
import { Dialog } from "../components/Dialog";
import { api, errorMessage } from "../lib/api";

type Pending = {
  reason: string;
  action: (password: string) => Promise<unknown>;
  finish: (result: { value: unknown } | null) => void;
  fail: (cause: unknown) => void;
};

/** OS verification where supported; a fresh master-password prompt elsewhere.
 * The backend enforces both paths; hiding this UI never grants authorization. */
export function useReauthentication() {
  const pending = useRef<Pending | null>(null);
  const mounted = useRef(true);
  const [reason, setReason] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const preparing = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; pending.current?.finish(null); pending.current = null; };
  }, []);

  function cancel() {
    pending.current?.finish(null); pending.current = null;
    setReason(null); setPassword(""); setError(null);
  }

  async function run<T>(description: string, action: (password?: string) => Promise<T>): Promise<{ value: T } | null> {
    if (pending.current || preparing.current) return null;
    preparing.current = true;
    let status;
    try { status = await api.vaultStatus(); }
    finally { preparing.current = false; }
    if (!mounted.current) return null;
    if (status.biometricAvailable) return { value: await action() };
    return new Promise((resolve, reject) => {
      pending.current = { reason: description, action, finish: (result) => resolve(result as { value: T } | null), fail: reject };
      setPassword(""); setError(null); setReason(description);
    });
  }

  async function submit() {
    const request = pending.current;
    if (!request || submitting.current || !password) return;
    submitting.current = true; setBusy(true); setError(null);
    const supplied = password; setPassword("");
    try {
      const value = await request.action(supplied);
      if (mounted.current && pending.current === request) {
        pending.current = null; setReason(null); request.finish({ value });
      }
    } catch (cause) {
      if (mounted.current && pending.current === request) {
        const code = (cause as { code?: string })?.code;
        if (code === "reauth_failed" || code === "reauth_required") setError(errorMessage(cause));
        else { pending.current = null; setReason(null); request.fail(cause); }
      }
    } finally {
      submitting.current = false;
      if (mounted.current) setBusy(false);
    }
  }

  const dialog = reason && <Dialog label="Confirm with master password" onClose={cancel} dismissible={!busy}>
    <form onSubmit={(event) => { event.preventDefault(); void submit(); }} className="w-full max-w-md space-y-4 rounded-2xl border border-hairline bg-panel p-5 shadow-2xl">
      <h2 className="text-[15px] font-semibold text-neutral-100">Confirm it's you</h2>
      <p className="text-[13px] text-neutral-400">Enter your current vault master password to {reason}.</p>
      <label className="block text-[12px] text-neutral-300">Current master password
        <input autoFocus type="password" autoComplete="current-password" value={password} disabled={busy}
          onChange={(event) => setPassword(event.target.value)}
          className="mt-2 w-full rounded-lg bg-fill/5 px-3 py-2 text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60" />
      </label>
      {error && <p role="alert" className="text-[12px] text-red-400">{error}</p>}
      <div className="flex justify-end gap-2">
        <button type="button" disabled={busy} onClick={cancel} className="rounded-lg px-3 py-2 text-[13px] text-neutral-300 disabled:opacity-50">Cancel</button>
        <button type="submit" disabled={busy || !password} className="rounded-lg bg-accent px-3 py-2 text-[13px] font-medium text-white disabled:opacity-50">{busy ? "Verifying…" : "Confirm"}</button>
      </div>
    </form>
  </Dialog>;
  return { run, dialog };
}
