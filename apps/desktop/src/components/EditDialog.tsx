import { Dialog } from "./Dialog";
import { useEffect, useState, type ReactNode } from "react";
import { api, errorMessage, type LoginInput } from "../lib/api";
import { EyeIcon, EyeOffIcon, KeyIcon } from "./icons";
import { PasswordGenerator } from "./PasswordGenerator";
import { clearDraft, draftKey, useDraft } from "../lib/drafts";

type Form = Omit<LoginInput, "totpSecret"> & { totpSecret: string };

const EMPTY: Form = {
  id: null,
  title: "",
  username: "",
  password: "",
  url: "",
  totpSecret: "",
  notes: "",
};

export function EditDialog({
  itemId,
  onClose,
  onSaved,
}: {
  itemId: string | null; // null = create new
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const [form, setForm] = useState<Form>(EMPTY);
  const key = draftKey("login", itemId);
  // Scoped to this unlocked session; locking discards the draft.
  const restored = useDraft(key, form, setForm);
  const [loading, setLoading] = useState(itemId !== null && !restored);
  const [saving, setSaving] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [showGen, setShowGen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    // Cancel discards the current draft.
    clearDraft(key);
    onClose();
  };

  // Load existing values (including secrets) when editing.
  useEffect(() => {
    // A restored draft is newer than the file; refetching would overwrite the
    // user's unsaved edits with what is still on disk.
    if (restored) return;
    if (itemId === null) {
      setForm(EMPTY);
      setLoading(false);
      return;
    }
    let alive = true;
    (async () => {
      try {
        const d = await api.getItem(itemId);
        const password = d.hasPassword
          ? await api.revealField(itemId, "password")
          : "";
        const totpSecret = d.hasTotp
          ? await api.revealField(itemId, "totp_secret")
          : "";
        if (!alive) return;
        setForm({
          id: itemId,
          title: d.title,
          username: d.username,
          password,
          url: d.url,
          totpSecret,
          notes: d.notes,
        });
      } catch (e) {
        if (alive) setError(errorMessage(e));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [itemId, restored]);

  const set = <K extends keyof Form>(k: K, v: Form[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  const save = async () => {
    if (!form.title.trim() && !form.username.trim()) {
      setError("Add a title or user name.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const input: LoginInput = {
        ...form,
        totpSecret: form.totpSecret.trim() ? form.totpSecret.trim() : null,
      };
      const id = await api.upsertItem(input);
      clearDraft(key);
      onSaved(id);
    } catch (e) {
      setError(errorMessage(e));
      setSaving(false);
    }
  };

  return (
    <Dialog label="Login" onClose={close} dismissible={!saving}>
      <div className="w-full max-w-md rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <KeyIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            {itemId === null ? "New Login" : "Edit Login"}
          </h2>
        </div>

        <p className="px-5 pt-3 text-xs text-neutral-400">
          Locking discards unsaved changes. Save before switching apps if lock-on-blur is enabled.
        </p>

        {loading ? (
          <div className="px-5 py-10 text-center text-[13px] text-neutral-500">
            Loading…
          </div>
        ) : (
          <div className="space-y-3 px-5 py-4">
            <LabeledInput
              label="Title"
              value={form.title}
              onChange={(v) => set("title", v)}
              placeholder="GitHub"
              autoFocus
            />
            <LabeledInput
              label="User name"
              value={form.username}
              onChange={(v) => set("username", v)}
              placeholder="frank-lia"
            />

            <div>
              <FieldLabel>Password</FieldLabel>
              <div className="flex items-center gap-2">
                <div className="flex flex-1 items-center rounded-lg bg-fill/5 ring-1 ring-line/10 focus-within:ring-accent/60">
                  <input
                    type={showPw ? "text" : "password"}
                    value={form.password}
                    onChange={(e) => set("password", e.target.value)}
                    className="w-full bg-transparent px-3 py-2 font-mono text-[13px] text-neutral-100 outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw((s) => !s)}
                    className="px-2 text-neutral-500 hover:text-neutral-200"
                    title={showPw ? "Hide" : "Show"}
                  >
                    {showPw ? (
                      <EyeOffIcon className="h-4 w-4" />
                    ) : (
                      <EyeIcon className="h-4 w-4" />
                    )}
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => setShowGen((s) => !s)}
                  className="rounded-lg border border-hairline px-3 py-2 text-[12px] text-neutral-200 hover:bg-fill/5"
                >
                  Generate
                </button>
              </div>
              {showGen && (
                <PasswordGenerator
                  onUse={(pw) => {
                    set("password", pw);
                    setShowPw(true);
                    setShowGen(false);
                  }}
                />
              )}
            </div>

            <LabeledInput
              label="Website"
              value={form.url}
              onChange={(v) => set("url", v)}
              placeholder="https://github.com"
            />
            <LabeledInput
              label="Setup key (TOTP)"
              value={form.totpSecret}
              onChange={(v) => set("totpSecret", v)}
              placeholder="Base32 secret or otpauth:// URI (optional)"
              mono
            />

            <div>
              <FieldLabel>Notes</FieldLabel>
              <textarea
                value={form.notes}
                onChange={(e) => set("notes", e.target.value)}
                rows={2}
                className="w-full resize-none rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60"
              />
            </div>

            {error && <p className="text-[12px] text-red-400">{error}</p>}
          </div>
        )}

        <div className="flex justify-end gap-2 border-t border-hairline px-5 py-3">
          <button
            onClick={close}
            className="rounded-lg px-4 py-1.5 text-[13px] text-neutral-300 hover:bg-fill/5"
          >
            Cancel
          </button>
          <button
            onClick={save}
            disabled={saving || loading}
            className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </Dialog>
  );
}

function FieldLabel({ children }: { children: ReactNode }) {
  return (
    <label className="mb-1 block text-[12px] font-medium text-neutral-500">
      {children}
    </label>
  );
}

function LabeledInput({
  label,
  value,
  onChange,
  placeholder,
  autoFocus,
  mono,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
  mono?: boolean;
}) {
  return (
    <div>
      <FieldLabel>{label}</FieldLabel>
      <input
        value={value}
        autoFocus={autoFocus}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className={`w-full rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60 ${
          mono ? "font-mono" : ""
        }`}
        spellCheck={false}
      />
    </div>
  );
}
