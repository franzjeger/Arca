import { Dialog } from "./Dialog";
import { useState } from "react";
import { api, errorMessage } from "../lib/api";
import { SshIcon } from "./icons";
import { SshImportPanel } from "./SshImportPanel";

/** A new SSH key: generated in the vault, or taken from ~/.ssh (see
 *  `SshImportPanel`). Keys are create-only: the private seed is never shown,
 *  so there is nothing to edit later (beyond deleting the key). */
export function SshKeyDialog({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const [mode, setMode] = useState<"generate" | "import">("generate");
  const [comment, setComment] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = async () => {
    // The button is disabled while saving, but Enter went straight here: key
    // auto-repeat generated a new key per keydown and filled the vault.
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      const id = await api.generateSshKey(comment.trim());
      onSaved(id);
    } catch (e) {
      setError(errorMessage(e));
      setSaving(false);
    }
  };

  return (
    <Dialog label="New SSH key" onClose={onClose}>
      <div className="w-full max-w-md rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <SshIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            New SSH key
          </h2>
          <div role="tablist" className="ml-auto flex rounded-lg bg-fill/5 p-0.5 text-[12px]">
            {(["generate", "import"] as const).map((m) => (
              <button
                key={m}
                role="tab"
                aria-selected={mode === m}
                onClick={() => setMode(m)}
                className={`rounded-md px-2.5 py-1 ${mode === m ? "bg-fill/10 text-neutral-100" : "text-neutral-400 hover:text-neutral-200"}`}
              >
                {m === "generate" ? "Generate" : "Import from ~/.ssh"}
              </button>
            ))}
          </div>
        </div>

        {mode === "import" ? (
          <SshImportPanel onImported={(ids) => onSaved(ids[0])} onClose={onClose} />
        ) : (
          <>
            <div className="space-y-3 px-5 py-4">
              <div>
                <label className="mb-1 block text-[12px] font-medium text-neutral-500">
                  Comment / label
                </label>
                <input
                  value={comment}
                  autoFocus
                  placeholder="frank@macbook"
                  onChange={(e) => setComment(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && void generate()}
                  className="w-full rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-hidden ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
                  spellCheck={false}
                />
              </div>
              <p className="text-[12px] leading-relaxed text-neutral-500">
                A new Ed25519 key is generated inside the vault. The private key
                never leaves Arca — the ssh-agent signs with it in place. You'll get
                the public key to add to a server or GitHub.
              </p>
              {error && <p className="text-[12px] text-red-400">{error}</p>}
            </div>

            <div className="flex justify-end gap-2 border-t border-hairline px-5 py-3">
              <button
                onClick={onClose}
                className="rounded-lg px-4 py-1.5 text-[13px] text-neutral-300 hover:bg-fill/5"
              >
                Cancel
              </button>
              <button
                onClick={() => void generate()}
                disabled={saving}
                className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
              >
                {saving ? "Generating…" : "Generate key"}
              </button>
            </div>
          </>
        )}
      </div>
    </Dialog>
  );
}

/** Keys from ~/.ssh on their own, where people look for an import: next to
 *  "Import passwords" in Settings. */
export function SshImportDialog({
  onClose,
  onImported,
}: {
  onClose: () => void;
  onImported: (ids: string[]) => void;
}) {
  return (
    <Dialog label="Import SSH keys" onClose={onClose}>
      <div className="w-full max-w-md rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <SshIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            Import SSH keys
          </h2>
        </div>
        <SshImportPanel onImported={onImported} onClose={onClose} />
      </div>
    </Dialog>
  );
}
