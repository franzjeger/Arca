import { Dialog } from "./Dialog";
import { useState } from "react";
import { api, errorMessage } from "../lib/api";
import { SshIcon } from "./icons";

/** Generate a new Ed25519 SSH key. Keys are create-only: the private seed is
 *  minted in the vault and never shown, so there is nothing to edit later
 *  (beyond deleting the key). */
export function SshKeyDialog({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
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
    <Dialog label="Generate SSH key" onClose={onClose}>
      <div className="w-full max-w-md rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <SshIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            New SSH key
          </h2>
        </div>

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
              className="w-full rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
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
      </div>
    </Dialog>
  );
}
