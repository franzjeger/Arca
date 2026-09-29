import { useEffect, useState } from "react";
import { api, errorMessage, type FoundSshKey } from "../lib/api";

/** `ssh-ed25519` → `Ed25519`; old PEM files already say `RSA`, `EC`, `DSA`. */
export function sshTypeLabel(keyType: string): string {
  const known: Record<string, string> = {
    "ssh-ed25519": "Ed25519",
    "ssh-rsa": "RSA",
    "ssh-dss": "DSA",
    "ecdsa-sha2-nistp256": "ECDSA P-256",
    "ecdsa-sha2-nistp384": "ECDSA P-384",
    "ecdsa-sha2-nistp521": "ECDSA P-521",
  };
  return known[keyType] ?? keyType;
}

const REASONS: Record<string, string> = {
  passphrase: "wrong passphrase",
  unsupported: "this key type isn't supported yet",
  unreadable: "the file could not be read as a key",
  in_vault: "Arca already has this key",
  not_a_key_file: "the file is gone",
};

/** The keys already in ~/.ssh, crossed off against each other and against the
 *  vault by fingerprint (see `ssh_import`). Only a key the vault does not hold
 *  yet can be picked, and copies of one key count once. The private halves
 *  never come here: this sees file names, fingerprints and comments, and sends
 *  back which files to take and their passphrases. */
export function SshImportPanel({
  onImported,
  onClose,
}: {
  onImported: (id: string) => void;
  onClose: () => void;
}) {
  const [found, setFound] = useState<FoundSshKey[] | null>(null);
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [passphrases, setPassphrases] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [failed, setFailed] = useState<{ file: string; reason: string }[]>([]);

  const scan = async () => {
    const list = await api.sshImportScan();
    setFound(list);
    setPicked(
      Object.fromEntries(
        list.filter((k) => k.status.kind === "new").map((k) => [k.file, true]),
      ),
    );
  };
  useEffect(() => {
    scan().catch((e) => setError(errorMessage(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const chosen = (found ?? []).filter(
    (k) => k.status.kind === "new" && picked[k.file],
  );
  const needsPassphrase = chosen.some((k) => k.encrypted && !passphrases[k.file]);

  const run = async () => {
    if (busy || chosen.length === 0 || needsPassphrase) return;
    setBusy(true);
    setError(null);
    setFailed([]);
    try {
      const result = await api.sshImport(
        chosen.map((k) => ({
          file: k.file,
          passphrase: k.encrypted ? passphrases[k.file] : undefined,
        })),
      );
      setPassphrases({});
      if (result.failed.length === 0 && result.ids.length > 0) {
        onImported(result.ids[0]);
        return;
      }
      setFailed(result.failed);
      await scan();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="max-h-[60vh] space-y-3 overflow-y-auto px-5 py-4">
        <p className="text-[12px] leading-relaxed text-neutral-500">
          Keys are matched by fingerprint: one Arca already has, and copies of
          the same key, are never taken twice. The files stay in ~/.ssh; remove
          them yourself once ssh works through Arca's agent (open a key to see
          how).
        </p>
        {found === null && !error && (
          <p className="text-[12px] text-neutral-500">Looking in ~/.ssh…</p>
        )}
        {found?.length === 0 && (
          <p className="text-[13px] text-neutral-300">No private keys in ~/.ssh.</p>
        )}
        {found && found.length > 0 && (
          <ul aria-label="Keys in ~/.ssh" className="space-y-2">
            {found.map((k) => {
              const importable = k.status.kind === "new";
              return (
                <li
                  key={k.file}
                  className="rounded-lg bg-fill/5 px-3 py-2 ring-1 ring-line/10"
                >
                  <label className="flex items-start gap-2.5">
                    <input
                      type="checkbox"
                      aria-label={`Import ${k.file}`}
                      disabled={!importable || busy}
                      checked={importable && !!picked[k.file]}
                      onChange={(e) =>
                        setPicked({ ...picked, [k.file]: e.target.checked })
                      }
                      className="mt-0.5"
                    />
                    <span className="min-w-0 flex-1">
                      <span className="flex justify-between gap-2">
                        <span className="truncate text-[13px] text-neutral-100">
                          {k.file}
                        </span>
                        <span className="shrink-0 text-[11px] text-neutral-500">
                          {sshTypeLabel(k.keyType)}
                        </span>
                      </span>
                      {k.comment && (
                        <span className="block truncate text-[12px] text-neutral-400">
                          {k.comment}
                        </span>
                      )}
                      {k.fingerprint && (
                        <span className="block truncate font-mono text-[11px] text-neutral-500">
                          {k.fingerprint}
                        </span>
                      )}
                      <span className="block text-[11px] text-neutral-500">
                        {k.status.kind === "inVault"
                          ? `Already in Arca as “${k.status.title}”`
                          : k.status.kind === "sameAs"
                            ? `Same key as ${k.status.file}`
                            : k.status.kind === "unsupported"
                              ? `${sshTypeLabel(k.keyType)} keys aren't supported yet`
                              : k.encrypted
                                ? "Protected by a passphrase"
                                : "Not in Arca yet"}
                      </span>
                    </span>
                  </label>
                  {importable && k.encrypted && picked[k.file] && (
                    <input
                      type="password"
                      aria-label={`Passphrase for ${k.file}`}
                      placeholder="Passphrase"
                      value={passphrases[k.file] ?? ""}
                      onChange={(e) =>
                        setPassphrases({ ...passphrases, [k.file]: e.target.value })
                      }
                      className="mt-2 w-full rounded-lg bg-fill/5 px-3 py-1.5 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60"
                    />
                  )}
                </li>
              );
            })}
          </ul>
        )}
        {failed.length > 0 && (
          <ul aria-label="Not imported" className="space-y-1">
            {failed.map((f) => (
              <li key={f.file} className="text-[12px] text-red-400">
                {f.file}: {REASONS[f.reason] ?? f.reason}
              </li>
            ))}
          </ul>
        )}
        {error && <p className="text-[12px] text-red-400">{error}</p>}
      </div>

      <div className="flex justify-end gap-2 border-t border-hairline px-5 py-3">
        <button
          onClick={onClose}
          className="rounded-lg px-4 py-1.5 text-[13px] text-neutral-300 hover:bg-fill/5"
        >
          {failed.length > 0 ? "Done" : "Cancel"}
        </button>
        <button
          onClick={() => void run()}
          disabled={busy || chosen.length === 0 || needsPassphrase}
          className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
        >
          {busy
            ? "Importing…"
            : chosen.length === 1
              ? "Import 1 key"
              : `Import ${chosen.length} keys`}
        </button>
      </div>
    </>
  );
}
