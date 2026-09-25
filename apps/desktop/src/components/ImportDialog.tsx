import { Dialog } from "./Dialog";
import { useState } from "react";
import { api, errorMessage, type ImportSummary } from "../lib/api";
import { toastError, type ToastMessage } from "../lib/toast";

/** Per-browser export walkthroughs. The CSV parser auto-detects all formats. */
const SOURCES: {
  id: string;
  name: string;
  steps: string[];
  /** Extra action rendered next to the import button (e.g. open an app). */
  action?: { label: string; run: () => Promise<void> };
}[] = [
  {
    id: "safari",
    name: "Safari / Apple Passwords",
    steps: [
      "Open the Passwords app and unlock it.",
      "File menu → Export → Export All Passwords…, save the CSV.",
    ],
    action: { label: "Open Passwords app", run: () => api.openPasswordsApp() },
  },
  {
    id: "chrome",
    name: "Chrome / Edge",
    steps: [
      "Go to chrome://password-manager/settings (Edge: edge://wallet/passwords).",
      "Export passwords → confirm, save the CSV.",
    ],
  },
  {
    id: "brave",
    name: "Brave",
    steps: [
      "Go to brave://settings/passwords.",
      'Click ⋯ next to "Saved passwords" → Export passwords, save the CSV.',
    ],
  },
  {
    id: "firefox",
    name: "Firefox",
    steps: [
      "Go to about:logins.",
      "Click ⋯ (top right) → Export passwords, save the CSV.",
    ],
  },
  {
    id: "other",
    name: "Other (any CSV)",
    steps: [
      "Export a CSV with site, username and password columns (1Password, Bitwarden, KeePass exports work).",
      "Column names are detected automatically; otpauth:// TOTP columns import too.",
    ],
  },
];

function summaryText(s: ImportSummary): string {
  const parts = [`Imported ${s.imported}`];
  if (s.updated) parts.push(`updated ${s.updated}`);
  if (s.duplicates) parts.push(`${s.duplicates} already present`);
  if (s.skipped) parts.push(`skipped ${s.skipped}`);
  return parts.join(", ");
}

export function ImportDialog({
  onClose,
  onImported,
  onToast,
}: {
  onClose: () => void;
  onImported: () => void;
  onToast: (msg: ToastMessage) => void;
}) {
  const [open, setOpen] = useState<string>("safari");
  const [busy, setBusy] = useState(false);

  const importCsv = async () => {
    setBusy(true);
    try {
      const summary = await api.pickAndImportCsv();
      if (summary) {
        onToast(summaryText(summary));
        onImported();
      }
    } catch (e) {
      onToast(toastError(errorMessage(e)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog label="Import passwords" onClose={onClose} dismissible={!busy}>
      <div className="w-full max-w-md rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="border-b border-hairline px-5 py-3.5">
          <h2 className="text-[15px] font-semibold text-neutral-100">
            Import passwords
          </h2>
          <p className="mt-0.5 text-[11px] leading-snug text-neutral-500">
            Re-importing is safe: unchanged logins are skipped and changed
            passwords update the existing entry.
          </p>
        </div>

        <div className="max-h-[50vh] overflow-y-auto px-5 py-2">
          {SOURCES.map((src) => {
            const isOpen = open === src.id;
            return (
              <div
                key={src.id}
                className="border-b border-hairline py-2.5 last:border-b-0"
              >
                <button
                  type="button"
                  onClick={() => setOpen(isOpen ? "" : src.id)}
                  className="flex w-full items-center justify-between text-left"
                >
                  <span className="text-[13px] font-medium text-neutral-100">
                    {src.name}
                  </span>
                  <span className="text-[11px] text-neutral-500">
                    {isOpen ? "Hide" : "Show"}
                  </span>
                </button>
                {isOpen && (
                  <div className="mt-2">
                    <ol className="list-decimal space-y-1 pl-5 text-[12px] leading-snug text-neutral-400">
                      {src.steps.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ol>
                    <div className="mt-2.5 flex items-center gap-2">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void importCsv()}
                        className="rounded-lg bg-accent px-3 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
                      >
                        Choose CSV…
                      </button>
                      {src.action && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() =>
                            void src
                              .action!.run()
                              .catch((e) =>
                                onToast(toastError(errorMessage(e))),
                              )
                          }
                          className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                        >
                          {src.action.label}
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="flex items-center justify-between border-t border-hairline px-5 py-3">
          <p className="pr-4 text-[11px] leading-snug text-amber-400/90">
            Delete the CSV after importing — it holds your passwords in plain
            text.
          </p>
          <button
            onClick={onClose}
            className="shrink-0 rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90"
          >
            Done
          </button>
        </div>
      </div>
    </Dialog>
  );
}
