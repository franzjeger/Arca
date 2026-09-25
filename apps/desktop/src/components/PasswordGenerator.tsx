import { useCallback, useEffect, useState } from "react";
import { api, errorMessage, type PasswordOptions } from "../lib/api";
import { RefreshIcon } from "./icons";

const TOGGLES: { key: keyof Omit<PasswordOptions, "length">; label: string }[] =
  [
    { key: "lowercase", label: "a-z" },
    { key: "uppercase", label: "A-Z" },
    { key: "digits", label: "0-9" },
    { key: "symbols", label: "!@#" },
  ];

/** Inline password generator. Calls `onUse` to push a value into the form. */
export function PasswordGenerator({ onUse }: { onUse: (pw: string) => void }) {
  const [opts, setOpts] = useState<PasswordOptions>({
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
  });
  const [preview, setPreview] = useState("");
  const [error, setError] = useState<string | null>(null);

  const regenerate = useCallback(async () => {
    try {
      setPreview(await api.generate(opts));
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    }
  }, [opts]);

  useEffect(() => {
    void regenerate();
  }, [regenerate]);

  const enabledCount = TOGGLES.filter((t) => opts[t.key]).length;

  return (
    <div className="mt-2 rounded-lg border border-hairline bg-fill/[0.03] p-3">
      <div className="flex items-center gap-2">
        <code className="flex-1 truncate rounded bg-black/30 px-2 py-1.5 font-mono text-[13px] text-neutral-100">
          {preview || "…"}
        </code>
        <button
          type="button"
          onClick={regenerate}
          className="rounded-md p-1.5 text-neutral-400 hover:bg-fill/5 hover:text-neutral-100"
          title="Regenerate"
        >
          <RefreshIcon className="h-4 w-4" />
        </button>
      </div>

      <div className="mt-3 flex items-center gap-3">
        <input
          type="range"
          min={8}
          max={64}
          value={opts.length}
          onChange={(e) =>
            setOpts((o) => ({ ...o, length: Number(e.target.value) }))
          }
          className="flex-1 accent-accent"
        />
        <span className="w-8 text-right text-[13px] tabular-nums text-neutral-300">
          {opts.length}
        </span>
      </div>

      <div className="mt-2 flex flex-wrap gap-1.5">
        {TOGGLES.map((t) => {
          const on = opts[t.key];
          const lastOn = on && enabledCount === 1;
          return (
            <button
              key={t.key}
              type="button"
              disabled={lastOn}
              onClick={() => setOpts((o) => ({ ...o, [t.key]: !o[t.key] }))}
              className={`rounded-md px-2.5 py-1 font-mono text-[12px] ring-1 transition-colors ${
                on
                  ? "bg-accent/20 text-accent ring-accent/40"
                  : "text-neutral-400 ring-line/10 hover:bg-fill/5"
              } ${lastOn ? "cursor-not-allowed opacity-70" : ""}`}
              title={lastOn ? "At least one set is required" : undefined}
            >
              {t.label}
            </button>
          );
        })}
        <button
          type="button"
          onClick={() => preview && onUse(preview)}
          className="ml-auto rounded-md bg-accent px-3 py-1 text-[12px] font-medium text-white hover:bg-accent/90"
        >
          Use
        </button>
      </div>
      {error && <p className="mt-2 text-[12px] text-red-400">{error}</p>}
    </div>
  );
}
