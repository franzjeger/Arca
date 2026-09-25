import { useEffect } from "react";
import { AlertIcon, CheckIcon } from "./icons";
import type { ToastMessage } from "../lib/toast";
import { toastParts } from "../lib/toast";

/** Transient bottom-center toast.
 *
 * Errors are not successes. Every failure in the app routes here, and with one
 * green check for everything, "Could not read or write the vault file." looked
 * exactly like "Copied". Errors get their own colour, icon and a longer read —
 * 1.6s is enough to confirm a copy, not enough to read what went wrong. */
export function Toast({
  message,
  onDone,
  duration,
}: {
  message: ToastMessage | null;
  onDone: () => void;
  duration?: number;
}) {
  const parts = toastParts(message);
  const isError = parts?.tone === "error";
  const shown = duration ?? (isError ? 5000 : 1600);

  useEffect(() => {
    if (!parts) return;
    const t = setTimeout(onDone, shown);
    return () => clearTimeout(t);
  }, [parts?.text, parts?.tone, shown, onDone]);

  if (!parts) return null;
  return (
    <div
      role={isError ? "alert" : "status"}
      className="pointer-events-none fixed inset-x-0 bottom-6 z-50 flex justify-center"
    >
      <div
        className={`flex max-w-[min(32rem,90vw)] items-center gap-2 rounded-full px-4 py-2 text-[13px] shadow-lg ring-1 backdrop-blur ${
          isError
            ? "bg-red-950/95 text-red-100 ring-red-500/30"
            : "bg-neutral-800 text-neutral-100 ring-line/10"
        }`}
      >
        {isError ? (
          <AlertIcon className="h-4 w-4 shrink-0 text-red-400" />
        ) : (
          <CheckIcon className="h-4 w-4 shrink-0 text-green-400" />
        )}
        {parts.text}
      </div>
    </div>
  );
}
