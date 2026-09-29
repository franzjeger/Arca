import { useEffect, useLayoutEffect, useState } from "react";
import { createPortal } from "react-dom";
import { AlertIcon, CheckIcon } from "./icons";
import type { ToastMessage } from "../lib/toast";
import { toastParts } from "../lib/toast";

/** The open modal dialog in front, or the page when none is.
 *
 * A modal `<dialog>` sits in the browser's top layer, above every z-index, so a
 * toast outside it is drawn underneath: a result raised from Settings ("No
 * duplicates found", a failed update check) was never seen, and the button
 * looked dead. Inside the dialog it shares the top layer, and it is not inert,
 * so screen readers announce it too. Dialogs portal into the body in the order
 * they open, so the last open one is in front. */
function frontmostLayer(): Element {
  const open = document.querySelectorAll("dialog[open]");
  return open.length > 0 ? open[open.length - 1] : document.body;
}

/** Where to render while `active`, following dialogs that open or close while
 * the toast is up (a nested dialog saves, closes, then reports). */
function useLayer(active: boolean): Element | null {
  const [layer, setLayer] = useState<Element | null>(null);
  useLayoutEffect(() => {
    if (!active) {
      setLayer(null);
      return;
    }
    const follow = () => setLayer(frontmostLayer());
    follow();
    const observer = new MutationObserver(follow);
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["open"],
    });
    return () => observer.disconnect();
  }, [active]);
  return layer;
}

/** Transient bottom-center toast, in front of any open dialog.
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
  const layer = useLayer(parts !== null);

  useEffect(() => {
    if (!parts) return;
    const t = setTimeout(onDone, shown);
    return () => clearTimeout(t);
  }, [parts?.text, parts?.tone, shown, onDone]);

  if (!parts || !layer) return null;
  return createPortal(
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
    </div>,
    layer,
  );
}
