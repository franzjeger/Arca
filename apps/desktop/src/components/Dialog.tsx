import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

/** Native modality provides inert background content, nested focus containment
 * and Escape. Unmounting on a vault lock never invokes the discard callback. */
export function Dialog({ label, onClose, dismissible = true, children, className = "" }: {
  label: string;
  onClose: () => void;
  dismissible?: boolean;
  children: ReactNode;
  className?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [returnFocus] = useState(() => document.activeElement);
  useLayoutEffect(() => {
    const element = dialog.current!;
    element.showModal();
    return () => {
      element.close();
      if (returnFocus instanceof HTMLElement && returnFocus.isConnected) {
        returnFocus.focus({ preventScroll: true });
      }
    };
  }, [returnFocus]);

  return createPortal(
    <dialog
      ref={dialog}
      aria-label={label}
      aria-modal="true"
      className={`arca-dialog flex items-center justify-center bg-black/50 p-6 backdrop-blur-sm ${className}`}
      onKeyDown={(event) => {
        if (event.key !== "Tab" || !event.currentTarget.contains(event.target as Node)) return;
        event.stopPropagation();
        const controls = Array.from(event.currentTarget.querySelectorAll<HTMLElement>(
          'button, input, select, textarea, a[href], [tabindex]',
        )).filter((element) => element.tabIndex >= 0 && !element.matches(":disabled") && element.getClientRects().length > 0);
        const first = controls[0];
        const last = controls[controls.length - 1];
        if (!first) { event.preventDefault(); event.currentTarget.focus(); return; }
        if (event.shiftKey && (document.activeElement === first || document.activeElement === event.currentTarget)) {
          event.preventDefault(); last.focus();
        } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === event.currentTarget)) {
          event.preventDefault(); first.focus();
        }
      }}
      onCancel={(event) => {
        event.preventDefault();
        event.stopPropagation();
        if (dismissible) onClose();
      }}
      onMouseDown={(event) => {
        if (dismissible && event.target === event.currentTarget) onClose();
      }}
    >
      {children}
    </dialog>,
    document.body,
  );
}
