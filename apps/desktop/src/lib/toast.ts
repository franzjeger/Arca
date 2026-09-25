/** What can be handed to the toast.
 *
 * A bare string is a success/confirmation, which keeps the many "Copied" style
 * call sites unchanged. Failures wrap their text with `toastError` so the toast
 * can render them as failures — previously every error was shown with a green
 * check for 1.6s and read as if it had worked. */
export type ToastMessage = string | { text: string; tone: "error" };

export function toastError(text: string): ToastMessage {
  return { text, tone: "error" };
}

export function toastParts(
  message: ToastMessage | null | undefined,
): { text: string; tone: "ok" | "error" } | null {
  if (message == null) return null;
  if (typeof message === "string") {
    return message ? { text: message, tone: "ok" } : null;
  }
  return message.text ? { text: message.text, tone: message.tone } : null;
}
