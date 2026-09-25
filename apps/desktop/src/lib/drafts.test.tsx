import { renderHook } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { clearAllDrafts, draftKey, hasDraft, useDraft } from "./drafts";

beforeEach(clearAllDrafts);

it("invalidates every editor kind and rejects writes from the previous session", () => {
  const keys = ["login", "wifi", "note", "bookmark"].map((kind) => draftKey(kind, null));
  const editors = keys.map((key) => renderHook(
    ({ secret }) => useDraft(key, { secret }, vi.fn()),
    { initialProps: { secret: "" } },
  ));
  editors.forEach((editor) => editor.rerender({ secret: "unsaved-secret" }));
  keys.forEach((key) => expect(hasDraft(key)).toBe(true));

  clearAllDrafts();
  keys.forEach((key) => expect(hasDraft(key)).toBe(false));
  // Simulate an async result/queued render before the old editors unmount.
  editors.forEach((editor) => editor.rerender({ secret: "late-secret" }));
  keys.forEach((key) => expect(hasDraft(key)).toBe(false));
  editors.forEach((editor) => editor.unmount());

  const restore = vi.fn();
  const next = renderHook(({ secret }) => useDraft(keys[0], { secret }, restore), {
    initialProps: { secret: "" },
  });
  expect(next.result.current).toBe(false);
  expect(restore).not.toHaveBeenCalled();
  next.rerender({ secret: "new-session-secret" });
  expect(hasDraft(keys[0])).toBe(true);
});
