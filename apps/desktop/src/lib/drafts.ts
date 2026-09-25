import { useEffect, useRef, useState } from "react";

/// Unsaved editor contents for the current unlocked session only. Never written
/// to disk. Save, cancel and vault lock discard drafts. Releasing references
/// reduces retention but cannot guarantee erasure of immutable JS strings.
const drafts = new Map<string, unknown>();
let generation = 0;

/** Key for one editor's draft. `null` id means a new item. */
export function draftKey(kind: string, itemId: string | null): string {
  return `${kind}:${itemId ?? "new"}`;
}

export function clearDraft(key: string): void {
  drafts.delete(key);
}

/** Forget every draft on lock/sign-out and invalidate still-mounted editors. */
export function clearAllDrafts(): void {
  generation += 1;
  drafts.clear();
}

export function hasDraft(key: string): boolean {
  return drafts.has(key);
}

/// Mirror an editor's form into the draft store, and restore it on mount.
///
/// Returns whether a draft was restored, which the caller uses to skip its
/// initial load — refetching would overwrite the user's edits with what is
/// still on disk.
export function useDraft<T extends object>(
  key: string,
  value: T,
  restore: (draft: T) => void,
): boolean {
  const session = useRef(generation);
  // Read on the FIRST render, not in an effect: the caller needs to know
  // before it decides whether to fetch.
  const [restored] = useState(() => drafts.has(key));

  const restoreRef = useRef(restore);
  restoreRef.current = restore;

  useEffect(() => {
    if (session.current !== generation) return;
    const draft = drafts.get(key) as T | undefined;
    if (draft) restoreRef.current(draft);
    // Mount only: re-running would clobber live edits with the stored copy.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  // Skip the first commit. `value` is still the empty form there — restore's
  // setState has been queued but not applied — so writing it would destroy the
  // very draft we are about to put back.
  const settled = useRef(false);
  useEffect(() => {
    // A queued effect from before the lock must not resurrect a cleared draft.
    if (session.current !== generation) return;
    if (!settled.current) {
      settled.current = true;
      return;
    }
    drafts.set(key, value);
  });

  return restored;
}
