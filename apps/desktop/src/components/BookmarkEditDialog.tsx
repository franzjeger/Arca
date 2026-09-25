import { Dialog } from "./Dialog";
import { useEffect, useId, useState } from "react";
import { api, errorMessage } from "../lib/api";
import { BookmarkIcon } from "./icons";
import { clearDraft, draftKey, useDraft } from "../lib/drafts";

/** Create or edit a bookmark, with suggestions from existing folder paths. */
export function BookmarkEditDialog({
  itemId,
  folders,
  onClose,
  onSaved,
}: {
  itemId: string | null;
  folders: string[];
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const folderListId = useId();
  const [title, setTitle] = useState("");
  const [url, setUrl] = useState("");
  const [folder, setFolder] = useState("");
  const [notes, setNotes] = useState("");
  const key = draftKey("bookmark", itemId);
  // Scoped to this unlocked session; locking discards the draft.
  const restored = useDraft(key, { title, url, folder, notes }, (d) => {
    setTitle(d.title);
    setUrl(d.url);
    setFolder(d.folder);
    setNotes(d.notes);
  });
  const [loading, setLoading] = useState(itemId !== null && !restored);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    // Closing IS a decision to discard. Only a lock is not.
    clearDraft(key);
    onClose();
  };

  useEffect(() => {
    // A restored draft is newer than the file; refetching would overwrite the
    // user's unsaved edits with what is still on disk.
    if (restored) return;
    if (itemId === null) {
      setLoading(false);
      return;
    }
    let alive = true;
    api
      .getItem(itemId)
      .then((detail) => {
        if (!alive) return;
        if (detail.kind !== "bookmark") {
          throw new Error("This item is not a bookmark.");
        }
        setTitle(detail.title);
        setUrl(detail.url);
        setFolder(detail.folder);
        setNotes(detail.notes);
      })
      .catch((cause) => alive && setError(errorMessage(cause)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [itemId, restored]);

  const save = async () => {
    if (!url.trim()) {
      setError("Enter a web address.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const id = await api.upsertBookmark({
        id: itemId,
        title,
        url,
        folder,
        notes,
      });
      clearDraft(key);
      onSaved(id);
    } catch (cause) {
      setError(errorMessage(cause));
      setSaving(false);
    }
  };

  return (
    <Dialog label="Bookmark" onClose={close} dismissible={!saving}>
      <div className="flex max-h-[85vh] w-full max-w-lg flex-col rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <BookmarkIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            {itemId === null ? "New bookmark" : "Edit bookmark"}
          </h2>
        </div>

        <p className="px-5 pt-3 text-xs text-neutral-400">
          Locking discards unsaved changes. Save before switching apps if lock-on-blur is enabled.
        </p>

        {loading ? (
          <div className="px-5 py-10 text-center text-[13px] text-neutral-500">
            Loading…
          </div>
        ) : (
          <div className="flex min-h-0 flex-1 flex-col gap-3 px-5 py-4">
            <input
              value={title}
              autoFocus
              placeholder="Title (defaults to the website)"
              onChange={(event) => setTitle(event.target.value)}
              className="w-full rounded-lg bg-fill/5 px-3 py-2 text-[14px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
            />
            <input
              value={url}
              inputMode="url"
              placeholder="https://example.com"
              onChange={(event) => setUrl(event.target.value)}
              className="w-full rounded-lg bg-fill/5 px-3 py-2 text-[14px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
              spellCheck={false}
            />
            <div>
              <input
                value={folder}
                list={folderListId}
                placeholder="Folder, e.g. Work/Projects (optional)"
                onChange={(event) => setFolder(event.target.value)}
                className="w-full rounded-lg bg-fill/5 px-3 py-2 text-[14px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
                spellCheck={false}
              />
              <datalist id={folderListId}>
                {folders.map((known) => (
                  <option key={known} value={known} />
                ))}
              </datalist>
              <p className="mt-1.5 text-[11px] text-neutral-500">
                Choose an existing folder or type a new path using “/”.
              </p>
            </div>
            <textarea
              value={notes}
              placeholder="Notes (optional)"
              onChange={(event) => setNotes(event.target.value)}
              className="min-h-[110px] resize-none rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
            />
            {error && <p className="text-[12px] text-red-400">{error}</p>}
          </div>
        )}

        <div className="flex shrink-0 justify-end gap-2 border-t border-hairline px-5 py-3">
          <button
            onClick={close}
            className="rounded-lg px-4 py-1.5 text-[13px] text-neutral-300 hover:bg-fill/5"
          >
            Cancel
          </button>
          <button
            onClick={() => void save()}
            disabled={saving || loading}
            className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </Dialog>
  );
}
