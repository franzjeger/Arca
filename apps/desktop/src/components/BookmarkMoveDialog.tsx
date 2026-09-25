import { Dialog } from "./Dialog";
import { useId, useState } from "react";
import { api, errorMessage } from "../lib/api";
import { FolderIcon } from "./icons";

export function BookmarkMoveDialog({
  ids,
  folders,
  onClose,
  onMoved,
}: {
  ids: string[];
  folders: string[];
  onClose: () => void;
  onMoved: (count: number) => void;
}) {
  const folderListId = useId();
  const [folder, setFolder] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const move = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      onMoved(await api.moveBookmarks(ids, folder));
    } catch (cause) {
      setError(errorMessage(cause));
      setBusy(false);
    }
  };

  return (
    <Dialog label="Move bookmarks" onClose={onClose}>
      <div className="w-full max-w-md rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <FolderIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            Move {ids.length} bookmark{ids.length === 1 ? "" : "s"}
          </h2>
        </div>
        <div className="px-5 py-4">
          <input
            autoFocus
            value={folder}
            list={folderListId}
            placeholder="Folder path (blank = top level)"
            onChange={(event) => setFolder(event.target.value)}
            onKeyDown={(event) => event.key === "Enter" && void move()}
            className="w-full rounded-lg bg-fill/5 px-3 py-2 text-[14px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
            spellCheck={false}
          />
          <datalist id={folderListId}>
            {folders.map((known) => (
              <option key={known} value={known} />
            ))}
          </datalist>
          <p className="mt-2 text-[11px] text-neutral-500">
            Choose a folder, type a new “/”-separated path, or leave it blank to
            move the bookmarks to the top level.
          </p>
          {error && <p className="mt-2 text-[12px] text-red-400">{error}</p>}
        </div>
        <div className="flex justify-end gap-2 border-t border-hairline px-5 py-3">
          <button
            onClick={onClose}
            className="rounded-lg px-4 py-1.5 text-[13px] text-neutral-300 hover:bg-fill/5"
          >
            Cancel
          </button>
          <button
            onClick={() => void move()}
            disabled={busy}
            className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
          >
            {busy ? "Moving…" : "Move"}
          </button>
        </div>
      </div>
    </Dialog>
  );
}
