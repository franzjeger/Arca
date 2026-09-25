import { SyncConflictsDialog } from "./SyncConflictsDialog";
import { SettingsDialog } from "./SettingsDialog";
import { SshKeyDialog } from "./SshKeyDialog";
import { NoteEditDialog } from "./NoteEditDialog";
import { WifiEditDialog } from "./WifiEditDialog";
import { BookmarkEditDialog } from "./BookmarkEditDialog";
import { EditDialog } from "./EditDialog";
import { BookmarkMoveDialog } from "./BookmarkMoveDialog";
import { ConsentDialog } from "./ConsentDialog";
import { PasskeyChoiceDialog } from "./PasskeyChoiceDialog";
import { PasskeyVerifyDialog } from "./PasskeyVerifyDialog";
import { Toast } from "./Toast";
import type { EditorKind } from "../lib/editing";
import type { FillConsent, PasskeyChoiceRequest, PasskeyVerifyRequest, ItemSummary, VaultStatus } from "../lib/api";
import type { ToastMessage } from "../lib/toast";

export type Editor = { id: string | null; kind: EditorKind | "ssh" };

interface AppDialogsProps {
  items: ItemSummary[];
  status: VaultStatus;
  refreshStatus: () => void;
  loadItems: () => Promise<void>;
  setToast: (toast: ToastMessage | null) => void;
  setSelectedId: (id: string | null) => void;
  setDetail: (detail: any) => void;
  clearSelection: () => void;

  conflictsOpen: boolean;
  setConflictsOpen: (open: boolean) => void;

  settingsOpen: boolean;
  setSettingsOpen: (open: boolean) => void;

  editing: Editor | null;
  setEditing: (editor: Editor | null) => void;
  handleSaved: (id: string) => Promise<void>;

  bookmarkFolders: string[];
  movingBookmarks: string[] | null;
  setMovingBookmarks: (ids: string[] | null) => void;

  consent: FillConsent | null;
  setConsent: (consent: FillConsent | null) => void;

  passkeyChoice: PasskeyChoiceRequest | null;
  setPasskeyChoice: (choice: PasskeyChoiceRequest | null) => void;

  passkeyVerify: PasskeyVerifyRequest | null;
  setPasskeyVerify: (verify: PasskeyVerifyRequest | null) => void;

  toast: ToastMessage | null;
}

export function AppDialogs({
  items, status, refreshStatus, loadItems, setToast, setSelectedId, setDetail, clearSelection,
  conflictsOpen, setConflictsOpen,
  settingsOpen, setSettingsOpen,
  editing, setEditing, handleSaved,
  bookmarkFolders, movingBookmarks, setMovingBookmarks,
  consent, setConsent,
  passkeyChoice, setPasskeyChoice,
  passkeyVerify, setPasskeyVerify,
  toast
}: AppDialogsProps) {
  return (
    <>
      {conflictsOpen && (
        <SyncConflictsDialog
          items={items}
          onClose={() => setConflictsOpen(false)}
          onResolved={async (action) => {
            setSelectedId(null);
            setDetail(null);
            await loadItems();
            setToast(
              action === "keepCopy"
                ? "Conflict copy kept as a separate entry."
                : action === "keepBoth"
                  ? "Both entries kept separately."
                  : "Conflict resolved. Previous entries are available in Trash."
            );
          }}
        />
      )}
      {settingsOpen && (
        <SettingsDialog
          status={status}
          onClose={() => setSettingsOpen(false)}
          onStatusChanged={refreshStatus}
          onToast={setToast}
        />
      )}
      {editing &&
        (editing.kind === "ssh" ? (
          <SshKeyDialog
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ) : editing.kind === "note" ? (
          <NoteEditDialog
            itemId={editing.id}
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ) : editing.kind === "wifi" ? (
          <WifiEditDialog
            itemId={editing.id}
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ) : editing.kind === "bookmark" ? (
          <BookmarkEditDialog
            itemId={editing.id}
            folders={bookmarkFolders}
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ) : (
          <EditDialog
            itemId={editing.id}
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ))}
      {movingBookmarks && (
        <BookmarkMoveDialog
          ids={movingBookmarks}
          folders={bookmarkFolders}
          onClose={() => setMovingBookmarks(null)}
          onMoved={(count) => {
            setMovingBookmarks(null);
            clearSelection();
            setToast(
              count === 0
                ? "Bookmarks already in that folder"
                : `Moved ${count} bookmark${count === 1 ? "" : "s"}`,
            );
            void loadItems();
          }}
        />
      )}
      {consent && (
        <ConsentDialog
          request={consent}
          onResolved={() => setConsent(null)}
          onToast={setToast}
        />
      )}
      {passkeyChoice && (
        <PasskeyChoiceDialog
          key={passkeyChoice.id}
          request={passkeyChoice}
          onResolved={() => setPasskeyChoice(null)}
          onToast={setToast}
        />
      )}
      {passkeyVerify && (
        <PasskeyVerifyDialog
          request={passkeyVerify}
          onResolved={() => setPasskeyVerify(null)}
          onToast={setToast}
        />
      )}
      <Toast message={toast} onDone={() => setToast(null)} />
    </>
  );
}
