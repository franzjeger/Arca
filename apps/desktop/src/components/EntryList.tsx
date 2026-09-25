import { useMemo, useState, type ReactNode } from "react";
import type { ItemSummary, SecurityTag } from "../lib/api";
import { buildBookmarkSections, buildSections } from "../lib/grouping";
import {
  ClockIcon,
  BookmarkIcon,
  ChevronRightIcon,
  FolderIcon,
  NoteIcon,
  PasskeyIcon,
  PlusIcon,
  SshIcon,
  TrashIcon,
  WifiIcon,
} from "./icons";
import { Tile } from "./Tile";

const ISSUE_LABEL: Record<SecurityTag, string> = {
  weak: "Weak",
  reused: "Reused",
  breached: "Breached",
};

/** A small check glyph for the selection checkbox. */
function CheckMark() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-3 w-3"
      fill="none"
      stroke="currentColor"
      strokeWidth="3.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M5 12.5 10 17l9-10" />
    </svg>
  );
}

export function EntryList({
  title,
  items,
  selectedId,
  onSelect,
  onAdd,
  emptyHint,
  banner,
  issuesById,
  selectedIds,
  onToggleSelect,
  onSelectAll,
  onClearSelection,
  onSelectRange,
  isDeletedView,
  onBulkDelete,
  onBulkRestore,
  onBulkPurge,
  onBulkMove,
  structuredBookmarks = false,
}: {
  title: string;
  items: ItemSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onAdd?: () => void;
  emptyHint?: string;
  /** Optional bar shown under the header (e.g. the Security "check breaches"). */
  banner?: ReactNode;
  /** When present (Security view), renders issue badges per item. */
  issuesById?: Map<string, SecurityTag[]>;
  /** Ids currently checked for a bulk action. */
  selectedIds: Set<string>;
  onToggleSelect: (id: string) => void;
  onSelectAll: () => void;
  onClearSelection: () => void;
  /** Replace the whole selection (used for Shift+click range selection). */
  onSelectRange: (ids: string[]) => void;
  /** Deleted (trash) view: bulk actions are Restore + Delete Forever. */
  isDeletedView: boolean;
  onBulkDelete: () => void;
  onBulkRestore: () => void;
  onBulkPurge: () => void;
  /** Move the selected bookmarks to another folder. */
  onBulkMove?: () => void;
  /** Render bookmarks under folder headers, folders first. */
  structuredBookmarks?: boolean;
}) {
  const sections = useMemo(() => buildSections(items), [items]);
  const bookmarkSections = useMemo(
    () => (structuredBookmarks ? buildBookmarkSections(items) : []),
    [items, structuredBookmarks],
  );
  const [collapsedFolders, setCollapsedFolders] = useState<Set<string>>(
    new Set(),
  );
  const selCount = selectedIds.size;
  const selectionActive = selCount > 0;
  const allSelected =
    items.length > 0 && items.every((i) => selectedIds.has(i.id));

  // Flat id list in the exact order rows are rendered (grouped + sorted), so
  // Shift+click can pick a contiguous range.
  const orderedIds = useMemo(
    () =>
      structuredBookmarks
        ? bookmarkSections.flatMap((section) =>
            section.kind === "folder" && collapsedFolders.has(section.folder)
              ? []
              : section.items.map((item) => item.id),
          )
        : sections.flatMap((section) =>
            section.kind === "single"
              ? [section.item.id]
              : section.items.map((item) => item.id),
          ),
    [bookmarkSections, collapsedFolders, sections, structuredBookmarks],
  );
  // Anchor for Shift+range selection: the last row activated by a plain or
  // Ctrl/Cmd click.
  const [anchorId, setAnchorId] = useState<string | null>(null);

  // A left-click on a row: plain = open detail (and reset the selection),
  // Ctrl/Cmd = toggle this row, Shift = select the range from the anchor.
  const activateRow = (id: string, e: React.MouseEvent) => {
    if (e.shiftKey) {
      const anchor = anchorId ?? selectedId;
      const a = anchor ? orderedIds.indexOf(anchor) : -1;
      const b = orderedIds.indexOf(id);
      if (a !== -1 && b !== -1) {
        const [lo, hi] = a < b ? [a, b] : [b, a];
        onSelectRange(orderedIds.slice(lo, hi + 1));
        return;
      }
    }
    if (e.ctrlKey || e.metaKey) {
      onToggleSelect(id);
      setAnchorId(id);
      return;
    }
    // Plain click: single-select for the detail pane, clear any multi-selection.
    if (selectionActive) onClearSelection();
    setAnchorId(id);
    onSelect(id);
  };

  return (
    <div className="flex w-[340px] shrink-0 flex-col border-r border-hairline bg-panel">
      <div className="flex h-12 items-center justify-between px-4">
        <h2 className="text-[15px] font-bold text-neutral-100">{title}</h2>
        {onAdd && (
          <button
            onClick={onAdd}
            className="rounded-md p-1 text-accent hover:bg-fill/5"
            title="Add item"
          >
            <PlusIcon className="h-5 w-5" />
          </button>
        )}
      </div>

      {banner}

      {/* Bulk-action bar: appears once one or more items are checked. */}
      {selectionActive && (
        <div className="flex items-center gap-2 border-y border-hairline bg-fill/[0.03] px-3 py-2 text-[12px]">
          <span className="font-semibold text-neutral-100">
            {selCount} selected
          </span>
          <button
            onClick={onSelectAll}
            className="text-accent hover:underline"
            title="Select or clear all items in this view"
          >
            {allSelected ? "Clear all" : "Select all"}
          </button>
          <button
            onClick={onClearSelection}
            className="text-neutral-400 hover:text-neutral-200"
          >
            Cancel
          </button>
          <div className="ml-auto flex items-center gap-1.5">
            {isDeletedView ? (
              <>
                <button
                  onClick={onBulkRestore}
                  className="rounded-md border border-hairline px-2.5 py-1 text-neutral-200 hover:bg-fill/5"
                >
                  Restore
                </button>
                <button
                  onClick={onBulkPurge}
                  className="rounded-md border border-red-500/40 px-2.5 py-1 text-red-400 hover:bg-red-500/10"
                >
                  Delete Forever
                </button>
              </>
            ) : (
              <>
                {structuredBookmarks && onBulkMove && (
                  <button
                    onClick={onBulkMove}
                    className="rounded-md border border-hairline px-2.5 py-1 text-neutral-200 hover:bg-fill/5"
                  >
                    Move…
                  </button>
                )}
                <button
                  onClick={onBulkDelete}
                  className="flex items-center gap-1.5 rounded-md border border-red-500/40 px-2.5 py-1 text-red-400 hover:bg-red-500/10"
                >
                  <TrashIcon className="h-3.5 w-3.5" />
                  Delete
                </button>
              </>
            )}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto px-2 pb-2">
        {items.length === 0 ? (
          <p className="px-3 py-8 text-center text-[13px] text-neutral-500">
            {emptyHint ?? "No items"}
          </p>
        ) : structuredBookmarks ? (
          bookmarkSections.map((section) => {
            const collapsed =
              section.kind === "folder" && collapsedFolders.has(section.folder);
            const key =
              section.kind === "folder" ? `folder:${section.folder}` : "loose";
            return (
              <div key={key} className="mt-1">
                {section.kind === "folder" ? (
                  <button
                    type="button"
                    aria-expanded={!collapsed}
                    onClick={() =>
                      setCollapsedFolders((current) => {
                        const next = new Set(current);
                        if (next.has(section.folder))
                          next.delete(section.folder);
                        else next.add(section.folder);
                        return next;
                      })
                    }
                    className="flex w-full items-center gap-1.5 rounded-md px-2 pb-0.5 pt-2 text-left text-[11px] font-semibold uppercase tracking-wide text-neutral-500 hover:bg-fill/5 hover:text-neutral-300"
                  >
                    <ChevronRightIcon
                      className={`h-3 w-3 shrink-0 transition-transform ${
                        collapsed ? "" : "rotate-90"
                      }`}
                    />
                    <FolderIcon className="h-3.5 w-3.5 shrink-0" />
                    <span className="min-w-0 flex-1 truncate">
                      {section.folder}
                    </span>
                    <span className="shrink-0 pl-2 text-neutral-600">
                      {section.items.length}
                    </span>
                  </button>
                ) : (
                  <div className="flex items-center gap-1.5 px-2 pb-0.5 pt-2 text-[11px] font-semibold uppercase tracking-wide text-neutral-500">
                    <BookmarkIcon className="h-3.5 w-3.5 shrink-0" />
                    <span className="min-w-0 flex-1 truncate">
                      Loose bookmarks
                    </span>
                    <span className="shrink-0 pl-2 text-neutral-600">
                      {section.items.length}
                    </span>
                  </div>
                )}
                {!collapsed && (
                  <div className="border-l border-hairline pl-1.5">
                    {section.items.map((item) => (
                      <Row
                        key={item.id}
                        item={item}
                        isSel={item.id === selectedId}
                        onActivate={activateRow}
                        issuesById={issuesById}
                        checked={selectedIds.has(item.id)}
                        onToggleSelect={onToggleSelect}
                        selectionActive={selectionActive}
                      />
                    ))}
                  </div>
                )}
              </div>
            );
          })
        ) : (
          sections.map((section) =>
            section.kind === "single" ? (
              <Row
                key={section.item.id}
                item={section.item}
                isSel={section.item.id === selectedId}
                onActivate={activateRow}
                issuesById={issuesById}
                checked={selectedIds.has(section.item.id)}
                onToggleSelect={onToggleSelect}
                selectionActive={selectionActive}
              />
            ) : (
              <div key={`host:${section.host}`} className="mt-1">
                <div className="flex items-baseline justify-between px-2 pb-0.5 pt-2">
                  <span className="truncate text-[11px] font-semibold uppercase tracking-wide text-neutral-500">
                    {section.host}
                  </span>
                  <span className="shrink-0 pl-2 text-[11px] text-neutral-600">
                    {section.items.length} accounts
                  </span>
                </div>
                <div className="border-l border-hairline pl-1.5">
                  {section.items.map((item) => (
                    <Row
                      key={item.id}
                      item={item}
                      isSel={item.id === selectedId}
                      onActivate={activateRow}
                      issuesById={issuesById}
                      checked={selectedIds.has(item.id)}
                      onToggleSelect={onToggleSelect}
                      selectionActive={selectionActive}
                    />
                  ))}
                </div>
              </div>
            ),
          )
        )}
      </div>
    </div>
  );
}

function Row({
  item,
  isSel,
  onActivate,
  issuesById,
  checked,
  onToggleSelect,
  selectionActive,
}: {
  item: ItemSummary;
  isSel: boolean;
  onActivate: (id: string, e: React.MouseEvent) => void;
  issuesById?: Map<string, SecurityTag[]>;
  checked: boolean;
  onToggleSelect: (id: string) => void;
  selectionActive: boolean;
}) {
  return (
    <div
      className={`group flex w-full items-center gap-1.5 rounded-lg pr-2 transition-colors ${
        isSel ? "bg-accent/90" : "hover:bg-fill/5"
      }`}
    >
      {/* Checkbox: hidden until row hover, forced visible once a selection is
          active or this row is checked. Stops propagation so ticking a box
          never changes the detail-pane selection. */}
      <button
        onClick={(e) => {
          e.stopPropagation();
          onToggleSelect(item.id);
        }}
        title={checked ? "Deselect" : "Select"}
        aria-pressed={checked}
        className={`ml-1 flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-[5px] border transition ${
          checked
            ? "border-accent bg-accent text-white"
            : isSel
              ? "border-white/60 text-white"
              : "border-neutral-600 text-transparent"
        } ${
          checked || selectionActive
            ? "opacity-100"
            : "opacity-0 group-hover:opacity-100"
        }`}
      >
        {checked && <CheckMark />}
      </button>

      <button
        onClick={(e) => onActivate(item.id, e)}
        className="flex min-w-0 flex-1 select-none items-center gap-3 py-2 text-left"
      >
        <Tile letter={item.letter} seed={item.title || item.id} />
        <div className="min-w-0 flex-1">
          <div
            className={`truncate text-[13px] font-semibold ${
              isSel ? "text-white" : "text-neutral-100"
            }`}
          >
            {item.title || "Untitled"}
          </div>
          {item.subtitle && (
            <div
              className={`truncate text-[12px] ${
                isSel ? "text-white/80" : "text-neutral-500"
              }`}
            >
              {item.subtitle}
            </div>
          )}
          {(item.kind === "passkey" ||
            (issuesById && issuesById.get(item.id))) && (
            <div className="mt-1 flex flex-wrap gap-1">
              {item.kind === "passkey" && (
                <span
                  className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                    isSel
                      ? "bg-white/20 text-white"
                      : "bg-accent/15 text-accent"
                  }`}
                >
                  Passkey
                </span>
              )}
              {(issuesById?.get(item.id) ?? []).map((tag) => (
                <span
                  key={tag}
                  className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                    isSel
                      ? "bg-white/20 text-white"
                      : tag === "breached"
                        ? "bg-red-500/15 text-red-400"
                        : "bg-amber-500/15 text-amber-400"
                  }`}
                >
                  {ISSUE_LABEL[tag]}
                </span>
              ))}
            </div>
          )}
        </div>
        <div
          className={`flex items-center gap-1.5 ${
            isSel ? "text-white/80" : "text-neutral-600"
          }`}
        >
          {item.hasTotp && <ClockIcon className="h-4 w-4" />}
          {item.kind === "passkey" && <PasskeyIcon className="h-4 w-4" />}
          {item.kind === "wifi" && <WifiIcon className="h-4 w-4" />}
          {item.kind === "sshKey" && <SshIcon className="h-4 w-4" />}
          {item.kind === "secureNote" && <NoteIcon className="h-4 w-4" />}
          {item.kind === "bookmark" && <BookmarkIcon className="h-4 w-4" />}
        </div>
      </button>
    </div>
  );
}
