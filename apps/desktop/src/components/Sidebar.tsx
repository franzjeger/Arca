import type { ComponentType } from "react";
import { CATEGORIES, type CategoryId } from "../lib/categories";
import {
  BookmarkIcon,
  ClockIcon,
  GearIcon,
  KeyIcon,
  LockOpenIcon,
  PasskeyIcon,
  SearchIcon,
  NoteIcon,
  ShieldIcon,
  SshIcon,
  TrashIcon,
  WifiIcon,
} from "./icons";

const ICONS: Record<CategoryId, ComponentType<{ className?: string }>> = {
  all: KeyIcon,
  passkeys: PasskeyIcon,
  codes: ClockIcon,
  wifi: WifiIcon,
  sshKeys: SshIcon,
  notes: NoteIcon,
  bookmarks: BookmarkIcon,
  security: ShieldIcon,
  deleted: TrashIcon,
};

export function Sidebar({
  counts,
  active,
  onSelect,
  search,
  onSearch,
  onLock,
  onOpenSettings,
}: {
  counts: Record<CategoryId, number>;
  active: CategoryId;
  onSelect: (c: CategoryId) => void;
  search: string;
  onSearch: (s: string) => void;
  onLock: () => void;
  onOpenSettings: () => void;
}) {
  return (
    <div className="flex w-60 shrink-0 flex-col border-r border-hairline bg-sidebar">
      <div className="px-3 pt-3">
        <div className="flex items-center gap-2 rounded-lg bg-fill/5 px-2.5 py-1.5 text-neutral-300 focus-within:ring-1 focus-within:ring-accent/60">
          <SearchIcon className="h-4 w-4 text-neutral-500" />
          <input
            value={search}
            onChange={(e) => onSearch(e.target.value)}
            placeholder="Search"
            className="w-full bg-transparent text-[13px] text-neutral-100 placeholder-neutral-500 outline-none"
            spellCheck={false}
          />
        </div>
      </div>

      <nav className="mt-3 flex-1 space-y-0.5 overflow-y-auto px-2">
        {CATEGORIES.map((c) => {
          const Icon = ICONS[c.id];
          const count = counts[c.id] ?? 0;
          const isActive = c.id === active;
          const showCount = c.id !== "deleted" && count > 0;
          return (
            <button
              key={c.id}
              onClick={() => onSelect(c.id)}
              className={`flex w-full items-center gap-3 rounded-lg px-2.5 py-1.5 text-[13px] transition-colors ${
                isActive
                  ? "bg-accent text-white"
                  : "text-neutral-300 hover:bg-fill/5"
              }`}
            >
              <Icon
                className={`h-[18px] w-[18px] ${
                  isActive ? "text-white" : "text-accent"
                }`}
              />
              <span className="flex-1 text-left font-medium">{c.label}</span>
              {showCount && (
                <span
                  className={`text-[12px] tabular-nums ${
                    isActive ? "text-white/80" : "text-neutral-500"
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="space-y-2 border-t border-hairline p-3">
        <div className="flex items-center justify-between">
          <button
            onClick={onLock}
            className="no-drag flex items-center gap-2 text-[12px] font-medium text-green-400 hover:text-green-300"
            title="Lock vault"
          >
            <LockOpenIcon className="h-4 w-4" />
            Unlocked
          </button>
          <button
            onClick={onOpenSettings}
            className="no-drag rounded-md p-1 text-neutral-400 hover:bg-fill/5 hover:text-neutral-200"
            title="Settings"
          >
            <GearIcon className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
