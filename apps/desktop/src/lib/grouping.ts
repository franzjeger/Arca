import type { ItemSummary } from "./api";

/** One rendered unit: a lone entry, or entries sharing the same website. */
export type Section =
  | { kind: "single"; item: ItemSummary }
  | { kind: "group"; host: string; items: ItemSummary[] };

/** Bookmark folders are rendered before bookmarks without a folder. */
export type BookmarkSection =
  | { kind: "folder"; folder: string; items: ItemSummary[] }
  | { kind: "loose"; items: ItemSummary[] };

const collate = (a: string, b: string) =>
  a.localeCompare(b, undefined, { sensitivity: "base" });

/**
 * Group entries that share a normalized website host (2+ members) under a
 * site header; everything else stays a plain row. Sections are sorted
 * alphabetically by their label (host or title), members by title.
 *
 * This is the single source of display order: both the list rendering
 * (EntryList) and the auto-selection logic (App) must derive from it so the
 * highlighted item is always the visually first row.
 */
export function buildSections(items: ItemSummary[]): Section[] {
  const byHost = new Map<string, ItemSummary[]>();
  for (const it of items) {
    if (!it.host) continue;
    byHost.set(it.host, [...(byHost.get(it.host) ?? []), it]);
  }

  const sections: Section[] = [];
  const emittedHosts = new Set<string>();
  for (const it of items) {
    const members = it.host ? byHost.get(it.host) : undefined;
    if (members && members.length >= 2) {
      if (emittedHosts.has(it.host)) continue;
      emittedHosts.add(it.host);
      sections.push({
        kind: "group",
        host: it.host,
        items: [...members].sort((a, b) => collate(a.title, b.title)),
      });
    } else {
      sections.push({ kind: "single", item: it });
    }
  }

  const label = (s: Section) =>
    s.kind === "group" ? s.host : s.item.title || s.item.subtitle;
  return sections.sort((a, b) => collate(label(a), label(b)));
}

export const normalizedFolder = (folder: string) =>
  folder
    .split("/")
    .map((part) => part.trim())
    .filter(Boolean)
    .join("/");

/**
 * Build the dedicated bookmark view. Folder sections are sorted by their full
 * path and always precede loose bookmarks; members are sorted by title.
 */
export function buildBookmarkSections(items: ItemSummary[]): BookmarkSection[] {
  const byFolder = new Map<string, ItemSummary[]>();
  const loose: ItemSummary[] = [];

  for (const item of items) {
    const folder = normalizedFolder(item.folder);
    if (!folder) {
      loose.push(item);
      continue;
    }
    byFolder.set(folder, [...(byFolder.get(folder) ?? []), item]);
  }

  const sections: BookmarkSection[] = [...byFolder.entries()]
    .sort(([a], [b]) => collate(a, b))
    .map(([folder, members]) => ({
      kind: "folder" as const,
      folder,
      items: [...members].sort((a, b) =>
        collate(a.title || a.host, b.title || b.host),
      ),
    }));

  if (loose.length) {
    sections.push({
      kind: "loose",
      items: loose.sort((a, b) =>
        collate(a.title || a.host, b.title || b.host),
      ),
    });
  }
  return sections;
}

/** The items exactly as displayed, top to bottom. */
export function displayOrder(
  items: ItemSummary[],
  structuredBookmarks = false,
): ItemSummary[] {
  if (structuredBookmarks) {
    return buildBookmarkSections(items).flatMap((section) => section.items);
  }
  return buildSections(items).flatMap((s) =>
    s.kind === "single" ? [s.item] : s.items,
  );
}
