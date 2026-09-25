import type { ItemSummary } from "./api";

export type CategoryId =
  | "all"
  | "passkeys"
  | "codes"
  | "wifi"
  | "sshKeys"
  | "notes"
  | "bookmarks"
  | "security"
  | "deleted";

export interface CategoryDef {
  id: CategoryId;
  label: string;
}

export const CATEGORIES: CategoryDef[] = [
  { id: "all", label: "All" },
  { id: "passkeys", label: "Passkeys" },
  { id: "codes", label: "Codes" },
  { id: "wifi", label: "Wi-Fi" },
  { id: "sshKeys", label: "SSH Keys" },
  { id: "notes", label: "Notes" },
  { id: "bookmarks", label: "Bookmarks" },
  { id: "security", label: "Security" },
  { id: "deleted", label: "Deleted" },
];

/** Items shown for a category. Security is resolved with its separate report. */
export function filterByCategory(
  items: ItemSummary[],
  cat: CategoryId,
): ItemSummary[] {
  switch (cat) {
    case "all":
      return items.filter((i) => !i.isDeleted);
    case "passkeys":
      return items.filter((i) => !i.isDeleted && i.kind === "passkey");
    case "codes":
      return items.filter((i) => !i.isDeleted && i.hasTotp);
    case "wifi":
      return items.filter((i) => !i.isDeleted && i.kind === "wifi");
    case "sshKeys":
      return items.filter((i) => !i.isDeleted && i.kind === "sshKey");
    case "notes":
      return items.filter((i) => !i.isDeleted && i.kind === "secureNote");
    case "bookmarks":
      return items.filter((i) => !i.isDeleted && i.kind === "bookmark");
    case "security":
      // Security issues are returned separately from item summaries; App joins
      // the report to the items so breach results can be included as well.
      return [];
    case "deleted":
      return items.filter((i) => i.isDeleted);
  }
}

export function categoryCount(items: ItemSummary[], cat: CategoryId): number {
  return filterByCategory(items, cat).length;
}
