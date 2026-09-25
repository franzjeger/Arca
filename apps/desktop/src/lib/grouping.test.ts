import { describe, expect, it } from "vitest";
import type { ItemSummary } from "./api";
import { buildBookmarkSections, displayOrder } from "./grouping";

const bookmark = (id: string, title: string, folder = ""): ItemSummary => ({
  id,
  kind: "bookmark",
  title,
  subtitle: folder,
  letter: title[0] ?? "?",
  host: "example.com",
  folder,
  hasTotp: false,
  isDeleted: false,
  modifiedAt: 0,
});

describe("bookmark grouping", () => {
  it("sorts folders first and loose bookmarks last", () => {
    const sections = buildBookmarkSections([
      bookmark("loose-z", "Zulu"),
      bookmark("work-b", "Beta", "Work"),
      bookmark("personal", "Alpha", "Personal/Travel"),
      bookmark("work-a", "alpha", "/ Work /"),
      bookmark("loose-a", "Alpha"),
    ]);

    expect(
      sections.map((s) => (s.kind === "folder" ? s.folder : "loose")),
    ).toEqual(["Personal/Travel", "Work", "loose"]);
    expect(sections.map((s) => s.items.map((i) => i.id))).toEqual([
      ["personal"],
      ["work-a", "work-b"],
      ["loose-a", "loose-z"],
    ]);
  });

  it("uses the same folder-first order for selection", () => {
    const items = [
      bookmark("loose", "A loose"),
      bookmark("folder", "Z filed", "Folder"),
    ];
    expect(displayOrder(items, true).map((item) => item.id)).toEqual([
      "folder",
      "loose",
    ]);
  });
});
