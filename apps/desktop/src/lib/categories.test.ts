import { describe, expect, it } from "vitest";

import type { ItemKind, ItemSummary } from "./api";
import { categoryCount, filterByCategory } from "./categories";

function item(
  id: string,
  kind: ItemKind,
  overrides: Partial<ItemSummary> = {},
): ItemSummary {
  return {
    id,
    kind,
    title: id,
    subtitle: "",
    letter: id[0]?.toUpperCase() ?? "?",
    host: "",
    folder: "",
    hasTotp: false,
    isDeleted: false,
    modifiedAt: 0,
    ...overrides,
  };
}

const items = [
  item("login", "login"),
  item("code", "login", { hasTotp: true }),
  item("passkey", "passkey"),
  item("wifi", "wifi"),
  item("ssh", "sshKey"),
  item("note", "secureNote"),
  item("bookmark", "bookmark"),
  item("future", "unknown"),
  item("deleted", "login", { isDeleted: true, hasTotp: true }),
];

describe("category filtering", () => {
  it.each([
    [
      "all",
      ["login", "code", "passkey", "wifi", "ssh", "note", "bookmark", "future"],
    ],
    ["passkeys", ["passkey"]],
    ["codes", ["code"]],
    ["wifi", ["wifi"]],
    ["sshKeys", ["ssh"]],
    ["notes", ["note"]],
    ["bookmarks", ["bookmark"]],
    ["deleted", ["deleted"]],
  ] as const)("selects the %s category", (category, expected) => {
    expect(filterByCategory(items, category).map(({ id }) => id)).toEqual(
      expected,
    );
    expect(categoryCount(items, category)).toBe(expected.length);
  });

  it("leaves Security to the separately returned security report", () => {
    expect(filterByCategory(items, "security")).toEqual([]);
  });
});
