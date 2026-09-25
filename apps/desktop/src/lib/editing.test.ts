import { describe, expect, it } from "vitest";
import type { ItemKind } from "./api";
import { editorKindForItemKind } from "./editing";

describe("item editor routing", () => {
  it.each<[ItemKind, string | null]>([
    ["login", "login"],
    ["wifi", "wifi"],
    ["secureNote", "note"],
    ["passkey", null],
    ["sshKey", null],
    ["bookmark", "bookmark"],
    ["unknown", null],
  ])("routes %s without falling through", (kind, expected) => {
    expect(editorKindForItemKind(kind)).toBe(expected);
  });
});
