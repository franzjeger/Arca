import type { ItemKind } from "./api";

/** Editors that can safely round-trip an existing vault item today. */
export type EditorKind = "login" | "wifi" | "note" | "bookmark";

/**
 * Keep item-to-editor routing in one exhaustive, testable place. Returning
 * `null` is deliberate: unsupported and forward-compatible item types must
 * never fall through to the login editor.
 */
export function editorKindForItemKind(kind: ItemKind): EditorKind | null {
  switch (kind) {
    case "login":
      return "login";
    case "wifi":
      return "wifi";
    case "secureNote":
      return "note";
    case "bookmark":
      return "bookmark";
    case "passkey":
    case "sshKey":
    case "unknown":
      return null;
  }
}
