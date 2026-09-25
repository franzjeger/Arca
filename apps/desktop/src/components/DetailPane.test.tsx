import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ItemDetail, ItemKind } from "../lib/api";
import { DetailPane } from "./DetailPane";

vi.mock("../lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: {
      sshPublicKey: vi.fn().mockResolvedValue({
        authorizedKey: "ssh-ed25519 public",
        fingerprint: "SHA256:test",
        comment: "test",
      }),
      sshAgentInfo: vi.fn().mockResolvedValue({
        socket: "",
        available: false,
      }),
    },
  };
});

const detail = (kind: ItemKind): ItemDetail => ({
  id: "00000000-0000-0000-0000-000000000001",
  kind,
  title: "Example",
  username: "",
  url: kind === "bookmark" ? "https://example.com/" : "",
  notes: "",
  hasPassword: false,
  hasTotp: false,
  passwordStrength: null,
  isDeleted: false,
  createdAt: 1,
  modifiedAt: 1,
  ssid: "",
  security: "",
  hidden: false,
  folder: kind === "bookmark" ? "Work" : "",
});

describe("DetailPane editor safety", () => {
  it.each<ItemKind>(["passkey", "sshKey", "unknown"])(
    "does not offer the login editor for %s items",
    async (kind) => {
      render(
        <DetailPane
          detail={detail(kind)}
          onEdit={vi.fn()}
          onChanged={vi.fn()}
          onCopy={vi.fn()}
        />,
      );
      expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
      if (kind === "sshKey") {
        await screen.findByText("SHA256:test");
      }
    },
  );

  it.each<ItemKind>(["login", "wifi", "secureNote", "bookmark"])(
    "offers a type-specific editor for %s items",
    (kind) => {
      render(
        <DetailPane
          detail={detail(kind)}
          onEdit={vi.fn()}
          onChanged={vi.fn()}
          onCopy={vi.fn()}
        />,
      );
      expect(screen.getByRole("button", { name: "Edit" })).toBeInTheDocument();
    },
  );
});
