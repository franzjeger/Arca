import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { SshImportPanel } from "./SshImportPanel";
import { api, type FoundSshKey } from "../lib/api";

vi.mock("../lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: { sshImportScan: vi.fn(), sshImport: vi.fn() },
  };
});

const scan = vi.mocked(api.sshImportScan);
const importKeys = vi.mocked(api.sshImport);

const key = (file: string, overrides: Partial<FoundSshKey> = {}): FoundSshKey => ({
  file,
  keyType: "ssh-ed25519",
  fingerprint: `SHA256:${file}`,
  comment: "",
  encrypted: false,
  status: { kind: "new" },
  ...overrides,
});

const found: FoundSshKey[] = [
  key("id_ed25519", { comment: "frank@mac" }),
  key("homelab", { encrypted: true }),
  key("copy_of_id", { status: { kind: "sameAs", file: "id_ed25519" } }),
  key("work", { status: { kind: "inVault", title: "Work laptop" } }),
  key("id_rsa", { keyType: "RSA", fingerprint: "", status: { kind: "unsupported" } }),
];

beforeEach(() => {
  vi.clearAllMocks();
  scan.mockResolvedValue(found);
});

describe("SshImportPanel", () => {
  it("names what the cross-check found, and offers only the keys Arca lacks", async () => {
    render(<SshImportPanel onImported={vi.fn()} onClose={vi.fn()} />);

    expect(await screen.findByText("Same key as id_ed25519")).toBeInTheDocument();
    expect(screen.getByText("Already in Arca as “Work laptop”")).toBeInTheDocument();
    expect(screen.getByText("RSA keys aren't supported yet")).toBeInTheDocument();

    expect(screen.getByLabelText("Import id_ed25519")).toBeChecked();
    expect(screen.getByLabelText("Import homelab")).toBeChecked();
    for (const file of ["copy_of_id", "work", "id_rsa"]) {
      expect(screen.getByLabelText(`Import ${file}`)).toBeDisabled();
    }
    // An encrypted key waits for its passphrase.
    expect(screen.getByRole("button", { name: "Import 2 keys" })).toBeDisabled();
  });

  it("imports the picked keys with their passphrases", async () => {
    importKeys.mockResolvedValue({ ids: ["a", "b"], failed: [] });
    const onImported = vi.fn();
    const user = userEvent.setup();
    render(<SshImportPanel onImported={onImported} onClose={vi.fn()} />);

    await user.type(await screen.findByLabelText("Passphrase for homelab"), "secret");
    await user.click(screen.getByRole("button", { name: "Import 2 keys" }));

    expect(importKeys).toHaveBeenCalledWith([
      { file: "id_ed25519", passphrase: undefined },
      { file: "homelab", passphrase: "secret" },
    ]);
    await waitFor(() => expect(onImported).toHaveBeenCalledWith("a"));
  });

  it("stays open and says which files were not taken, and why", async () => {
    importKeys.mockResolvedValue({
      ids: ["a"],
      failed: [{ file: "homelab", reason: "passphrase" }],
    });
    const onImported = vi.fn();
    const user = userEvent.setup();
    render(<SshImportPanel onImported={onImported} onClose={vi.fn()} />);

    await user.type(await screen.findByLabelText("Passphrase for homelab"), "wrong");
    await user.click(screen.getByRole("button", { name: "Import 2 keys" }));

    expect(await screen.findByText("homelab: wrong passphrase")).toBeInTheDocument();
    expect(onImported).not.toHaveBeenCalled();
    expect(scan).toHaveBeenCalledTimes(2);
  });

  it("says so when ~/.ssh holds no private keys", async () => {
    scan.mockResolvedValue([]);
    render(<SshImportPanel onImported={vi.fn()} onClose={vi.fn()} />);
    expect(await screen.findByText("No private keys in ~/.ssh.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import 0 keys" })).toBeDisabled();
  });
});
