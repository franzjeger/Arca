import { expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ImportDialog } from "./ImportDialog";
import { api, type ImportSummary } from "../lib/api";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { ...actual.api, pickAndImport: vi.fn(), openPasswordsApp: vi.fn() } };
});

const summary: ImportSummary = { imported: 12, updated: 0, duplicates: 0, skipped: 0, notes: 0,
  passkeysLeftOut: 0, attachmentsLeftOut: 0 };
const onToast = vi.fn();
beforeEach(() => vi.clearAllMocks());

async function importFrom(source: string, result: ImportSummary | null) {
  vi.mocked(api.pickAndImport).mockResolvedValue(result);
  render(<ImportDialog onClose={vi.fn()} onImported={vi.fn()} onToast={onToast} />);
  await userEvent.click(screen.getByRole("button", { name: new RegExp(source) }));
  await userEvent.click(screen.getByRole("button", { name: "Choose file…" }));
}

it("walks through a Bitwarden and a 1Password export, in their own formats", async () => {
  render(<ImportDialog onClose={vi.fn()} onImported={vi.fn()} onToast={onToast} />);
  await userEvent.click(screen.getByRole("button", { name: /Bitwarden/ }));
  expect(screen.getByText(/not "\.json \(Encrypted\)"/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /1Password/ }));
  expect(screen.getByText(/Choose the format "1PUX"/)).toBeInTheDocument();
});

// A toast is gone in seconds; what did not come along has to stay readable
// until the user has dealt with it.
it("keeps what was not imported on screen, and says what to do about it", async () => {
  await importFrom("Bitwarden", { ...summary, notes: 3, passkeysLeftOut: 2, attachmentsLeftOut: 1 });
  expect(onToast).toHaveBeenCalledWith("Imported 12 logins, 3 notes");
  const status = await screen.findByRole("status");
  expect(status).toHaveTextContent("2 passkeys were not imported: keep the old app until");
  expect(status).toHaveTextContent("1 attached file was not imported: save it from the old app first.");
});

it("says nothing more when everything came along", async () => {
  await importFrom("Chrome", { ...summary, imported: 1, duplicates: 4, skipped: 2 });
  expect(onToast).toHaveBeenCalledWith("Imported 1 login, 4 already present, skipped 2 empty");
  expect(screen.queryByRole("status")).not.toBeInTheDocument();
});

it("does nothing when the picker is cancelled", async () => {
  await importFrom("Firefox", null);
  expect(onToast).not.toHaveBeenCalled();
});
