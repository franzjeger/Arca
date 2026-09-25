import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { api, type ItemSummary } from "../lib/api";
import { SyncConflictsDialog } from "./SyncConflictsDialog";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { ...actual.api, compareSyncConflict: vi.fn(), revealConflictField: vi.fn(), resolveSyncConflict: vi.fn(), keepSyncConflictCopy: vi.fn().mockResolvedValue(undefined) } };
});
const original = { id: "original", title: "Account", subtitle: "user", kind: "login", isSyncConflict: false } as ItemSummary;
const copy = { ...original, id: "copy", title: "Account (sync conflict)", isSyncConflict: true, conflictOf: "original" };
const comparison = { originalRevision: "left-revision", copyRevision: "right-revision", fields: [
  { key: "username", original: "alice", copy: "bob", secret: false, revealable: false, different: true },
  { key: "password", original: "Hidden", copy: "Hidden", secret: true, revealable: true, different: true },
] };
beforeEach(() => {
  vi.clearAllMocks(); vi.mocked(api.compareSyncConflict).mockResolvedValue(comparison);
  vi.mocked(api.resolveSyncConflict).mockResolvedValue();
  vi.mocked(api.revealConflictField).mockResolvedValue(["old-secret", "new-secret"]);
});

it("keeps secrets hidden and resolves only the selected fields and reviewed revisions", async () => {
  const close = vi.fn(); const refresh = vi.fn().mockResolvedValue(undefined);
  render(<SyncConflictsDialog items={[original, copy]} onClose={close} onResolved={refresh} />);
  await screen.findByLabelText("Password: conflict copy");
  expect(screen.queryByText("new-secret")).not.toBeInTheDocument();
  expect(api.revealConflictField).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Reveal values" }));
  expect(await screen.findByText("new-secret")).toBeInTheDocument();
  await userEvent.click(screen.getByLabelText("Password: conflict copy"));
  await userEvent.click(screen.getByRole("button", { name: "Save selected values" }));
  await waitFor(() => expect(close).toHaveBeenCalledOnce());
  expect(api.resolveSyncConflict).toHaveBeenCalledWith({ originalId: "original", copyId: "copy", originalRevision: "left-revision", copyRevision: "right-revision" }, "merge", ["password"]);
  expect(refresh).toHaveBeenCalledOnce();
});

it("requires manual pairing for legacy copies", async () => {
  render(<SyncConflictsDialog items={[original, { ...copy, conflictOf: null }]} onClose={vi.fn()} onResolved={vi.fn()} />);
  expect(api.compareSyncConflict).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Save selected values" })).toBeDisabled();
  await userEvent.selectOptions(screen.getByLabelText("Compare with"), "original");
  await screen.findByLabelText("Username: original");
  expect(api.compareSyncConflict).toHaveBeenCalledWith("original", "copy");
});

it("keeps stale-conflict failures visible and permits refreshing", async () => {
  vi.mocked(api.resolveSyncConflict).mockRejectedValue(new Error("These entries changed. Refresh the comparison."));
  const close = vi.fn();
  render(<SyncConflictsDialog items={[original, copy]} onClose={close} onResolved={vi.fn()} />);
  await screen.findByLabelText("Username: original");
  await userEvent.click(screen.getByRole("button", { name: "Use conflict copy" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("These entries changed");
  expect(close).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Refresh comparison" }));
  await waitFor(() => expect(api.compareSyncConflict).toHaveBeenCalledTimes(2));
});

it("lets an orphan copy become an independent entry without replacing another item", async () => {
  const resolved = vi.fn().mockResolvedValue(undefined);
  vi.mocked(api.compareSyncConflict).mockRejectedValue(new Error("Original missing"));
  render(<SyncConflictsDialog items={[copy]} onClose={vi.fn()} onResolved={resolved} />);
  await userEvent.click(screen.getByRole("button", { name: "Keep this copy separately" }));
  await waitFor(() => expect(resolved).toHaveBeenCalledWith("keepCopy"));
  expect(api.keepSyncConflictCopy).toHaveBeenCalledWith("copy");
  expect(api.resolveSyncConflict).not.toHaveBeenCalled();
});
