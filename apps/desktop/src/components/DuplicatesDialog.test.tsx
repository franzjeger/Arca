import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { api, type DuplicateGroup, type DuplicateLogin } from "../lib/api";
import { DuplicatesDialog } from "./DuplicatesDialog";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { ...actual.api, findDuplicates: vi.fn(), mergeDuplicates: vi.fn() } };
});

function login(id: string, site: string, password: number, extra: Partial<DuplicateLogin> = {}): DuplicateLogin {
  return { id, revision: `rev-${id}`, title: "Google", site, username: "me@example.test",
    modifiedAt: Date.UTC(2026, 8, 1), password, hasPassword: true, hasTotp: false, hasNotes: false, ...extra };
}

const same: DuplicateGroup = { possible: false, keep: "b",
  logins: [login("b", "google.com", 0), login("a", "google.com", 1, { hasTotp: true })] };
const possible: DuplicateGroup = { possible: true, keep: "c",
  logins: [login("c", "accounts.google.com", 0, { title: "Google sign-in" }), login("b", "google.com", 1)] };

beforeEach(() => vi.clearAllMocks());

it("ticks the same account, only offers a possible one, and keeps the default", async () => {
  vi.mocked(api.findDuplicates).mockResolvedValue([same, possible]);
  render(<DuplicatesDialog onClose={vi.fn()} onMerged={vi.fn()} />);
  const sameSection = await screen.findByRole("region", { name: "Same site and username" });
  const possibleSection = screen.getByRole("region", { name: "Possibly the same account" });
  expect(within(sameSection).getByRole("checkbox")).toBeChecked();
  expect(within(possibleSection).getByRole("checkbox")).not.toBeChecked();
  const keepers = within(sameSection).getAllByRole("radio");
  expect(keepers[0]).toBeChecked();
  expect(within(sameSection).getByText("Different password")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Merge 1 group" })).toBeEnabled();
});

it("merges only the ticked groups, into the login picked, as they were shown", async () => {
  vi.mocked(api.findDuplicates).mockResolvedValue([same, possible]);
  vi.mocked(api.mergeDuplicates).mockResolvedValue(2);
  const onMerged = vi.fn();
  render(<DuplicatesDialog onClose={vi.fn()} onMerged={onMerged} />);
  const sameSection = await screen.findByRole("region", { name: "Same site and username" });
  // Keep the older login instead; the badge moves to the other one.
  await userEvent.click(within(sameSection).getAllByRole("radio")[1]);
  expect(within(sameSection).getAllByText("Different password")).toHaveLength(1);
  await userEvent.click(within(screen.getByRole("region", { name: "Possibly the same account" })).getByRole("checkbox"));
  await userEvent.click(screen.getByRole("button", { name: "Merge 2 groups" }));
  expect(api.mergeDuplicates).toHaveBeenCalledWith(
    [{ keep: "a", ids: ["b", "a"] }, { keep: "c", ids: ["c", "b"] }],
    [{ id: "b", revision: "rev-b" }, { id: "a", revision: "rev-a" }, { id: "c", revision: "rev-c" }],
  );
  expect(onMerged).toHaveBeenCalledWith(2);
});

it("says so when there is nothing to merge", async () => {
  vi.mocked(api.findDuplicates).mockResolvedValue([]);
  render(<DuplicatesDialog onClose={vi.fn()} onMerged={vi.fn()} />);
  expect(await screen.findByText("No duplicates found.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /^Merge/ })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument();
});

it("shows why a merge was refused and offers to look again", async () => {
  vi.mocked(api.findDuplicates).mockResolvedValue([same]);
  vi.mocked(api.mergeDuplicates).mockRejectedValue({
    code: "changed",
    message: "These logins changed after they were shown. Look again before merging.",
  });
  const onMerged = vi.fn();
  render(<DuplicatesDialog onClose={vi.fn()} onMerged={onMerged} />);
  await userEvent.click(await screen.findByRole("button", { name: "Merge 1 group" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("These logins changed after they were shown.");
  expect(onMerged).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Look again" }));
  expect(api.findDuplicates).toHaveBeenCalledTimes(2);
});
