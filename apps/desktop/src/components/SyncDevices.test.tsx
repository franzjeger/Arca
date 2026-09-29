import { render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { api } from "../lib/api";
import { SyncDevices } from "./SyncDevices";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { ...actual.api, syncDevices: vi.fn() } };
});

it("lists every device that syncs the vault, and marks this one", async () => {
  vi.mocked(api.syncDevices).mockResolvedValue([
    { name: "MacBook Pro", lastUpload: Date.UTC(2026, 8, 28, 10), thisDevice: true },
    { name: "iPhone", lastUpload: Date.UTC(2026, 8, 20, 10), thisDevice: false },
  ]);
  render(<SyncDevices />);
  const list = await screen.findByRole("list", { name: "Devices syncing this vault" });
  await waitFor(() => expect(list.querySelectorAll("li")).toHaveLength(2));
  expect(list).toHaveTextContent("MacBook Pro (this computer)");
  expect(list).toHaveTextContent("iPhone");
});

it("shows nothing when the vault knows of no devices yet", async () => {
  vi.mocked(api.syncDevices).mockResolvedValue([]);
  const { container } = render(<SyncDevices />);
  await waitFor(() => expect(api.syncDevices).toHaveBeenCalled());
  expect(container).toBeEmptyDOMElement();
});
