import { beforeEach, expect, it, vi } from "vitest";
import { check } from "@tauri-apps/plugin-updater";
import { checkForUpdate } from "./api";

vi.mock("@tauri-apps/plugin-updater", () => ({ check: vi.fn() }));
beforeEach(() => {
  vi.mocked(check).mockReset();
});

// The update address answers 404 until a release is published there, and the
// updater reports that in words that mean nothing to the person who clicked.
it("says plainly when no release has been published", async () => {
  vi.mocked(check).mockRejectedValue("Could not fetch a valid release JSON from the remote");
  await expect(checkForUpdate()).rejects.toThrow("No release has been published at the update address.");
});

it("passes any other failure through as it is", async () => {
  vi.mocked(check).mockRejectedValue("error sending request for url (https://github.com/)");
  await expect(checkForUpdate()).rejects.toThrow("error sending request for url (https://github.com/)");
});

it("returns null when up to date", async () => {
  vi.mocked(check).mockResolvedValue(null);
  await expect(checkForUpdate()).resolves.toBeNull();
});
