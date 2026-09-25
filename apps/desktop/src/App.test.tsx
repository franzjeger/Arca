import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import App from "./App";
import { api } from "./lib/api";
import { clearAllDrafts, draftKey, hasDraft } from "./lib/drafts";

const events = vi.hoisted(() => new Map<string, () => void>());
vi.mock("./lib/api", async () => {
  const actual = await vi.importActual<typeof import("./lib/api")>("./lib/api");
  return {
    ...actual,
    ...Object.fromEntries(Object.keys(actual).filter((key) => key.startsWith("on")).map((key) => [
      key, vi.fn((callback: () => void) => {
        events.set(key, callback);
        return Promise.resolve(() => { events.delete(key); });
      }),
    ])),
    isTauri: () => true,
    api: {
      vaultStatus: vi.fn(),
      listItems: vi.fn().mockResolvedValue([]),
      securityReport: vi.fn().mockResolvedValue([]),
      touch: vi.fn().mockResolvedValue(undefined),
    },
  };
});
vi.mock("./components/TitleBar", () => ({ TitleBar: () => null }));
vi.mock("./components/Sidebar", () => ({ Sidebar: () => null }));
vi.mock("./components/VaultStatusBar", () => ({ VaultStatusBar: () => null }));
vi.mock("./components/EntryList", () => ({
  EntryList: ({ onAdd }: { onAdd: () => void }) => <button onClick={onAdd}>New login</button>,
}));
vi.mock("./components/LockScreen", () => ({
  LockScreen: ({ onUnlocked }: { onUnlocked: () => void }) => <button onClick={onUnlocked}>Unlock test vault</button>,
}));
vi.mock("./components/AppDialogs", async () => {
  const { EditDialog } = await import("./components/EditDialog");
  return {
    AppDialogs: ({ editing }: { editing: unknown }) => editing
      ? <EditDialog itemId={null} onClose={() => {}} onSaved={() => {}} /> : null,
  };
});

const unlocked = {
  exists: true, unlocked: true, hasQuickUnlock: false,
  quickUnlockAvailable: false, biometricAvailable: false,
};
beforeEach(() => {
  clearAllDrafts();
  events.clear();
  vi.mocked(api.vaultStatus).mockResolvedValue(unlocked);
});

it.each(["button", "external event"])("drops drafts on lock and does not reopen after %s unlock", async (mode) => {
  render(<App />);
  fireEvent.click(await screen.findByText("New login"));
  fireEvent.change(screen.getByPlaceholderText("GitHub"), { target: { value: "Unsaved" } });
  const key = draftKey("login", null);
  expect(hasDraft(key)).toBe(true);

  // Lock must close the editor even if the status request has not returned.
  vi.mocked(api.vaultStatus).mockReturnValueOnce(new Promise(() => {}));
  act(() => { events.get("onVaultLocked")!(); });
  expect(hasDraft(key)).toBe(false);
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.getByText("Unlock test vault")).toBeInTheDocument();

  if (mode === "button") fireEvent.click(screen.getByText("Unlock test vault"));
  else act(() => { events.get("onVaultUnlocked")!(); });
  await screen.findByText("New login");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  fireEvent.click(screen.getByText("New login"));
  expect(screen.getByPlaceholderText("GitHub")).toHaveValue("");
});
