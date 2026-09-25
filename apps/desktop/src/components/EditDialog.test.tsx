import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EditDialog } from "./EditDialog";
import { clearAllDrafts } from "../lib/drafts";

vi.mock("../lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: {
      getItem: vi.fn(),
      revealField: vi.fn(),
      upsertItem: vi.fn().mockResolvedValue("new-id"),
      generate: vi.fn(),
    },
  };
});

describe("EditDialog drafts", () => {
  beforeEach(() => clearAllDrafts());

  it("discards typed secrets when locking clears drafts and unmounts the dialog", async () => {
    const user = userEvent.setup();
    const view = render(
      <EditDialog itemId={null} onClose={vi.fn()} onSaved={vi.fn()} />,
    );

    await user.type(screen.getByPlaceholderText("GitHub"), "Visma");
    await user.type(screen.getByPlaceholderText("frank-lia"), "frank.lia");

    await user.type(document.querySelector('input[type="password"]')!, "unsaved-secret");
    // App clears all drafts before the lock screen unmounts the editor.
    clearAllDrafts();
    view.unmount();

    render(<EditDialog itemId={null} onClose={vi.fn()} onSaved={vi.fn()} />);
    expect(screen.getByPlaceholderText("GitHub")).toHaveValue("");
    expect(screen.getByPlaceholderText("frank-lia")).toHaveValue("");
    expect(document.querySelector('input[type="password"]')).toHaveValue("");
  });

  it("discards the draft when the user closes the dialog themselves", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const view = render(
      <EditDialog itemId={null} onClose={onClose} onSaved={vi.fn()} />,
    );

    await user.type(screen.getByPlaceholderText("GitHub"), "Throwaway");
    // Cancel discards the draft within the unlocked session, too.
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalled();
    view.unmount();

    render(<EditDialog itemId={null} onClose={vi.fn()} onSaved={vi.fn()} />);
    expect(screen.getByPlaceholderText("GitHub")).toHaveValue("");
  });

  it("discards the draft once the edit is saved", async () => {
    const user = userEvent.setup();
    const onSaved = vi.fn();
    const view = render(
      <EditDialog itemId={null} onClose={vi.fn()} onSaved={onSaved} />,
    );

    await user.type(screen.getByPlaceholderText("GitHub"), "Saved");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await vi.waitFor(() => expect(onSaved).toHaveBeenCalledWith("new-id"));
    view.unmount();

    render(<EditDialog itemId={null} onClose={vi.fn()} onSaved={vi.fn()} />);
    expect(screen.getByPlaceholderText("GitHub")).toHaveValue("");
  });

  it("does not refetch over a restored draft", async () => {
    const { api } = await import("../lib/api");
    const getItem = vi.mocked(api.getItem);
    const revealField = vi.mocked(api.revealField);
    getItem.mockResolvedValue({
      id: "abc",
      kind: "login",
      title: "On disk",
      username: "disk-user",
      url: "",
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
      folder: "",
    });
    revealField.mockResolvedValue("");

    const user = userEvent.setup();
    const first = render(
      <EditDialog itemId="abc" onClose={vi.fn()} onSaved={vi.fn()} />,
    );
    expect(await screen.findByDisplayValue("On disk")).toBeTruthy();

    await user.clear(screen.getByPlaceholderText("GitHub"));
    await user.type(screen.getByPlaceholderText("GitHub"), "My edit");
    first.unmount();

    getItem.mockClear();
    render(<EditDialog itemId="abc" onClose={vi.fn()} onSaved={vi.fn()} />);
    // The edit survives, and the stale file is NOT read back over it.
    expect(screen.getByPlaceholderText("GitHub")).toHaveValue("My edit");
    expect(getItem).not.toHaveBeenCalled();
  });
});
