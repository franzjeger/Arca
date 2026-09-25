import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import { PasskeyChoiceDialog } from "./PasskeyChoiceDialog";
vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { ...actual.api, resolvePasskeyChoice: vi.fn().mockResolvedValue(undefined) } };
});
const request = { id: "ceremony", site: "example.test", accounts: [
  { id: "first", account: "first@example.test", title: "Example" },
  { id: "wanted", account: "wanted@example.test", title: "Example" },
] };
beforeEach(() => vi.clearAllMocks());
it("waits for an explicit account choice and sends the chosen item ID", async () => {
  const done = vi.fn();
  render(<PasskeyChoiceDialog request={request} onResolved={done} onToast={vi.fn()} />);
  expect(api.resolvePasskeyChoice).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "wanted@example.test" }));
  expect(api.resolvePasskeyChoice).toHaveBeenCalledWith("ceremony", "wanted");
  await waitFor(() => expect(done).toHaveBeenCalledOnce());
});
it("cancels without selecting an account", async () => {
  render(<PasskeyChoiceDialog request={request} onResolved={vi.fn()} onToast={vi.fn()} />);
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(api.resolvePasskeyChoice).toHaveBeenCalledWith("ceremony", null);
});
