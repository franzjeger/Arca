import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { api, type VaultStatus } from "../lib/api";
import { useReauthentication } from "./useReauthentication";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return { ...actual, api: { ...actual.api, vaultStatus: vi.fn() } };
});
beforeEach(() => { vi.mocked(api.vaultStatus).mockResolvedValue({ unlocked: true, biometricAvailable: false } as VaultStatus); });
function Harness({ action, done }: { action: (password?: string) => Promise<string>; done: (result: unknown) => void }) {
  const verification = useReauthentication();
  return <><button onClick={() => void verification.run("export passwords", action).then(done, (error) => done({ error }))}>Export</button>{verification.dialog}</>;
}

it("requires a password, keeps failure inline and submits only once while pending", async () => {
  let complete!: (value: string) => void;
  const action = vi.fn().mockRejectedValueOnce({ code: "reauth_failed", message: "Wrong current password" })
    .mockImplementationOnce(() => new Promise<string>((resolve) => { complete = resolve; }));
  const done = vi.fn(); render(<Harness action={action} done={done} />);
  await userEvent.click(screen.getByRole("button", { name: "Export" }));
  const password = await screen.findByLabelText("Current master password");
  expect(action).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Confirm" })).toBeDisabled();
  await userEvent.type(password, "wrong{Enter}");
  expect(await screen.findByRole("alert")).toHaveTextContent("Wrong current password");
  expect(password).toHaveValue(""); expect(done).not.toHaveBeenCalled();
  await userEvent.type(password, "correct{Enter}{Enter}");
  expect(action).toHaveBeenCalledTimes(2);
  expect(action).toHaveBeenLastCalledWith("correct");
  await act(async () => complete("exported"));
  expect(done).toHaveBeenCalledWith({ value: "exported" });
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

it("cancel and vault-lock unmount never execute the requested operation", async () => {
  const action = vi.fn(); const done = vi.fn();
  const view = render(<Harness action={action} done={done} />);
  await userEvent.click(screen.getByRole("button", { name: "Export" }));
  await userEvent.click(await screen.findByRole("button", { name: "Cancel" }));
  expect(done).toHaveBeenCalledWith(null); expect(action).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Export" }));
  await screen.findByRole("dialog"); view.unmount();
  await waitFor(() => expect(done).toHaveBeenCalledTimes(2));
  expect(action).not.toHaveBeenCalled();
});

it("uses backend system verification on supported platforms", async () => {
  vi.mocked(api.vaultStatus).mockResolvedValue({ unlocked: true, biometricAvailable: true } as VaultStatus);
  const action = vi.fn().mockResolvedValue("done"); const done = vi.fn();
  render(<Harness action={action} done={done} />);
  await userEvent.click(screen.getByRole("button", { name: "Export" }));
  await waitFor(() => expect(done).toHaveBeenCalledWith({ value: "done" }));
  expect(action).toHaveBeenCalledWith(); expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

it("returns operation errors to the owning dialog instead of asking for the password again", async () => {
  const error = { code: "backup_read", message: "Could not read the backup." };
  const action = vi.fn().mockRejectedValue(error); const done = vi.fn();
  render(<Harness action={action} done={done} />);
  await userEvent.click(screen.getByRole("button", { name: "Export" }));
  await userEvent.type(await screen.findByLabelText("Current master password"), "correct{Enter}");
  await waitFor(() => expect(done).toHaveBeenCalledWith({ error }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});
