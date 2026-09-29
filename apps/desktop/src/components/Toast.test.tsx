import { render, screen, waitFor } from "@testing-library/react";
import { expect, it } from "vitest";
import { Dialog } from "./Dialog";
import { Toast } from "./Toast";

// A modal <dialog> sits in the browser's top layer, above every z-index. A
// toast outside it is drawn underneath, so a result raised from Settings was
// never seen: "Merge…" and "Check…" looked like they did nothing.
function Screen({ nested, message }: { nested: boolean; message: string | null }) {
  return (
    <>
      <Dialog label="Settings" onClose={() => {}}>
        <p>Settings</p>
        {nested && <Dialog label="Earlier vault versions" onClose={() => {}}><p>Nested</p></Dialog>}
      </Dialog>
      <Toast message={message} onDone={() => {}} />
    </>
  );
}

it("shows a toast inside the dialog in front, where it can be seen", async () => {
  const view = render(<Screen nested={false} message={null} />);
  view.rerender(<Screen nested={false} message="No duplicates found" />);
  const settings = screen.getByRole("dialog", { name: "Settings" });
  await waitFor(() => expect(settings).toContainElement(screen.getByRole("status")));

  view.rerender(<Screen nested message="No duplicates found" />);
  const nested = screen.getByRole("dialog", { name: "Earlier vault versions" });
  await waitFor(() => expect(nested).toContainElement(screen.getByRole("status")));

  // The nested dialog closes while the toast is up: it moves back.
  view.rerender(<Screen nested={false} message="No duplicates found" />);
  await waitFor(() =>
    expect(screen.getByRole("dialog", { name: "Settings" })).toContainElement(screen.getByRole("status")),
  );
});

it("shows a toast on the page when no dialog is open", async () => {
  render(<Toast message={{ text: "Could not save", tone: "error" }} onDone={() => {}} />);
  const alert = await screen.findByRole("alert");
  expect(alert.closest("dialog")).toBeNull();
  expect(alert).toHaveTextContent("Could not save");
});
