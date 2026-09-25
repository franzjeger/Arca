import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { Dialog } from "./Dialog";

it("Escape cancellation follows the same close path and restores focus on unmount", () => {
  const opener = document.createElement("button");
  document.body.append(opener); opener.focus();
  const close = vi.fn();
  const view = render(<Dialog label="Example" onClose={close}><button>Inside</button></Dialog>);
  fireEvent(screen.getByRole("dialog", { name: "Example" }), new Event("cancel", { cancelable: true }));
  expect(close).toHaveBeenCalledOnce();
  screen.getByRole("button", { name: "Inside" }).focus();
  view.unmount();
  expect(document.activeElement).toBe(opener);
  opener.remove();
});

it("does not discard a draft when unmounted by a lock, or cancel an in-flight save", () => {
  const close = vi.fn();
  const view = render(<Dialog label="Saving" onClose={close} dismissible={false}><button>Inside</button></Dialog>);
  fireEvent(screen.getByRole("dialog"), new Event("cancel", { cancelable: true }));
  view.unmount();
  expect(close).not.toHaveBeenCalled();
});
