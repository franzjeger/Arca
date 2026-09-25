import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { LockScreen } from "./LockScreen";
import { api, type VaultStatus } from "../lib/api";

vi.mock("../lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: {
      quickUnlock: vi.fn(),
      keyfileUnlock: vi.fn(),
      unlock: vi.fn(),
      createVault: vi.fn(),
    },
  };
});

const quickUnlock = vi.mocked(api.quickUnlock);
const keyfileUnlock = vi.mocked(api.keyfileUnlock);
const unlock = vi.mocked(api.unlock);

/** Linux with a USB key enrolled: no biometric, no keychain quick unlock. */
function keyStatus(present: boolean, overrides: Partial<VaultStatus> = {}): VaultStatus {
  return status({
    hasQuickUnlock: false,
    quickUnlockAvailable: false,
    biometricAvailable: false,
    keyFile: { enrolled: true, present, volumeLabel: "ESD-USB", volumeId: "3CCC-1EA9", lockOnRemoval: true },
    ...overrides,
  });
}

/** An existing vault with Touch ID available — the everyday case. */
function status(overrides: Partial<VaultStatus> = {}): VaultStatus {
  return {
    exists: true,
    unlocked: false,
    hasQuickUnlock: true,
    quickUnlockAvailable: true,
    biometricAvailable: true,
    ...overrides,
  } as VaultStatus;
}

/** The backend's error shape (`CmdError`), which `isApiError` recognises. */
const apiError = (code: string, message: string) => ({ code, message });

beforeEach(() => {
  vi.clearAllMocks();
});

describe("LockScreen", () => {

  describe("USB key", () => {
    it("lets a present key pre-empt the automatic Touch ID prompt", async () => {
      keyfileUnlock.mockResolvedValue(undefined);
      quickUnlock.mockResolvedValue(undefined);
      const onUnlocked = vi.fn();
      // A Mac with Touch ID AND a key plugged in.
      render(<LockScreen status={keyStatus(true, { quickUnlockAvailable: true, biometricAvailable: true })} onUnlocked={onUnlocked} />);
      await waitFor(() => expect(onUnlocked).toHaveBeenCalledTimes(1));
      expect(keyfileUnlock).toHaveBeenCalledTimes(1);
      expect(quickUnlock).not.toHaveBeenCalled();
      // Both buttons stay available for a manual choice.
      expect(screen.getByRole("button", { name: /unlock with usb key/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /use quick unlock/i })).toBeInTheDocument();
    });

    /// A plugged-in key is standing permission. No prompt is involved, so an
    /// automatic lock does not silence it the way it silences Touch ID.
    it("opens with the key on focus, once, even after an automatic lock", async () => {
      keyfileUnlock.mockResolvedValue(undefined);
      const onUnlocked = vi.fn();
      const focused = vi.spyOn(document, "hasFocus").mockReturnValue(false);
      render(<LockScreen status={keyStatus(true)} autoLocked onUnlocked={onUnlocked} />);

      await new Promise((r) => setTimeout(r, 50));
      expect(keyfileUnlock).not.toHaveBeenCalled();
      expect(screen.getByText(/USB key \(ESD-USB\) is plugged in/i)).toBeInTheDocument();

      focused.mockReturnValue(true);
      act(() => window.dispatchEvent(new Event("focus")));
      await waitFor(() => expect(onUnlocked).toHaveBeenCalledTimes(1));
      expect(keyfileUnlock).toHaveBeenCalledTimes(1);

      act(() => window.dispatchEvent(new Event("focus")));
      await new Promise((r) => setTimeout(r, 50));
      expect(keyfileUnlock).toHaveBeenCalledTimes(1);
      expect(quickUnlock).not.toHaveBeenCalled();
      focused.mockRestore();
    });

    it("asks for the key when it is not plugged in, and tries on demand", async () => {
      keyfileUnlock.mockRejectedValue(apiError("keyfile_missing", "Plug in your USB key, or enter your master password."));
      const user = userEvent.setup();
      render(<LockScreen status={keyStatus(false)} onUnlocked={vi.fn()} />);

      expect(screen.getByText(/Plug in your USB key \(ESD-USB\)/i)).toBeInTheDocument();
      await new Promise((r) => setTimeout(r, 50));
      expect(keyfileUnlock).not.toHaveBeenCalled();

      await user.click(screen.getByRole("button", { name: /unlock with usb key/i }));
      await waitFor(() => expect(keyfileUnlock).toHaveBeenCalledTimes(1));
      expect(await screen.findByText(/plug in your usb key/i, { selector: "p.text-red-400" })).toBeInTheDocument();
      // The password field is right there for the fallback.
      expect(screen.getByPlaceholderText("Master password")).toBeInTheDocument();
    });

    it("keeps an automatic failure quiet", async () => {
      keyfileUnlock.mockRejectedValue(apiError("keyfile_stale", "This USB key no longer matches the vault."));
      render(<LockScreen status={keyStatus(true)} onUnlocked={vi.fn()} />);
      await waitFor(() => expect(keyfileUnlock).toHaveBeenCalledTimes(1));
      await new Promise((r) => setTimeout(r, 50));
      expect(screen.queryByText(/no longer matches/i)).toBeNull();
    });
  });
  /// The complaint, as a test: Arca locked itself, so Arca does not get to ask
  /// for a fingerprint. Not now, not when the window is brought back.
  it("never prompts by itself after an automatic lock", async () => {
    quickUnlock.mockResolvedValue(undefined);
    render(<LockScreen status={status()} autoLocked onUnlocked={vi.fn()} />);

    await new Promise((r) => setTimeout(r, 50));
    expect(quickUnlock).not.toHaveBeenCalled();

    // Coming back to the window is not a request either — the user may have
    // clicked over for something else entirely.
    act(() => window.dispatchEvent(new Event("focus")));
    await new Promise((r) => setTimeout(r, 50));
    expect(quickUnlock).not.toHaveBeenCalled();

    // Pressing the button is. That is the only thing that should be.
    await userEvent.click(
      screen.getByRole("button", { name: /use quick unlock/i }),
    );
    await waitFor(() => expect(quickUnlock).toHaveBeenCalledTimes(1));
  });

  /// The idle timer expires while you are working in another app. Arca must not
  /// throw a Touch ID sheet in front of that.
  it("stays silent when the window is not focused, and asks once it is", async () => {
    quickUnlock.mockResolvedValue(undefined);
    const focused = vi.spyOn(document, "hasFocus").mockReturnValue(false);

    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);

    // Nothing, and it has to STAY nothing — a prompt that merely arrives late
    // is the same interruption.
    await new Promise((r) => setTimeout(r, 50));
    expect(quickUnlock).not.toHaveBeenCalled();

    // The user comes back to Arca. Now it is what they wanted.
    focused.mockReturnValue(true);
    act(() => window.dispatchEvent(new Event("focus")));
    await waitFor(() => expect(quickUnlock).toHaveBeenCalledTimes(1));

    // And still only once: returning to the window again must not re-prompt
    // someone who cancelled and is typing their password instead.
    act(() => window.dispatchEvent(new Event("focus")));
    await new Promise((r) => setTimeout(r, 50));
    expect(quickUnlock).toHaveBeenCalledTimes(1);

    focused.mockRestore();
  });

  it("prompts for Touch ID once on mount", async () => {
    quickUnlock.mockResolvedValue(undefined);
    const onUnlocked = vi.fn();
    render(<LockScreen status={status()} onUnlocked={onUnlocked} />);

    await waitFor(() => expect(onUnlocked).toHaveBeenCalledTimes(1));
    expect(quickUnlock).toHaveBeenCalledTimes(1);
  });

  it("does not prompt at all when quick unlock is unavailable", async () => {
    render(
      <LockScreen
        status={status({ quickUnlockAvailable: false })}
        onUnlocked={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(
        screen.getByPlaceholderText("Master password"),
      ).toBeInTheDocument(),
    );
    expect(quickUnlock).not.toHaveBeenCalled();
  });

  // REGRESSION (2026-07-20): clicking the empty password field used to re-fire
  // Touch ID. Combined with a failing unlock that produced an endless storm of
  // prompts: 3x Touch ID -> master password -> 3x again.
  it("never triggers Touch ID from clicking or typing in the password field", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Cancelled."));
    const user = userEvent.setup();
    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);

    await waitFor(() => expect(quickUnlock).toHaveBeenCalledTimes(1)); // the mount prompt
    const field = screen.getByPlaceholderText("Master password");
    await user.click(field);
    await user.click(field);
    await user.type(field, "hunter2");

    expect(quickUnlock).toHaveBeenCalledTimes(1); // still just the mount one
  });

  // REGRESSION (2026-07-20): when Touch ID SUCCEEDED but the unlock behind it
  // failed (device key drifted from the header wrap), the error was swallowed
  // and the prompt kept coming back. It must be shown, and prompting must stop.
  it("stops offering Touch ID after a failure past the biometric", async () => {
    quickUnlock.mockRejectedValue(
      apiError(
        "quick_unlock_stale",
        "Quick unlock is out of sync with this vault.",
      ),
    );
    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);

    // The reason is surfaced, not swallowed.
    await waitFor(() =>
      expect(screen.getByText(/out of sync/i)).toBeInTheDocument(),
    );
    // …and the Touch ID affordance is gone, so it cannot be fired again.
    expect(screen.queryByRole("button", { name: /use quick unlock/i })).toBeNull();
    expect(quickUnlock).toHaveBeenCalledTimes(1);
  });

  it("stays quiet when the user simply cancels the automatic prompt", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Cancelled."));
    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);

    await waitFor(() => expect(quickUnlock).toHaveBeenCalledTimes(1));
    // No scary error for a deliberate cancel, and Touch ID stays available.
    expect(screen.queryByText(/cancelled/i)).toBeNull();
    expect(
      screen.getByRole("button", { name: /use quick unlock/i }),
    ).toBeInTheDocument();
  });

  it("retries on demand via the Touch ID button, and reports why it failed", async () => {
    quickUnlock.mockRejectedValue(
      apiError("biometric_failed", "Not recognised."),
    );
    const user = userEvent.setup();
    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);
    await waitFor(() => expect(quickUnlock).toHaveBeenCalledTimes(1));

    await user.click(screen.getByRole("button", { name: /use quick unlock/i }));

    expect(quickUnlock).toHaveBeenCalledTimes(2);
    await waitFor(() =>
      expect(screen.getByText(/not recognised/i)).toBeInTheDocument(),
    );
  });

  it("unlocks with the master password", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Cancelled."));
    unlock.mockResolvedValue(undefined);
    const onUnlocked = vi.fn();
    const user = userEvent.setup();
    render(<LockScreen status={status()} onUnlocked={onUnlocked} />);

    await user.type(
      screen.getByPlaceholderText("Master password"),
      "correct horse",
    );
    await user.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() => expect(unlock).toHaveBeenCalledWith("correct horse"));
    expect(onUnlocked).toHaveBeenCalled();
  });

  it("shows the reason when the master password is wrong", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Cancelled."));
    unlock.mockRejectedValue(
      apiError("invalid_credentials", "That master password is not correct."),
    );
    const onUnlocked = vi.fn();
    const user = userEvent.setup();
    render(<LockScreen status={status()} onUnlocked={onUnlocked} />);

    await user.type(screen.getByPlaceholderText("Master password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() =>
      expect(screen.getByText(/not correct/i)).toBeInTheDocument(),
    );
    expect(onUnlocked).not.toHaveBeenCalled();
  });

  it("requires a confirmed, long-enough password when creating a vault", async () => {
    const onUnlocked = vi.fn();
    const user = userEvent.setup();
    render(
      <LockScreen status={status({ exists: false })} onUnlocked={onUnlocked} />,
    );

    const pw = screen.getByPlaceholderText("Master password");
    const confirm = screen.getByPlaceholderText("Confirm master password");
    const submit = screen.getByRole("button", { name: "Create Vault" });

    await user.type(pw, "short");
    await user.click(submit);
    expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument();
    expect(api.createVault).not.toHaveBeenCalled();

    await user.clear(pw);
    await user.type(pw, "long-enough-pw");
    await user.type(confirm, "different-pw");
    await user.click(submit);
    expect(screen.getByText(/don't match/i)).toBeInTheDocument();
    expect(api.createVault).not.toHaveBeenCalled();
  });
});

it("does not start an automatic prompt after a manual unlock regains focus", async () => {
  const focused = vi.spyOn(document, "hasFocus").mockReturnValue(false);
  let finish!: () => void;
  quickUnlock.mockImplementation(() => new Promise<void>(resolve => { finish = resolve; }));
  const onUnlocked = vi.fn();
  render(<LockScreen status={status()} onUnlocked={onUnlocked} />);
  await userEvent.click(screen.getByRole("button", { name: /use quick unlock/i }));
  focused.mockReturnValue(true);
  act(() => window.dispatchEvent(new Event("focus")));
  expect(quickUnlock).toHaveBeenCalledTimes(1);
  await act(async () => finish());
  focused.mockRestore();
  expect(onUnlocked).toHaveBeenCalledOnce();
});

it("does not prompt again while the parent refreshes status after a manual unlock", async () => {
  const focused = vi.spyOn(document, "hasFocus").mockReturnValue(true);
  quickUnlock.mockResolvedValue();
  const onUnlocked = vi.fn(() => {
    // App clears autoLocked immediately, before its async vaultStatus result
    // replaces the lock screen with the unlocked UI.
    view.rerender(<LockScreen status={status()} autoLocked={false} onUnlocked={onUnlocked} />);
  });
  const view = render(<LockScreen status={status()} autoLocked onUnlocked={onUnlocked} />);
  await userEvent.click(screen.getByRole("button", { name: /use quick unlock/i }));
  await waitFor(() => expect(onUnlocked).toHaveBeenCalledOnce());
  expect(quickUnlock).toHaveBeenCalledOnce();
  focused.mockRestore();
});
