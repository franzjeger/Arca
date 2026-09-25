import { useState } from "react";
import { Dialog } from "./Dialog";
import { api, errorMessage, type PasskeyChoiceRequest } from "../lib/api";
import { toastError, type ToastMessage } from "../lib/toast";

export function PasskeyChoiceDialog({ request, onResolved, onToast }: {
  request: PasskeyChoiceRequest;
  onResolved: () => void;
  onToast: (message: ToastMessage) => void;
}) {
  const [busy, setBusy] = useState(false);
  const choose = async (itemId: string | null) => {
    if (busy) return;
    setBusy(true);
    try {
      await api.resolvePasskeyChoice(request.id, itemId);
      onResolved();
    } catch (error) {
      onToast(toastError(errorMessage(error)));
      setBusy(false);
    }
  };
  return <Dialog label="Choose a passkey account" onClose={() => void choose(null)} dismissible={!busy}>
    <div className="w-full max-w-sm rounded-2xl border border-hairline bg-panel p-6 shadow-2xl">
      <h2 className="text-[15px] font-semibold">Sign in to {request.site}</h2>
      <p className="mt-2 text-[13px] text-neutral-400">
        {request.accounts.length === 1 ? "With your passkey for:" : "Choose the account to sign in with:"}
      </p>
      <div className="mt-4 flex flex-col gap-2">
        {request.accounts.map(account => <button key={account.id} disabled={busy}
          onClick={() => void choose(account.id)}
          className="rounded-lg border border-hairline px-4 py-3 text-left text-[14px] hover:bg-fill/5 disabled:opacity-50">
          {account.account || account.title || "Unnamed account"}
        </button>)}
      </div>
      <button disabled={busy} onClick={() => void choose(null)}
        className="mt-4 w-full rounded-lg border border-hairline py-2 text-[13px] disabled:opacity-50">Cancel</button>
    </div>
  </Dialog>;
}
