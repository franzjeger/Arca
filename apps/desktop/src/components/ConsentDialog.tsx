import { Dialog } from "./Dialog";
import { api, errorMessage, type FillConsent } from "../lib/api";
import { KeyIcon } from "./icons";
import { toastError, type ToastMessage } from "../lib/toast";

/**
 * Blocking Allow/Deny prompt shown when "Confirm before autofill" is on. The
 * bridge thread is parked waiting for the answer, so every path must resolve
 * exactly once; dismissing counts as Deny.
 */
export function ConsentDialog({
  request,
  onResolved,
  onToast,
}: {
  request: FillConsent;
  onResolved: () => void;
  onToast: (msg: ToastMessage) => void;
}) {
  const answer = (approved: boolean) => {
    api
      .resolveAutofillConsent(request.id, approved)
      .catch((e) => onToast(toastError(errorMessage(e))));
    onResolved();
  };

  return (
    <Dialog label="Allow autofill?" onClose={() => answer(false)}>
      <div className="w-full max-w-sm rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex flex-col items-center gap-3 px-6 pt-6 pb-2 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/15 ring-1 ring-accent/30">
            <KeyIcon className="h-6 w-6 text-accent" />
          </div>
          <h2 className="text-[15px] font-semibold text-neutral-100">
            Allow autofill?
          </h2>
          <p className="text-[13px] leading-relaxed text-neutral-400">
            Fill{" "}
            <span className="font-medium text-neutral-100">
              {request.account || request.title}
            </span>{" "}
            into{" "}
            <span className="font-medium text-neutral-100">{request.site}</span>
            ?
          </p>
        </div>

        <div className="flex gap-2 px-6 py-5">
          <button
            autoFocus
            onClick={() => answer(false)}
            className="flex-1 rounded-lg border border-hairline py-2.5 text-[13px] text-neutral-200 hover:bg-fill/5"
          >
            Deny
          </button>
          <button
            onClick={() => answer(true)}
            className="flex-1 rounded-lg bg-accent py-2.5 text-[13px] font-medium text-white hover:bg-accent/90"
          >
            Allow
          </button>
        </div>
      </div>
    </Dialog>
  );
}
