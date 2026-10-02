import { useCallback, useEffect, useState } from "react";
import { Dialog } from "./Dialog";
import {
  api,
  errorMessage,
  type DuplicateGroup,
  type DuplicateLogin,
} from "../lib/api";

function edited(modifiedAt: number): string {
  return new Date(modifiedAt).toLocaleDateString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}

function Badge({ children, warn = false }: { children: string; warn?: boolean }) {
  return (
    <span
      className={`rounded px-1.5 py-px text-[10px] ${
        warn ? "bg-amber-500/15 text-amber-300" : "bg-fill/10 text-neutral-400"
      }`}
    >
      {children}
    </span>
  );
}

/** One group: whether to merge it, and which login to keep. */
function Group({
  group,
  index,
  merge,
  keep,
  disabled,
  onMerge,
  onKeep,
}: {
  group: DuplicateGroup;
  index: number;
  merge: boolean;
  keep: string;
  disabled: boolean;
  onMerge: (merge: boolean) => void;
  onKeep: (id: string) => void;
}) {
  const kept = group.logins.find((login) => login.id === keep);
  const name = kept?.title || kept?.site || "these logins";
  return (
    <li className="rounded-lg bg-fill/5 px-3 py-2.5 ring-1 ring-line/10">
      <label className="flex items-center gap-2 text-[13px] text-neutral-100">
        <input
          type="checkbox"
          checked={merge}
          disabled={disabled}
          onChange={(event) => onMerge(event.target.checked)}
        />
        Merge {group.logins.length} logins for {name}
      </label>
      {/* mt-3.5: the gap Tailwind 3 drew here. Its `space-y` put a top margin
          on every child after the first, and the first is the sr-only legend,
          so the first login sat 6px lower than `mt-2` alone; Tailwind 4's
          `space-y` puts a bottom margin on all but the last instead. */}
      <fieldset className="mt-3.5 space-y-1.5" disabled={disabled}>
        <legend className="sr-only">Login to keep for {name}</legend>
        {group.logins.map((login: DuplicateLogin) => (
          <label
            key={login.id}
            className="flex cursor-pointer items-start gap-2 rounded-md px-2 py-1.5 hover:bg-fill/5"
          >
            <input
              type="radio"
              name={`keep-${index}`}
              className="mt-0.5"
              checked={login.id === keep}
              onChange={() => onKeep(login.id)}
            />
            <span className="min-w-0">
              <span className="block truncate text-[13px] text-neutral-100">
                {login.title || login.site}
                {login.id === keep && (
                  <span className="ml-2 text-[11px] text-accent">Kept</span>
                )}
              </span>
              <span className="block truncate text-[11px] text-neutral-500">
                {[login.site, login.username].filter(Boolean).join(" · ")}
              </span>
              <span className="mt-1 flex flex-wrap items-center gap-1 text-[10px] text-neutral-500">
                <span>Edited {edited(login.modifiedAt)}</span>
                {!login.hasPassword && <Badge>No password</Badge>}
                {login.hasPassword && kept && login.password !== kept.password && (
                  <Badge warn>Different password</Badge>
                )}
                {login.hasTotp && <Badge>TOTP</Badge>}
                {login.hasNotes && <Badge>Notes</Badge>}
              </span>
            </span>
          </label>
        ))}
      </fieldset>
    </li>
  );
}

/**
 * Find & merge duplicate logins, after looking at them.
 *
 * Nothing is merged until someone has seen what would be: each group shows
 * its logins and which one is kept. Logins for one site and username are
 * ticked; the same username on related sites (accounts.google.com and
 * google.com) is only offered. The merge applies only if every login shown is
 * unchanged since.
 */
export function DuplicatesDialog({
  onClose,
  onMerged,
}: {
  onClose: () => void;
  onMerged: (merged: number) => void;
}) {
  const [groups, setGroups] = useState<DuplicateGroup[] | null>(null);
  const [merge, setMerge] = useState<boolean[]>([]);
  const [keep, setKeep] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const look = useCallback(() => {
    setGroups(null);
    setError(null);
    api
      .findDuplicates()
      .then((found) => {
        setGroups(found);
        setMerge(found.map((group) => !group.possible));
        setKeep(found.map((group) => group.keep));
      })
      .catch((e) => {
        setGroups([]);
        setError(errorMessage(e));
      });
  }, []);
  useEffect(look, [look]);

  const chosen = (groups ?? []).filter((_, i) => merge[i]).length;

  const run = async () => {
    if (!groups) return;
    setBusy(true);
    setError(null);
    try {
      const choices = groups.flatMap((group, i) =>
        merge[i] ? [{ keep: keep[i], ids: group.logins.map((login) => login.id) }] : [],
      );
      // A login can be in two groups: a possible match can include the
      // login a group of the same account keeps.
      const shown = [
        ...new Map(
          groups.flatMap((group) => group.logins.map(({ id, revision }) => [id, { id, revision }] as const)),
        ).values(),
      ];
      onMerged(await api.mergeDuplicates(choices, shown));
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };

  const same = (groups ?? []).map((group, i) => ({ group, i })).filter(({ group }) => !group.possible);
  const possible = (groups ?? []).map((group, i) => ({ group, i })).filter(({ group }) => group.possible);
  const section = (entries: typeof same) => (
    <ul className="space-y-2">
      {entries.map(({ group, i }) => (
        <Group
          key={group.keep}
          group={group}
          index={i}
          merge={merge[i]}
          keep={keep[i]}
          disabled={busy}
          onMerge={(value) => setMerge((all) => all.map((m, j) => (j === i ? value : m)))}
          onKeep={(id) => setKeep((all) => all.map((k, j) => (j === i ? id : k)))}
        />
      ))}
    </ul>
  );

  return (
    <Dialog label="Duplicate logins" onClose={onClose} dismissible={!busy}>
      <div className="flex max-h-[85vh] w-full max-w-lg flex-col rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="border-b border-hairline px-5 py-3.5">
          <h2 className="text-[14px] font-semibold text-neutral-100">Duplicate logins</h2>
          <p className="mt-1 text-[11px] leading-snug text-neutral-500">
            Logins saved more than once. The one you keep stays as it is; the
            others go to the Trash, and their passwords into its password
            history.
          </p>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-3">
          {error && (
            <div role="alert" className="rounded-lg bg-red-950/60 px-3 py-2 text-[12px] text-red-200 ring-1 ring-red-500/30">
              {error}{" "}
              <button type="button" className="underline" onClick={look}>
                Look again
              </button>
            </div>
          )}
          {groups === null ? (
            <p className="py-6 text-center text-[13px] text-neutral-500">Looking for duplicates…</p>
          ) : groups.length === 0 ? (
            !error && <p className="py-6 text-center text-[13px] text-neutral-500">No duplicates found.</p>
          ) : (
            <>
              {same.length > 0 && (
                <section aria-label="Same site and username">
                  <h3 className="mb-2 text-[12px] font-medium text-neutral-300">Same site and username</h3>
                  {section(same)}
                </section>
              )}
              {possible.length > 0 && (
                <section aria-label="Possibly the same account">
                  <h3 className="text-[12px] font-medium text-neutral-300">Possibly the same account</h3>
                  <p className="mb-2 mt-0.5 text-[11px] leading-snug text-neutral-500">
                    The same username on related sites, such as
                    accounts.google.com and google.com. Tick the ones that are
                    one account.
                  </p>
                  {section(possible)}
                </section>
              )}
            </>
          )}
        </div>

        <div className="flex shrink-0 justify-end gap-2 border-t border-hairline px-5 py-3">
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            className="rounded-lg px-3 py-1.5 text-[13px] text-neutral-400 hover:text-neutral-200 disabled:opacity-50"
          >
            {groups?.length ? "Cancel" : "Close"}
          </button>
          {!!groups?.length && (
            <button
              type="button"
              onClick={() => void run()}
              disabled={busy || chosen === 0}
              className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {busy ? "Merging…" : `Merge ${chosen} ${chosen === 1 ? "group" : "groups"}`}
            </button>
          )}
        </div>
      </div>
    </Dialog>
  );
}
