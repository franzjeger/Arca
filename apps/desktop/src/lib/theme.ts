// Light/dark theme control.
//
// The palette lives in styles.css as CSS variables. This module only decides
// which variable set is active by setting `data-theme` on <html>:
//   - "system": remove the attribute, so the OS appearance (prefers-color-scheme)
//     drives it, and re-render on OS changes.
//   - "light" / "dark": pin that appearance regardless of the OS.
//
// The choice is persisted in localStorage so it survives restarts, and applied
// before React mounts (see main.tsx) to avoid a flash of the wrong theme.

import { useSyncExternalStore } from "react";

export type ThemePref = "system" | "light" | "dark";
export type Effective = "light" | "dark";

const STORAGE_KEY = "arca.theme";

const listeners = new Set<() => void>();
const media = () =>
  typeof window !== "undefined" && window.matchMedia
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : null;

function notify() {
  for (const l of listeners) l();
}

export function getStoredPref(): ThemePref {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    /* private mode / unavailable — fall through to default */
  }
  return "system";
}

/** The appearance currently on screen for a given preference. */
export function resolveEffective(pref: ThemePref): Effective {
  if (pref === "light" || pref === "dark") return pref;
  return media()?.matches ? "dark" : "light";
}

/** Write `data-theme` on <html> for the given preference. */
export function applyPref(pref: ThemePref): void {
  const root = document.documentElement;
  if (pref === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", pref);
}

/** Persist + apply a preference and notify subscribers. */
export function setPref(pref: ThemePref): void {
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    /* ignore persistence failures — the applied theme still takes effect */
  }
  applyPref(pref);
  notify();
}

/** Apply the stored preference. Call once, before React mounts. */
export function initTheme(): void {
  applyPref(getStoredPref());
  // Keep "system" live: re-render/notify when the OS appearance flips.
  media()?.addEventListener?.("change", () => {
    if (getStoredPref() === "system") notify();
  });
}

const ORDER: ThemePref[] = ["system", "light", "dark"];

/**
 * Advance the preference: System (follow OS) → Light → Dark → System. "System"
 * tracks the OS appearance live; the other two pin it.
 */
export function cycleTheme(): void {
  const cur = getStoredPref();
  setPref(ORDER[(ORDER.indexOf(cur) + 1) % ORDER.length]);
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

/** React hook: current preference + the appearance actually on screen. */
export function useTheme(): { pref: ThemePref; effective: Effective } {
  const serverPref = (): ThemePref => "system";
  const pref = useSyncExternalStore(subscribe, getStoredPref, serverPref);
  return { pref, effective: resolveEffective(pref) };
}
