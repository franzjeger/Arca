// Small presentation helpers (no secrets pass through here).

/** Pick one of the statically defined tile colors without creating inline CSS. */
export function tileColorIndex(seed: string): number {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = (hash * 31 + seed.charCodeAt(i)) | 0;
  }
  return Math.abs(hash) % 8;
}

/** Format a 6-digit TOTP as "123 456" like the system UI. */
export function formatTotp(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  return code;
}

/** Strip scheme/path so "https://github.com/x" renders as "github.com". */
export function hostFromUrl(url: string): string {
  if (!url) return "";
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).host;
  } catch {
    return url;
  }
}

export function relativeTime(unixMillis: number): string {
  if (!unixMillis) return "";
  const diffMs = Date.now() - unixMillis;
  const sec = Math.round(diffMs / 1000);
  if (sec < 60) return "just now";
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr} hour${hr === 1 ? "" : "s"} ago`;
  const days = Math.round(hr / 24);
  if (days < 30) return `${days} day${days === 1 ? "" : "s"} ago`;
  return new Date(unixMillis).toLocaleDateString();
}
