import { tileColorIndex } from "../lib/format";

/** A colored rounded-square letter tile, as used for each entry. */
export function Tile({
  letter,
  seed,
  size = 34,
}: {
  letter: string;
  seed: string;
  size?: 34 | 56;
}) {
  const color = tileColorIndex(seed);
  return (
    <div
      className={`entry-tile entry-tile-${size} entry-tile-color-${color}`}
      aria-hidden
    >
      {letter}
    </div>
  );
}
