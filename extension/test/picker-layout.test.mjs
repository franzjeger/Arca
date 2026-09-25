import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = fs.readFileSync(
  path.join(here, "../chromium/picker-layout.js"),
  "utf8",
);
const context = vm.createContext({});
vm.runInContext(source, context);
const layout = context.__arcaPickerLayout;

const viewport = { left: 0, top: 0, width: 800, height: 600 };

const bottomRight = layout(
  { left: 750, top: 550, bottom: 584, width: 180 },
  { height: 240 },
  viewport,
);
assert.equal(bottomRight.placement, "above");
assert.ok(bottomRight.left >= 8);
assert.ok(bottomRight.left + bottomRight.width <= 792);
assert.ok(bottomRight.top >= 8);
assert.ok(bottomRight.top + 240 <= 592);

const topLeft = layout(
  { left: -40, top: 10, bottom: 42, width: 120 },
  { height: 180 },
  viewport,
);
assert.equal(topLeft.placement, "below");
assert.equal(topLeft.left, 8);
assert.ok(topLeft.top >= 8);

const zoomed = layout(
  { left: 315, top: 220, bottom: 250, width: 80 },
  { height: 900 },
  { left: 100, top: 75, width: 320, height: 260 },
);
assert.ok(zoomed.left >= 108);
assert.ok(zoomed.left + zoomed.width <= 412);
assert.ok(zoomed.top >= 83);
assert.ok(zoomed.top + zoomed.maxHeight <= 327);

for (const top of [30, 140, 280, 450, 540]) {
  const anchor = { left: 100, top, bottom: top + 34, width: 260 };
  const result = layout(anchor, { height: 900 }, viewport);
  const bottom = result.top + result.maxHeight;
  assert.ok(bottom <= anchor.top - 6 || result.top >= anchor.bottom + 6,
    `a long list must scroll instead of covering the field at ${top}`);
  assert.ok(result.top >= 8 && bottom <= 592);
}

console.log("picker layout: 8 viewport and field-overlap cases passed");
