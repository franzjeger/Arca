// Pure picker geometry shared by the live content script and the Node test
// suite. Keeping the arithmetic independent of the DOM makes every edge of
// the viewport testable, including zoomed/mobile visual viewports.
(() => {
  globalThis.__arcaPickerLayout = (
    anchor,
    measuredPanel,
    viewport,
    { gap = 6, margin = 8, minWidth = 240 } = {},
  ) => {
    const viewLeft = Number(viewport.left) || 0;
    const viewTop = Number(viewport.top) || 0;
    const viewWidth = Math.max(0, Number(viewport.width) || 0);
    const viewHeight = Math.max(0, Number(viewport.height) || 0);
    const viewRight = viewLeft + viewWidth;
    const viewBottom = viewTop + viewHeight;
    const usableWidth = Math.max(0, viewWidth - margin * 2);
    const usableHeight = Math.max(0, viewHeight - margin * 2);
    const width = Math.min(
      usableWidth,
      Math.max(Math.min(minWidth, usableWidth), Number(anchor.width) || 0),
    );
    const wantedHeight = Math.min(
      usableHeight,
      Math.max(0, Number(measuredPanel.height) || 0),
    );

    const minLeft = viewLeft + margin;
    const maxLeft = Math.max(minLeft, viewRight - margin - width);
    const left = Math.min(Math.max(Number(anchor.left) || 0, minLeft), maxLeft);

    const below = (Number(anchor.bottom) || 0) + gap;
    const spaceBelow = Math.max(0, viewBottom - margin - below);
    const spaceAbove = Math.max(0, (Number(anchor.top) || 0) - gap - (viewTop + margin));
    const placement = wantedHeight > spaceBelow && spaceAbove > spaceBelow
      ? "above"
      : "below";
    // Scroll the list in the space beside the field. Clamping a full-height
    // list to the viewport instead used to slide it on top of the input.
    const maxHeight = Math.min(usableHeight, placement === "above" ? spaceAbove : spaceBelow);
    const height = Math.min(wantedHeight, maxHeight);
    const wantedTop = placement === "above"
      ? (Number(anchor.top) || 0) - gap - height
      : below;
    const minTop = viewTop + margin;
    const maxTop = Math.max(minTop, viewBottom - margin - height);
    const top = Math.min(Math.max(wantedTop, minTop), maxTop);

    return { left, top, width, maxHeight, placement };
  };
})();
