// Injected into the page by the side panel to highlight findings and scroll to them.
// Chrome serialises this function and runs it in the page, so it must be
// self-contained: no imports and no references to anything outside it.
//
// cmd = {
//   action: "set" | "clear",
//   items: [{ id, value, matchHref, hrefOnly }],
//   focus: { id, index } | null,   // which match to scroll to
//   scroll: boolean
// }
// Returns { counts: { [id]: matchesFound }, focus: { id, index, total } | null }

export function oslHighlight(cmd) {
  const S = window.__oslHighlightState || (window.__oslHighlightState = { outlined: [], boxTimers: [] });
  const hasHL = typeof CSS !== "undefined" && CSS.highlights && typeof Highlight === "function";

  // Clear previous highlights. Restore outlines in reverse, in case one element was outlined twice.
  if (hasHL) {
    CSS.highlights.delete("osl-match");
    CSS.highlights.delete("osl-focus");
  }
  for (let i = S.outlined.length - 1; i >= 0; i--) {
    const [el, outline, offset] = S.outlined[i];
    el.style.outline = outline;
    el.style.outlineOffset = offset;
  }
  S.outlined = [];
  S.boxTimers.forEach(clearTimeout);
  S.boxTimers = [];
  document.getElementById("osl-focus-box")?.remove();
  if (S.onScrollEnd) window.removeEventListener("scrollend", S.onScrollEnd, true);

  if (cmd.action === "clear") return { counts: {}, focus: null };

  if (!document.getElementById("osl-style")) {
    const st = document.createElement("style");
    st.id = "osl-style";
    st.textContent = `
      ::highlight(osl-match) { background-color: #ffe066; color: #111; }
      ::highlight(osl-focus) { background-color: #ff8a3d; color: #111; }
      @keyframes osl-pulse { 0%, 65% { opacity: 1; } 100% { opacity: 0; } }`;
    (document.head || document.documentElement).append(st);
  }

  // One long string of all the page's text, plus where each text node starts in it.
  const nodes = [];
  let full = "";
  if (document.body) {
    const SKIP = /^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE|TEXTAREA|SELECT|OPTION)$/;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        const p = n.parentElement;
        if (!p || SKIP.test(p.tagName) || p.id === "osl-focus-box") return NodeFilter.FILTER_REJECT;
        return n.nodeValue ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    for (let n; (n = walker.nextNode()); ) {
      nodes.push({ n, start: full.length });
      full += n.nodeValue;
    }
  }

  // Map a position in `full` back to (text node, offset).
  const locate = (pos, isEnd) => {
    const p = isEnd ? pos - 1 : pos;
    let lo = 0, hi = nodes.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (nodes[mid].start <= p) lo = mid; else hi = mid - 1;
    }
    return [nodes[lo].n, pos - nodes[lo].start];
  };

  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const outline = (el, style) => {
    S.outlined.push([el, el.style.outline, el.style.outlineOffset]);
    el.style.outline = style;
    el.style.outlineOffset = "2px";
  };

  const counts = {};
  const matchRanges = [];
  let focusTarget = null;
  let focusOut = null;

  for (const item of cmd.items) {
    const v = String(item.value || "").trim();
    const targets = [];

    if (v.length >= 2) {
      // Text on the page. Whitespace is flexible because page text and the
      // scanned text can differ in spaces and line breaks.
      if (!item.hrefOnly && nodes.length) {
        const re = new RegExp(escapeRe(v).replace(/\s+/g, "\\s*"), "gi");
        for (const m of full.matchAll(re)) {
          if (!m[0]) continue;
          const r = document.createRange();
          try {
            r.setStart(...locate(m.index, false));
            r.setEnd(...locate(m.index + m[0].length, true));
          } catch {
            continue;
          }
          if (r.getClientRects().length) targets.push({ range: r });
          if (targets.length >= 200) break;
        }
      }

      // Form fields whose value contains it, and (for URLs) links pointing to it.
      const lower = v.toLowerCase();
      const selector = item.matchHref ? "input, textarea, a[href], area[href]" : "input, textarea";
      for (const el of document.querySelectorAll(selector)) {
        const hay = el.matches("a, area") ? el.href : el.value;
        if (typeof hay === "string" && hay.toLowerCase().includes(lower) && el.getClientRects().length) {
          const r = document.createRange();
          r.selectNode(el);
          targets.push({ range: r, el });
        }
      }
    }

    targets.sort((a, b) => a.range.compareBoundaryPoints(Range.START_TO_START, b.range));
    counts[item.id] = targets.length;
    for (const t of targets) {
      if (t.el) outline(t.el, "2px solid #ffb300");
      else matchRanges.push(t.range);
    }

    if (cmd.focus && cmd.focus.id === item.id && targets.length) {
      const index = ((cmd.focus.index % targets.length) + targets.length) % targets.length;
      focusTarget = targets[index];
      focusOut = { id: item.id, index, total: targets.length };
    }
  }

  if (hasHL) {
    if (matchRanges.length) CSS.highlights.set("osl-match", new Highlight(...matchRanges));
    if (focusTarget && !focusTarget.el) CSS.highlights.set("osl-focus", new Highlight(focusTarget.range));
  }

  if (focusTarget) {
    if (focusTarget.el) outline(focusTarget.el, "3px solid #ff5722");

    if (cmd.scroll) {
      const anchor = focusTarget.el || focusTarget.range.startContainer.parentElement;
      anchor?.scrollIntoView({ block: "center", inline: "nearest", behavior: "smooth" });

      // Draw a short-lived box around the match once scrolling settles.
      const drawBox = () => {
        document.getElementById("osl-focus-box")?.remove();
        const rect = focusTarget.range.getBoundingClientRect();
        if (!rect.width && !rect.height) return;
        const box = document.createElement("div");
        box.id = "osl-focus-box";
        Object.assign(box.style, {
          position: "fixed",
          left: `${rect.left - 5}px`,
          top: `${rect.top - 5}px`,
          width: `${rect.width + 10}px`,
          height: `${rect.height + 10}px`,
          border: "3px solid #ff5722",
          borderRadius: "6px",
          boxShadow: "0 0 0 5px rgba(255, 87, 34, .25)",
          pointerEvents: "none",
          zIndex: "2147483647",
          animation: "osl-pulse 2.6s ease-out forwards"
        });
        document.documentElement.append(box);
        S.boxTimers.push(setTimeout(() => box.remove(), 2700));
      };
      S.onScrollEnd = drawBox;
      window.addEventListener("scrollend", drawBox, { once: true, capture: true });
      S.boxTimers.push(setTimeout(drawBox, 600));
    }
  }

  return { counts, focus: focusOut };
}
