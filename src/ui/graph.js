// A small force-directed relationship graph (SVG, no libraries): the site in
// the middle, its identifiers around it, and earlier investigations that share
// an identifier linked through it.

const NS = "http://www.w3.org/2000/svg";
const COLORS = {
  site: "#0f766e", tracker: "#7c3aed", verification: "#7c3aed", api_key_public: "#7c3aed", email: "#2563eb", phone: "#2563eb", social: "#db2777",
  ip: "#ea580c", asn: "#ea580c", organization: "#16a34a", person: "#16a34a", crypto: "#ca8a04", domain: "#64748b", favicon: "#7c3aed", other: "#0ea5e9", bucket: "#dc2626", onion: "#dc2626"
};
const PICK = ["tracker", "verification", "api_key_public", "favicon", "email", "phone", "social", "crypto", "organization", "person", "ip", "asn", "onion", "bucket"];

const svg = (tag, attrs = {}) => {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
};

export function relationshipGraph(report, ctx) {
  const nodes = [{ id: "site", label: report.page.site, type: "site", r: 11, fixed: true }];
  const edges = [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const node = (id, label, type, ind) => {
    if (!byId.has(id)) {
      const n = { id, label, type, r: type === "other" ? 7 : 5.5, ind };
      nodes.push(n);
      byId.set(id, n);
    }
    return byId.get(id);
  };
  const perType = {};
  for (const i of report.indicators) {
    if (!PICK.includes(i.type) || i.extra?.private) continue;
    if ((perType[i.type] = (perType[i.type] || 0) + 1) > (i.type === "ip" ? 6 : 8)) continue;
    if (i.type === "email" && i.confidence === "low") continue;
    const n = node(`${i.type}|${i.value}`, i.label && i.type === "tracker" ? `${i.value}` : i.value, i.type, i);
    edges.push(["site", n.id]);
  }
  for (const c of (report.correlations || []).slice(0, 12)) {
    const key = `${c.type}|${c.value}`;
    const n = node(key, c.value, c.type, { type: c.type, value: c.value, label: c.label });
    if (!edges.some(([a, b]) => a === "site" && b === key)) edges.push(["site", key]);
    for (const o of c.others.slice(0, 4)) {
      const s = node(`other|${o.site}`, o.site, "other");
      s.reportId = o.reportId;
      edges.push([n.id, s.id]);
    }
  }
  if (nodes.length > 90) nodes.length = 90;

  // --- Layout: simple force simulation -----------------------------------------
  const W = 600, H = 400;
  nodes.forEach((n, i) => {
    const a = (i / nodes.length) * Math.PI * 2;
    n.x = n.fixed ? W / 2 : W / 2 + Math.cos(a) * 140 + (Math.random() - 0.5) * 20;
    n.y = n.fixed ? H / 2 : H / 2 + Math.sin(a) * 110 + (Math.random() - 0.5) * 20;
    n.vx = n.vy = 0;
  });
  const E = edges.map(([a, b]) => [byId.get(a), byId.get(b)]).filter(([a, b]) => a && b);
  for (let it = 0; it < 300; it++) {
    const k = 1 - it / 300;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        const d2 = Math.max(dx * dx + dy * dy, 25);
        const f = (1600 / d2) * k;
        dx *= f / Math.sqrt(d2);
        dy *= f / Math.sqrt(d2);
        a.vx += dx; a.vy += dy; b.vx -= dx; b.vy -= dy;
      }
    }
    for (const [a, b] of E) {
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const target = a.fixed || b.fixed ? 120 : 70;
      const f = ((d - target) / d) * 0.05;
      a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
    }
    for (const n of nodes) {
      if (n.fixed) continue;
      n.vx *= 0.6; n.vy *= 0.6;
      n.x = Math.max(20, Math.min(W - 20, n.x + n.vx));
      n.y = Math.max(16, Math.min(H - 16, n.y + n.vy));
    }
  }

  // --- Render ----------------------------------------------------------------------
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "graph", role: "img", "aria-label": "Relationship graph" });
  for (const [a, b] of E) root.append(svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: "currentColor", "stroke-opacity": b.type === "other" ? 0.55 : 0.18, "stroke-width": b.type === "other" ? 1.5 : 1 }));
  for (const n of nodes) {
    const g = svg("g", { style: "cursor:pointer" });
    const c = svg("circle", { cx: n.x, cy: n.y, r: n.r, fill: COLORS[n.type] || COLORS.domain, stroke: "var(--panel)", "stroke-width": 1.5 });
    const title = svg("title");
    title.textContent = n.type === "other" ? `Earlier investigation: ${n.label}` : `${n.ind?.label ? `${n.ind.label}: ` : ""}${n.label}`;
    c.append(title);
    const t = svg("text", { x: n.x + n.r + 3, y: n.y + 3 });
    t.textContent = n.label.length > 26 ? `${n.label.slice(0, 25)}…` : n.label;
    g.append(c, t);
    g.addEventListener("click", (e) => {
      if (n.type === "other" && n.reportId) ctx.openReport(n.reportId);
      else if (n.ind) ctx.pivotMenu(e.currentTarget, n.ind);
    });
    root.append(g);
  }
  const wrap = document.createElement("div");
  wrap.style.color = "var(--faint)";
  wrap.append(root);
  const legend = document.createElement("div");
  legend.className = "tiny faint";
  legend.textContent = nodes.length > 1 ? "Click a node for pivots. Grey links lead to sites from your earlier scans that share an identifier." : "Not enough identifiers for a graph yet.";
  wrap.append(legend);
  return wrap;
}
