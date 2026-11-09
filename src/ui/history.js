// History: earlier scans, stored locally in IndexedDB, searchable by any
// indicator value (an email, a GA ID, an IP...) across all investigations.

import { h, empty, sev, ago, send, toast, badge, download } from "./dom.js";
import { listReports, searchIndicators, getReport } from "../shared/db.js";
import { INDICATOR_TYPES } from "../core/indicators.js";
import { toJson } from "../core/export.js";

export function render(ctx) {
  const ui = (ctx.S.ui.history ||= { q: "" });
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  const q = h("input", { type: "search", placeholder: "Search history: URL, title, or any indicator (email, IP, GA ID, wallet…)", value: ui.q });
  const list = h("div.card", h("div.status-line", h("div.spin"), "Loading…"));
  const clearBtn = h("button.btn.small.danger", { type: "button" }, "Delete all history");
  clearBtn.addEventListener("click", async () => {
    if (clearBtn.dataset.confirm !== "1") {
      clearBtn.dataset.confirm = "1";
      clearBtn.textContent = "Click again to delete everything";
      return;
    }
    await send("clearHistory");
    toast("History deleted");
    draw();
  });
  const exportAll = h("button.btn.small", { type: "button" }, "Export all (JSON)");
  exportAll.addEventListener("click", async () => {
    const all = await listReports(100000);
    const full = [];
    for (const r of all) full.push(await getReport(r.id));
    download(`osint-lens-history-${new Date().toISOString().slice(0, 10)}.json`, toJson(full), "application/json");
  });
  out.append(h("div.card", { style: { display: "flex", flexDirection: "column", gap: "8px" } }, h("h2", { style: { fontSize: "14px" } }, "History"), q, h("div.row.wrap-row", exportAll, clearBtn), h("div.tiny.faint", "Reports are kept on this computer only. Indicators shared between sites are linked automatically in each report's Overview.")), list);

  let timer;
  const draw = async () => {
    const term = ui.q.trim().toLowerCase();
    const reports = await listReports(500);
    let rows = reports;
    let hits = [];
    if (term) {
      hits = await searchIndicators(term, 300);
      const ids = new Set(hits.map((x) => x.reportId));
      rows = reports.filter((r) => ids.has(r.id) || `${r.url} ${r.title} ${(r.tags || []).join(" ")}`.toLowerCase().includes(term));
    }
    list.replaceChildren();
    if (!rows.length) return list.append(empty(term ? "Nothing matches." : "No scans yet."));
    for (const r of rows.slice(0, 300)) {
      const matched = hits.filter((x) => x.reportId === r.id).slice(0, 4);
      const del = h("button.btn.tiny.ghost", { type: "button", title: "Delete this report" }, "✕");
      del.addEventListener("click", async (e) => {
        e.stopPropagation();
        await send("deleteReport", { reportId: r.id });
        draw();
      });
      list.append(h("div.item", { style: { cursor: "pointer" }, onclick: () => ctx.openReport(r.id) },
        h("div.main",
          h("div.row.wrap-row", r.starred ? "★" : null, h("b.wrap", r.title || r.site), r.risk && r.risk !== "minimal" ? sev(r.risk) : null, r.ai ? badge("AI") : null, r.notes ? badge("notes") : null, (r.tags || []).map((t) => badge(t, "accent"))),
          h("div.meta.wrap", r.url),
          h("div.ctx", `${ago(r.createdAt)} · ${r.indicators} indicators${r.exposures ? ` · ${r.exposures} exposures` : ""}`),
          matched.length ? h("div.meta", "Matches: ", matched.map((m) => `${INDICATOR_TYPES[m.type] || m.type} ${m.value}`).join(", ")) : null
        ),
        h("div.tools", del)
      ));
    }
  };
  q.addEventListener("input", () => {
    ui.q = q.value;
    clearTimeout(timer);
    timer = setTimeout(draw, 200);
  });
  draw().catch((e) => list.replaceChildren(h("div.notice.error", e.message)));
  return out;
}
