// Exposures: secrets, credentials and personal data found on the page.
// Values are masked until "Show full values" is ticked.

import { h, empty, limited, copyBtn, sev, section } from "../dom.js";

export function render(ctx) {
  const r = ctx.S.report;
  const out = h("div", { style: { display: "flex", flexDirection: "column", gap: "10px" } });
  const reveal = h("label.check.small", h("input", { type: "checkbox", checked: ctx.S.reveal, onchange: (e) => ((ctx.S.reveal = e.target.checked), ctx.rerender()) }), h("span", "Show full values"));
  const hlAll = h("button.btn.small", { type: "button", disabled: !ctx.isCurrentTab(), onclick: async () => {
    for (const e of r.exposures) ctx.S.hl.set(`exp:${e.id}:${e.value}`, { id: `exp:${e.id}:${e.value}`, value: e.value, matchHref: e.id === "url_credential" });
    await ctx.highlight(`exp:${r.exposures[0]?.id}:${r.exposures[0]?.value}`, { value: r.exposures[0]?.value || "" });
  } }, "Highlight all");
  const clr = h("button.btn.small.ghost", { type: "button", onclick: async () => (await ctx.clearHighlights(), ctx.rerender()) }, "Clear highlights");

  const card = h("div.card", { style: { display: "flex", flexDirection: "column", gap: "8px" } },
    h("div.row.wrap-row", reveal, h("div.spacer"), r.exposures.length ? [hlAll, clr] : null),
    r.exposures.length
      ? limited(r.exposures, (e) => item(ctx, e), 100)
      : empty("No secrets, credentials or personal data matched the pattern checks. The AI's exposure audit can catch what patterns can't (salaries, health data, addresses, confidential text).")
  );
  out.append(card);

  const fv = r.forms.flatMap((f) => f.fields.filter((x) => x.filled));
  if (fv.length) out.append(h("div.notice.warn", h("div", h("b", "A password field is filled in. "), "Its value is never read or stored by this extension.")));
  out.append(section("How this works", h("div.small.muted",
    h("p", "Patterns cover private keys, cloud and SaaS tokens (AWS, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, Twilio, SendGrid, npm, …), database URLs with passwords, JWTs (decoded), payment cards (Luhn), IBANs (mod-97), US SSNs and Finnish personal identity codes (check character)."),
    h("p", "They run over the visible text, the HTML source, HTML comments, inline and same-site scripts, runtime config objects, link URLs and (if enabled) typed form values. Checksums cut false positives, but treat every match as a lead to verify.")
  ), { open: false }));
  return out;
}

function item(ctx, e) {
  const id = `exp:${e.id}:${e.value}`;
  const shown = ctx.S.reveal ? e.value : e.masked;
  const checked = ctx.S.hl.has(id);
  const box = h("input", { type: "checkbox", checked, title: "Highlight on the page", disabled: !ctx.isCurrentTab() });
  box.addEventListener("change", () => ctx.highlight(id, { value: e.value, matchHref: e.id === "url_credential" }, { toggle: true, focus: box.checked }));
  const go = h("button.btn.tiny.ghost", { type: "button", title: "Go to the next place it appears", disabled: !ctx.isCurrentTab() }, "Go to ›");
  go.addEventListener("click", async () => {
    box.checked = true;
    const res = await ctx.highlight(id, { value: e.value, matchHref: e.id === "url_credential" }, { focus: true });
    if (res?.focus) go.textContent = `${res.focus.index + 1} of ${res.focus.total} ›`;
    else if (res) go.textContent = "not visible";
  });
  const extra = Object.entries(e.extra || {}).filter(([k, v]) => v != null && v !== "" && k !== "url").map(([k, v]) => `${k}: ${v}`).join(" · ");
  return h("div.item",
    box,
    h("div.main",
      h("div.row.wrap-row", sev(e.severity), h("b", e.label)),
      h("div.value", shown),
      extra ? h("div.meta", extra) : null,
      h("div.ctx", ctx.S.reveal ? e.context : e.context.split(e.value).join(e.masked)),
      h("div.meta", `Found in: ${e.source}`)
    ),
    h("div.tools", go, ctx.S.reveal ? copyBtn(e.value) : null)
  );
}
