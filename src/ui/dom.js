// Tiny DOM helpers. Every piece of page or model content is inserted as text
// (textContent / attributes), never as HTML, so a hostile page or a
// manipulated model answer can't inject script into the extension.

/**
 * h("div.card#id", { onclick, title, dataset: {...}, class: "x" }, child, "text", [children])
 */
export function h(sel, attrs, ...children) {
  const m = /^([a-z0-9-]+)?((?:[.#][\w-]+)*)$/i.exec(sel) || [];
  const el = document.createElement(m[1] || "div");
  for (const part of (m[2] || "").match(/[.#][\w-]+/g) || []) {
    if (part[0] === ".") el.classList.add(part.slice(1));
    else el.id = part.slice(1);
  }
  if (attrs && (typeof attrs !== "object" || attrs instanceof Node || Array.isArray(attrs))) {
    children.unshift(attrs);
    attrs = null;
  }
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "class") String(v).split(/\s+/).filter(Boolean).forEach((c) => el.classList.add(c));
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else if (k === "value") el.value = v;
    else if (k === "checked" || k === "disabled" || k === "selected" || k === "open" || k === "hidden") el[k] = !!v;
    else if (k === "href") {
      // Only web and extension links are clickable.
      if (/^(https?:|mailto:|chrome-extension:|#|blob:)/i.test(String(v))) el.setAttribute("href", v);
    } else el.setAttribute(k, v === true ? "" : v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children) {
    if (c == null || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export const clear = (el) => {
  while (el.firstChild) el.firstChild.remove();
  return el;
};

/** External link that opens in a new tab without leaking the referrer. */
export const ext = (href, text, cls) => h(`a${cls ? `.${cls}` : ""}`, { href, target: "_blank", rel: "noopener noreferrer", title: href }, text ?? href);

export const fmtDate = (d) => {
  if (!d) return "—";
  const x = new Date(d);
  return Number.isNaN(x.getTime()) ? String(d) : x.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};
export const fmtDay = (d) => {
  if (!d) return "—";
  const x = new Date(d);
  return Number.isNaN(x.getTime()) ? String(d) : x.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
};

export function ago(d) {
  const s = (Date.now() - new Date(d).getTime()) / 1000;
  if (!Number.isFinite(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 60) return `${Math.floor(s / 86400)} d ago`;
  return fmtDay(d);
}

export function sev(level) {
  return h(`span.sev.sev-${level || "info"}`, level || "info");
}

export const badge = (text, cls = "") => h(`span.badge${cls ? `.${cls}` : ""}`, text);

/** Copy text and flash the button. */
export async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(String(text));
    if (btn) {
      const old = btn.textContent;
      btn.textContent = "Copied";
      btn.classList.add("ok");
      setTimeout(() => {
        btn.textContent = old;
        btn.classList.remove("ok");
      }, 1100);
    }
  } catch {
    /* clipboard can be blocked; ignore */
  }
}

export const copyBtn = (text, label = "Copy") => {
  const b = h("button.btn.tiny.ghost", { title: "Copy to clipboard", type: "button" }, label);
  b.addEventListener("click", (e) => {
    e.stopPropagation();
    copy(typeof text === "function" ? text() : text, b);
  });
  return b;
};

/** Collapsible section. */
export function section(title, body, { open = true, count = null, actions = null, id = null } = {}) {
  const d = h("details.section", { open, id });
  d.append(h("summary", h("span.section-title", title), count != null ? h("span.count", String(count)) : null, actions ? h("span.section-actions", { onclick: (e) => e.stopPropagation() }, actions) : null));
  d.append(h("div.section-body", body));
  return d;
}

/** Key/value table. */
export function kv(rows) {
  return h("table.kv", h("tbody", rows.filter((r) => r && r[1] != null && r[1] !== "").map(([k, v]) => h("tr", h("th", k), h("td", v instanceof Node || Array.isArray(v) ? v : String(v))))));
}

export function empty(text) {
  return h("p.empty", text);
}

/** Show up to `n` items with a "show more" button. */
export function limited(items, render, n = 100) {
  const wrap = h("div.list");
  let shown = 0;
  const more = h("button.btn.ghost.small.more", { type: "button" });
  const step = () => {
    const next = items.slice(shown, shown + n);
    for (const it of next) wrap.insertBefore(render(it), more.parentNode ? more : null);
    shown += next.length;
    if (shown >= items.length) more.remove();
    else {
      more.textContent = `Show ${Math.min(n, items.length - shown)} more (${items.length - shown} left)`;
      if (!more.parentNode) wrap.append(more);
    }
  };
  more.addEventListener("click", step);
  step();
  return wrap;
}

/** Send a message to the service worker and unwrap {ok, result, error}. */
export async function send(type, payload = {}) {
  const res = await chrome.runtime.sendMessage({ type, ...payload });
  if (!res) throw new Error("No response from the extension background. Try reloading the extension.");
  if (!res.ok) throw new Error(res.error || "Unknown error");
  return res.result;
}

/** Trigger a file download from text or bytes (no downloads permission needed). */
export function download(filename, data, mime = "application/octet-stream") {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

/** Safe file-name stem from a host/title. */
export const fileStem = (s) => String(s || "report").replace(/^https?:\/\//, "").replace(/[^a-z0-9.\-_]+/gi, "_").slice(0, 60);

/** Small toast message. */
export function toast(text, kind = "info") {
  let box = document.getElementById("toasts");
  if (!box) {
    box = h("div#toasts");
    document.body.append(box);
  }
  const t = h(`div.toast.${kind}`, text);
  box.append(t);
  setTimeout(() => t.classList.add("out"), 3200);
  setTimeout(() => t.remove(), 3700);
}

/** Simple dropdown menu anchored to a button. items: [{label, onclick} | {label, href}] */
export function menu(btn, items) {
  document.querySelectorAll(".menu-pop").forEach((m) => m.remove());
  const pop = h("div.menu-pop", { role: "menu" }, items.map((it) =>
    it.href ? ext(it.href, it.label, "menu-item") : h("button.menu-item", { type: "button", onclick: () => (pop.remove(), it.onclick()) }, it.label)
  ));
  document.body.append(pop);
  const r = btn.getBoundingClientRect();
  const w = Math.min(280, window.innerWidth - 16);
  pop.style.minWidth = `${Math.min(200, w)}px`;
  pop.style.maxWidth = `${w}px`;
  pop.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - w - 8))}px`;
  const below = r.bottom + 4;
  pop.style.top = `${below}px`;
  requestAnimationFrame(() => {
    const ph = pop.getBoundingClientRect().height;
    if (below + ph > window.innerHeight - 8) pop.style.top = `${Math.max(8, r.top - ph - 4)}px`;
  });
  const close = (e) => {
    if (!pop.contains(e.target) && e.target !== btn) {
      pop.remove();
      document.removeEventListener("mousedown", close, true);
    }
  };
  setTimeout(() => document.addEventListener("mousedown", close, true));
  pop.addEventListener("click", (e) => {
    if (e.target.closest("a")) pop.remove();
  });
  return pop;
}
