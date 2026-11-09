// Minimal Markdown renderer that builds DOM nodes (never innerHTML), for model
// answers. Supports headings, paragraphs, lists, code blocks, inline code,
// bold, italics and http(s) links.

import { h } from "./dom.js";

function inline(text) {
  const out = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*\s][^*]*\*)|(\[[^\]]+\]\((https?:\/\/[^)\s]+)\))/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    if (m[1]) out.push(h("code", m[1].slice(1, -1)));
    else if (m[2]) out.push(h("strong", m[2].slice(2, -2)));
    else if (m[3]) out.push(h("em", m[3].slice(1, -1)));
    else if (m[4]) out.push(h("a", { href: m[5], target: "_blank", rel: "noopener noreferrer" }, m[4].slice(1, m[4].indexOf("]"))));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function renderMarkdown(src) {
  const root = h("div.md");
  const lines = String(src || "").replace(/\r\n?/g, "\n").split("\n");
  let i = 0;
  let para = [];
  const flush = () => {
    if (para.length) root.append(h("p", inline(para.join(" "))));
    para = [];
  };
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      flush();
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      root.append(h("pre", h("code", buf.join("\n"))));
      continue;
    }
    const hd = /^(#{1,6})\s+(.*)$/.exec(line);
    if (hd) {
      flush();
      root.append(h(`h${Math.min(4, hd[1].length + 1)}`, inline(hd[2])));
      i++;
      continue;
    }
    if (/^\s*([-*+]|\d+[.)])\s+/.test(line)) {
      flush();
      const ordered = /^\s*\d/.test(line);
      const list = h(ordered ? "ol" : "ul");
      while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
        list.append(h("li", inline(lines[i].replace(/^\s*([-*+]|\d+[.)])\s+/, ""))));
        i++;
      }
      root.append(list);
      continue;
    }
    if (!line.trim()) flush();
    else para.push(line.trim());
    i++;
  }
  flush();
  return root;
}
