// Server-Sent Events parser over a fetch() response body (WHATWG EventSource
// parsing rules). EventSource itself can't send custom headers or POST, which
// MCP needs, so we parse the stream by hand.

/**
 * @param {ReadableStream<Uint8Array>} body
 * @returns {AsyncGenerator<{event:string, data:string, id:string|null}>}
 */
export async function* readSse(body) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let data = [];
  let event = "";
  let id = null;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buf.search(/\r\n|\r|\n/)) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + (buf[nl] === "\r" && buf[nl + 1] === "\n" ? 2 : 1));
        if (line === "") {
          if (data.length) yield { event: event || "message", data: data.join("\n"), id };
          data = [];
          event = "";
          continue;
        }
        if (line.startsWith(":")) continue;
        const c = line.indexOf(":");
        const field = c < 0 ? line : line.slice(0, c);
        let val = c < 0 ? "" : line.slice(c + 1);
        if (val.startsWith(" ")) val = val.slice(1);
        if (field === "data") data.push(val);
        else if (field === "event") event = val;
        else if (field === "id") id = val;
      }
    }
    if (data.length) yield { event: event || "message", data: data.join("\n"), id };
  } finally {
    reader.releaseLock?.();
  }
}
