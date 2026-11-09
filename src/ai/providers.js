// AI providers behind one interface:
//
//   chat({ system, messages, tools, json, signal }) -> { text, toolCalls, thinking }
//
// Internal message format:
//   { role: "user", content }
//   { role: "assistant", content, toolCalls: [{ id, name, arguments }] }
//   { role: "tool", toolCallId, name, content, isError }
//
// Providers: Ollama (native /api/chat), any OpenAI-compatible server (LM Studio,
// llama.cpp, vLLM, LocalAI, OpenRouter, OpenAI...) and Anthropic.

export class AiError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = "AiError";
    this.status = status;
  }
}

/** True when the endpoint is on this machine (page data never leaves it). */
export function isLocalEndpoint(url) {
  try {
    const h = new URL(url).hostname;
    return h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h.endsWith(".localhost");
  } catch {
    return false;
  }
}

async function post(url, body, headers, signal, timeoutMs, label) {
  const signals = [signal, timeoutMs ? AbortSignal.timeout(timeoutMs) : null].filter(Boolean);
  const sig = signals.length > 1 ? AbortSignal.any(signals) : signals[0];
  let res;
  try {
    res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), signal: sig, credentials: "omit" });
  } catch (e) {
    if (signal?.aborted) throw new AiError("Cancelled");
    if (e.name === "TimeoutError") throw new AiError(`${label} didn't answer within ${Math.round(timeoutMs / 1000)}s. Try a smaller model, fewer page characters or a longer timeout in Settings.`);
    throw new AiError(`Couldn't reach ${label} at ${new URL(url).origin}. Is it running?`);
  }
  const text = await res.text();
  if (!res.ok) throw new AiError(explain(label, res.status, text, body.model), res.status);
  try {
    return JSON.parse(text);
  } catch {
    throw new AiError(`${label} returned something that isn't JSON: ${text.slice(0, 200)}`);
  }
}

function explain(label, status, text, model) {
  let msg = text;
  try {
    const j = JSON.parse(text);
    msg = j.error?.message || j.error || j.message || text;
  } catch {
    /* plain text */
  }
  msg = String(msg).slice(0, 400);
  if (label === "Ollama" && status === 403) return 'Ollama rejected the request (403). Set OLLAMA_ORIGINS="chrome-extension://*" and restart Ollama (see the README).';
  if (label === "Ollama" && status === 404 && /model/i.test(msg)) return `Model "${model}" isn't installed. Run: ollama pull ${model}`;
  if (label === "Ollama" && /does not support tools/i.test(msg)) return `${msg}. Turn off "Let the AI use tools" in Settings or pick a model with tool support.`;
  if (status === 401) return `${label}: authentication failed (check the API key). ${msg}`;
  if (status === 429) return `${label}: rate limited or out of quota. ${msg}`;
  return `${label} error ${status}: ${msg}`;
}

const parseArgs = (a) => {
  if (a && typeof a === "object") return a;
  try {
    return JSON.parse(a || "{}");
  } catch {
    return { _raw: String(a) };
  }
};

let callSeq = 0;
const callId = () => `call_${Date.now().toString(36)}_${(callSeq++).toString(36)}`;

// ---------------------------------------------------------------------------
// Ollama
// ---------------------------------------------------------------------------

export const ollama = {
  label: "Ollama",
  async models(cfg) {
    const base = cfg.url.replace(/\/+$/, "");
    const res = await fetch(`${base}/api/tags`).catch(() => {
      throw new AiError(`Couldn't reach Ollama at ${base}. Is it running?`);
    });
    if (res.status === 403) throw new AiError(explain("Ollama", 403, ""));
    if (!res.ok) throw new AiError(`Ollama error ${res.status}`);
    const j = await res.json();
    return (j.models || []).map((m) => ({ id: m.name, size: m.size, family: m.details?.family, params: m.details?.parameter_size }));
  },
  async capabilities(cfg, model) {
    try {
      const j = await post(`${cfg.url.replace(/\/+$/, "")}/api/show`, { model }, {}, null, 10000, "Ollama");
      return j.capabilities || [];
    } catch {
      return [];
    }
  },
  async chat(cfg, { system, messages, tools, json, signal, timeoutMs, temperature }) {
    const msgs = [{ role: "system", content: system }];
    for (const m of messages) {
      if (m.role === "tool") msgs.push({ role: "tool", content: m.content, tool_name: m.name });
      else if (m.role === "assistant") msgs.push({ role: "assistant", content: m.content || "", ...(m.toolCalls?.length ? { tool_calls: m.toolCalls.map((c) => ({ function: { name: c.name, arguments: c.arguments } })) } : {}) });
      else msgs.push({ role: "user", content: m.content });
    }
    const body = {
      model: cfg.model,
      messages: msgs,
      stream: false,
      options: { temperature, num_ctx: cfg.numCtx || 16384 },
      ...(tools?.length ? { tools: tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } })) } : {}),
      ...(json ? { format: json === true ? "json" : json } : {}),
      // Thinking models think by default; send "think" only to models that support it
      // (older Ollama versions and non-thinking models reject the field).
      ...(cfg.supportsThinking ? { think: !!cfg.think } : cfg.think ? { think: true } : {})
    };
    const j = await post(`${cfg.url.replace(/\/+$/, "")}/api/chat`, body, {}, signal, timeoutMs, "Ollama");
    const m = j.message || {};
    return {
      text: stripThink(m.content || ""),
      thinking: m.thinking || null,
      toolCalls: (m.tool_calls || []).map((c) => ({ id: callId(), name: c.function?.name, arguments: parseArgs(c.function?.arguments) })),
      usage: { input: j.prompt_eval_count, output: j.eval_count }
    };
  }
};

// Some local models wrap reasoning in <think> tags inside the answer.
const stripThink = (s) => String(s).replace(/<think>[\s\S]*?<\/think>\s*/g, "").trim();

// ---------------------------------------------------------------------------
// OpenAI-compatible
// ---------------------------------------------------------------------------

export const openai = {
  label: "OpenAI-compatible server",
  async models(cfg) {
    const base = cfg.url.replace(/\/+$/, "");
    const res = await fetch(`${base}/models`, { headers: cfg.apiKey ? { authorization: `Bearer ${cfg.apiKey}` } : {} }).catch(() => {
      throw new AiError(`Couldn't reach ${base}. Is the server running?`);
    });
    if (!res.ok) throw new AiError(explain(this.label, res.status, await res.text()));
    const j = await res.json();
    return (j.data || j.models || []).map((m) => ({ id: m.id || m.name }));
  },
  async chat(cfg, { system, messages, tools, json, signal, timeoutMs, temperature }) {
    const msgs = [{ role: "system", content: system }];
    for (const m of messages) {
      if (m.role === "tool") msgs.push({ role: "tool", tool_call_id: m.toolCallId, content: m.content });
      else if (m.role === "assistant") msgs.push({ role: "assistant", content: m.content || null, ...(m.toolCalls?.length ? { tool_calls: m.toolCalls.map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.arguments || {}) } })) } : {}) });
      else msgs.push({ role: "user", content: m.content });
    }
    const body = {
      model: cfg.model,
      messages: msgs,
      temperature,
      ...(tools?.length ? { tools: tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } })) } : {}),
      ...(json && !tools?.length ? { response_format: { type: "json_object" } } : {})
    };
    const j = await post(`${cfg.url.replace(/\/+$/, "")}/chat/completions`, body, cfg.apiKey ? { authorization: `Bearer ${cfg.apiKey}` } : {}, signal, timeoutMs, this.label);
    const m = j.choices?.[0]?.message || {};
    return {
      text: stripThink(m.content || ""),
      thinking: m.reasoning_content || m.reasoning || null,
      toolCalls: (m.tool_calls || []).map((c) => ({ id: c.id || callId(), name: c.function?.name, arguments: parseArgs(c.function?.arguments) })),
      usage: { input: j.usage?.prompt_tokens, output: j.usage?.completion_tokens }
    };
  }
};

// ---------------------------------------------------------------------------
// Anthropic
// ---------------------------------------------------------------------------

const ANTHROPIC = "https://api.anthropic.com/v1";
const anthropicHeaders = (cfg) => ({
  "x-api-key": cfg.apiKey,
  "anthropic-version": "2023-06-01",
  // Required for requests made directly from a browser; the key is the user's own and stays in local storage.
  "anthropic-dangerous-direct-browser-access": "true"
});

export const anthropic = {
  label: "Anthropic",
  async models(cfg) {
    if (!cfg.apiKey) throw new AiError("Add your Anthropic API key first.");
    const res = await fetch(`${ANTHROPIC}/models?limit=100`, { headers: anthropicHeaders(cfg) }).catch(() => {
      throw new AiError("Couldn't reach api.anthropic.com");
    });
    if (!res.ok) throw new AiError(explain(this.label, res.status, await res.text()));
    const j = await res.json();
    return (j.data || []).map((m) => ({ id: m.id, name: m.display_name }));
  },
  async chat(cfg, { system, messages, tools, signal, timeoutMs, temperature }) {
    if (!cfg.apiKey) throw new AiError("Add your Anthropic API key in Settings.");
    const out = [];
    const push = (role, block) => {
      const last = out[out.length - 1];
      if (last && last.role === role) last.content.push(block);
      else out.push({ role, content: [block] });
    };
    for (const m of messages) {
      if (m.role === "tool") push("user", { type: "tool_result", tool_use_id: m.toolCallId, content: m.content, ...(m.isError ? { is_error: true } : {}) });
      else if (m.role === "assistant") {
        if (m.content) push("assistant", { type: "text", text: m.content });
        for (const c of m.toolCalls || []) push("assistant", { type: "tool_use", id: c.id, name: c.name, input: c.arguments || {} });
      } else push("user", { type: "text", text: m.content });
    }
    const body = {
      model: cfg.model,
      max_tokens: 8192,
      system,
      messages: out,
      temperature,
      ...(tools?.length ? { tools: tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters })) } : {})
    };
    const j = await post(`${ANTHROPIC}/messages`, body, anthropicHeaders(cfg), signal, timeoutMs, this.label);
    const blocks = j.content || [];
    return {
      text: blocks.filter((b) => b.type === "text").map((b) => b.text).join("\n").trim(),
      thinking: blocks.filter((b) => b.type === "thinking").map((b) => b.thinking).join("\n") || null,
      toolCalls: blocks.filter((b) => b.type === "tool_use").map((b) => ({ id: b.id, name: b.name, arguments: b.input || {} })),
      usage: { input: j.usage?.input_tokens, output: j.usage?.output_tokens }
    };
  }
};

export const PROVIDERS = { ollama, openai, anthropic };

/** The provider config for the current settings, with an "endpoint" for locality checks. */
export function providerConfig(ai) {
  const p = ai.provider;
  if (p === "openai") return { provider: openai, cfg: ai.openai, endpoint: ai.openai.url, model: ai.openai.model };
  if (p === "anthropic") return { provider: anthropic, cfg: ai.anthropic, endpoint: ANTHROPIC, model: ai.anthropic.model };
  return { provider: ollama, cfg: ai.ollama, endpoint: ai.ollama.url, model: ai.ollama.model };
}

/** JSON Schema cleanup so MCP tool schemas are accepted by every provider. */
export function cleanSchema(schema) {
  const s = schema && typeof schema === "object" ? structuredClone(schema) : {};
  delete s.$schema;
  delete s.$id;
  if (s.type !== "object") return { type: "object", properties: {}, additionalProperties: true };
  s.properties ||= {};
  return s;
}

/** Provider-safe function name (letters, digits, _ and -; max 64). */
export function safeToolName(name, taken) {
  let n = String(name).replace(/[^A-Za-z0-9_-]/g, "_").replace(/_+/g, "_").slice(0, 64);
  if (!n) n = "tool";
  let i = 2;
  const base = n.slice(0, 60);
  while (taken?.has(n)) n = `${base}_${i++}`;
  taken?.add(n);
  return n;
}
