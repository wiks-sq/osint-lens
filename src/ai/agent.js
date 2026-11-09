// The analysis loop: send the digest, let the model call tools (built-in and
// MCP) with the user's approval where required, and collect a structured result.

import { providerConfig, cleanSchema, safeToolName, isLocalEndpoint, AiError, ollama } from "./providers.js";
import { MODES, FOLLOW_UP_SYSTEM, buildDigest, parseModelJson } from "./prompts.js";

const TOOL_RESULT_MAX = 12000;

/**
 * @param {object} p
 * @param {object} p.report
 * @param {object} p.settings          full settings
 * @param {string} p.mode              "osint" | "phishing" | "exposure" | "custom"
 * @param {string} [p.question]        custom question (mode "custom")
 * @param {Array}  [p.history]         previous messages for follow-ups
 * @param {Array}  p.tools             [{ name, description, parameters, readOnly, source, run(args) }]
 * @param {(call)=>Promise<boolean>} p.approve   resolves true to run a tool call
 * @param {(event)=>void} [p.onEvent]  progress events for the UI
 * @param {AbortSignal} [p.signal]
 */
export async function runAgent(p) {
  const ai = p.settings.ai;
  const { provider, cfg, endpoint, model } = providerConfig(ai);
  if (!model) throw new AiError("Choose a model in Settings → AI first.");
  const local = isLocalEndpoint(endpoint);
  const timeoutMs = ai.timeoutSec * 1000;
  const emit = (e) => p.onEvent?.({ at: Date.now(), ...e });

  if (provider === ollama && cfg.supportsThinking === undefined) {
    const caps = await provider.capabilities(cfg, model);
    cfg.supportsThinking = caps.includes("thinking");
    cfg.supportsTools = caps.length ? caps.includes("tools") : true;
  }

  // Tools: map provider-safe names to implementations.
  const taken = new Set();
  const tools = (ai.useTools && cfg.supportsTools !== false ? p.tools : []).map((t) => ({ ...t, apiName: safeToolName(t.name, taken), parameters: cleanSchema(t.parameters) }));
  const byName = new Map(tools.map((t) => [t.apiName, t]));
  const apiTools = tools.map((t) => ({ name: t.apiName, description: `${t.source === "built-in" ? "" : `[${t.source}] `}${t.description || ""}`.slice(0, 1000), parameters: t.parameters }));

  const followUp = !!p.history?.length;
  const system = followUp ? FOLLOW_UP_SYSTEM : (MODES[p.mode] || MODES.osint).system;
  const messages = followUp
    ? [...p.history, { role: "user", content: p.question }]
    : [{ role: "user", content: buildDigest(p.report, { maxChars: ai.maxChars, maskSecrets: !local, question: p.mode === "custom" ? p.question : null }) }];

  const log = [];
  let calls = 0;
  emit({ type: "status", text: `Asking ${model}${local ? "" : " (remote)"}…` });

  for (let turn = 0; turn < ai.maxToolCalls + 2; turn++) {
    const allowTools = calls < ai.maxToolCalls && apiTools.length > 0;
    const res = await provider.chat(cfg, {
      system,
      messages,
      tools: allowTools ? apiTools : [],
      // Without tools Ollama/OpenAI can be held to JSON output directly.
      json: !followUp && !allowTools,
      signal: p.signal,
      timeoutMs,
      temperature: ai.temperature
    });
    if (res.thinking) emit({ type: "thinking", text: res.thinking.slice(0, 4000) });

    if (res.toolCalls?.length && allowTools) {
      messages.push({ role: "assistant", content: res.text || "", toolCalls: res.toolCalls });
      for (const call of res.toolCalls) {
        const tool = byName.get(call.name);
        const entry = { id: call.id, tool: tool?.name || call.name, source: tool?.source || "?", args: call.arguments, status: "pending" };
        log.push(entry);
        emit({ type: "tool", entry });
        let content, isError = false;
        if (!tool) {
          content = `Unknown tool "${call.name}".`;
          isError = true;
          entry.status = "error";
        } else if (calls >= ai.maxToolCalls) {
          content = "Tool-call limit reached. Finish the analysis with what you have.";
          isError = true;
          entry.status = "skipped";
        } else {
          calls++;
          const ok = await p.approve({ ...entry, readOnly: tool.readOnly, serverId: tool.serverId, mcpTool: tool.mcpTool });
          if (!ok) {
            content = "The user declined this tool call. Continue without it.";
            isError = true;
            entry.status = "declined";
          } else {
            entry.status = "running";
            emit({ type: "tool", entry });
            try {
              content = String(await tool.run(call.arguments || {}, { signal: p.signal }));
              entry.status = "done";
            } catch (e) {
              content = `Tool error: ${e.message || e}`;
              isError = true;
              entry.status = "error";
            }
          }
        }
        if (content.length > TOOL_RESULT_MAX) content = `${content.slice(0, TOOL_RESULT_MAX)}\n…[truncated]`;
        entry.result = content.slice(0, 2000);
        emit({ type: "tool", entry });
        messages.push({ role: "tool", toolCallId: call.id, name: call.name, content: `<<<TOOL_RESULT (untrusted data)\n${content}\nTOOL_RESULT>>>`, isError });
      }
      continue;
    }

    // Final answer.
    messages.push({ role: "assistant", content: res.text || "" });
    if (followUp) return { answer: res.text, messages, log, model, local };
    let result = parseModelJson(res.text);
    if (!result && res.text) {
      // Ask once more for the JSON shape only (no tools, JSON mode where supported).
      emit({ type: "status", text: "Formatting the answer…" });
      const fix = await provider.chat(cfg, {
        system,
        messages: [...messages, { role: "user", content: "Rewrite your final answer as the JSON object described in the instructions. JSON only." }],
        tools: [],
        json: true,
        signal: p.signal,
        timeoutMs,
        temperature: 0
      });
      result = parseModelJson(fix.text);
    }
    return { result: result || null, raw: result ? null : res.text, messages, log, model, local };
  }
  throw new AiError("The model kept calling tools without finishing. Try again or lower the tool limit.");
}
