// Small, frequently-updated state the UI watches through chrome.storage.session
// (memory only, cleared when the browser closes). Big data (reports) lives in
// IndexedDB; here we only keep pointers and progress.

const tabKey = (tabId) => `tab:${tabId}`;
const jobKey = (reportId) => `job:${reportId}`;

export async function getTabState(tabId) {
  return (await chrome.storage.session.get(tabKey(tabId)))[tabKey(tabId)] || null;
}

export async function setTabState(tabId, patch) {
  const cur = (await getTabState(tabId)) || {};
  const next = { ...cur, ...patch, updatedAt: Date.now() };
  await chrome.storage.session.set({ [tabKey(tabId)]: next });
  return next;
}

export const clearTabState = (tabId) => chrome.storage.session.remove(tabKey(tabId));

export async function getJob(reportId) {
  return (await chrome.storage.session.get(jobKey(reportId)))[jobKey(reportId)] || {};
}

/** Update one job slot ("online", "ai", "files", "mcp", "evidence") of a report. */
export async function setJob(reportId, slot, patch) {
  const cur = await getJob(reportId);
  cur[slot] = patch === null ? undefined : { ...(cur[slot] || {}), ...patch, updatedAt: Date.now() };
  await chrome.storage.session.set({ [jobKey(reportId)]: cur });
}

/** Tell watchers a stored report changed (they re-read it from IndexedDB). */
export async function bumpReport(reportId) {
  await setJob(reportId, "rev", { n: Date.now() });
}

// --- Tool-call approvals --------------------------------------------------------

const waiting = new Map(); // approvalId -> resolve

export async function requestApproval(item, timeoutMs = 300000) {
  const id = `ap_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
  const { approvals = {} } = await chrome.storage.session.get("approvals");
  approvals[id] = { id, ...item, requestedAt: Date.now() };
  await chrome.storage.session.set({ approvals });
  return new Promise((resolve) => {
    const timer = setTimeout(() => finish("timeout"), timeoutMs);
    const finish = async (decision) => {
      clearTimeout(timer);
      waiting.delete(id);
      const { approvals: cur = {} } = await chrome.storage.session.get("approvals");
      delete cur[id];
      await chrome.storage.session.set({ approvals: cur });
      resolve(decision);
    };
    waiting.set(id, finish);
  });
}

/** decision: "allow" | "always" | "deny" */
export function resolveApproval(id, decision) {
  const fn = waiting.get(id);
  if (fn) fn(decision);
  return !!fn;
}

/** Deny every pending approval for a report (used when a job is cancelled). */
export async function denyApprovals(reportId) {
  const { approvals = {} } = await chrome.storage.session.get("approvals");
  for (const a of Object.values(approvals)) if (a.reportId === reportId) resolveApproval(a.id, "deny");
}

// --- Service-worker keep-alive ---------------------------------------------------

let holders = 0;
let timer = null;

/**
 * Keep the service worker alive while long work (AI calls, slow lookups) runs.
 * Calling an extension API resets Chrome's 30-second idle timer.
 */
export async function keepAlive(fn) {
  holders++;
  if (!timer) timer = setInterval(() => chrome.runtime.getPlatformInfo().catch(() => {}), 20000);
  try {
    return await fn();
  } finally {
    if (--holders === 0) {
      clearInterval(timer);
      timer = null;
    }
  }
}

// --- Cancellation -----------------------------------------------------------------

const controllers = new Map(); // `${reportId}:${slot}` -> AbortController

export function startCancellable(reportId, slot) {
  const k = `${reportId}:${slot}`;
  controllers.get(k)?.abort();
  const c = new AbortController();
  controllers.set(k, c);
  return { signal: c.signal, done: () => controllers.get(k) === c && controllers.delete(k) };
}

export function cancel(reportId, slot) {
  const k = `${reportId}:${slot}`;
  controllers.get(k)?.abort();
  controllers.delete(k);
}

export const isRunning = (reportId, slot) => controllers.has(`${reportId}:${slot}`);
