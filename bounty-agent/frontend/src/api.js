const BASE = "/api";

function token() {
  return localStorage.getItem("ba_token") || "";
}

function headers(extra = {}) {
  return { "Content-Type": "application/json", Authorization: `Bearer ${token()}`, ...extra };
}

async function req(method, path, body) {
  const res = await fetch(BASE + path, {
    method,
    headers: headers(),
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }
  return res.json();
}

export const api = {
  // Auth
  register: (email, password) => req("POST", "/auth/register", { email, password }),
  login:    (email, password) => req("POST", "/auth/login",    { email, password }),
  me:       ()               => req("GET",  "/auth/me"),

  // Agents
  listAgents:   ()            => req("GET",    "/agents/"),
  spawnAgents:  (count, mode) => req("POST",   "/agents/spawn",  { count, mode }),
  stopAgent:    (id)          => req("DELETE",  `/agents/${id}`),
  stopAll:      ()            => req("DELETE",  "/agents/"),

  // Targets
  listTargets:  ()            => req("GET",    "/agents/targets"),
  addTarget:    (url, mode)   => req("POST",   "/agents/targets", { url, mode }),
  removeTarget: (id)          => req("DELETE",  `/agents/targets/${id}`),

  // Findings
  listFindings: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return req("GET", `/findings/${qs ? "?" + qs : ""}`);
  },
  getFinding:   (id)          => req("GET",    `/findings/${id}`),
  getReport:    (id)          => req("GET",    `/findings/${id}/report`),
  getStats:     ()            => req("GET",    "/findings/stats/summary"),
};

// ── WebSocket ─────────────────────────────────────────────────────────────────

export function createWS(onMessage) {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const host  = window.location.host;
  const url   = `${proto}://${host}/ws?token=${token()}`;
  const ws    = new WebSocket(url);

  ws.onmessage = (e) => {
    try { onMessage(JSON.parse(e.data)); }
    catch {}
  };

  ws.onerror = () => {};

  return ws;
}
