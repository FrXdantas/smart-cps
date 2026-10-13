// SMART ESBMC/JBMC — cliente REST.
const API = "/api";

// Em qualquer 401, manda para a tela de login preservando a página atual.
function _redirectToLogin() {
  if (location.pathname === "/login.html") return;
  const next = encodeURIComponent(location.pathname + location.search);
  location.href = "/login.html?next=" + next;
}

async function _fetch(path, opts = {}) {
  const r = await fetch(API + path, { credentials: "same-origin", ...opts });
  if (r.status === 401) { _redirectToLogin(); throw new Error("Sessão expirada"); }
  return r;
}

async function jget(path) {
  const r = await _fetch(path);
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

async function jpost(path, body) {
  const r = await _fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || ("HTTP " + r.status));
  return data;
}

async function jdelete(path) {
  const r = await _fetch(path, { method: "DELETE" });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || ("HTTP " + r.status));
  return data;
}

const api = {
  health: () => jget("/health"),
  me: () => jget("/auth/me"),
  logout: () => jpost("/auth/logout", {}),
  listUsers: () => jget("/auth/users"),
  createUser: (cfg) => jpost("/auth/users", cfg),
  deleteUser: (id) => jdelete("/auth/users/" + id),
  rotateApiKey: (id) => jpost("/auth/users/" + id + "/api-key", {}),
  revokeApiKey: (id) => jdelete("/auth/users/" + id + "/api-key"),
  loginHistory: (limit) => jget("/auth/history" + (limit ? "?limit=" + limit : "")),
  createRun: (cfg) => jpost("/runs", cfg),
  solvers: () => jget("/runs/solvers"),
  getRun: (id) => jget("/runs/" + id),
  listRuns: () => jget("/runs"),
  deleteRun: (id) => jdelete("/runs/" + id),
  cancelRun: (id) => jpost("/runs/" + id + "/cancel", {}),
  browse: (path) => jget("/browse" + (path ? "?path=" + encodeURIComponent(path) : "")),
  createRepair: (cfg) => jpost("/repair", cfg),
  getRepair: (runId) => jget("/repair/" + runId),
  cancelRepair: (runId) => jpost("/repair/" + runId + "/cancel", {}),
  localLlmStatus: () => jget("/llm/local/status"),
};
