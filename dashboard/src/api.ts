import type { Stats, Threat, Bucket, LogRow, AgentRow, KeyRow } from "./types";

const BASE = (import.meta.env.VITE_PROXY_URL || "http://localhost:8000").replace(/\/$/, "");

function headers(token: string, json = false): HeadersInit {
  const h: Record<string, string> = { "X-Admin-Token": token };
  if (json) h["Content-Type"] = "application/json";
  return h;
}

async function get<T>(path: string, token: string): Promise<T> {
  const res = await fetch(BASE + path, { headers: headers(token) });
  if (res.status === 401) throw new Error("unauthorized");
  if (!res.ok) throw new Error("request failed: " + res.status);
  return (await res.json()) as T;
}

async function send<T>(method: string, path: string, token: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method,
    headers: headers(token, !!body),
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) throw new Error("unauthorized");
  if (!res.ok) throw new Error("request failed: " + res.status);
  return (await res.json()) as T;
}

export const api = {
  base: BASE,
  adminToken: (t: string) => get<{ token: string }>("/api/admin-token", t),
  stats: (t: string) => get<Stats>("/api/stats", t),
  threats: (t: string) => get<Threat[]>("/api/threats", t),
  timeseries: (t: string, hours = 24) => get<Bucket[]>(`/api/timeseries?hours=${hours}`, t),
  agents: (t: string) => get<AgentRow[]>("/api/agents", t),
  trace: (t: string, id: string) => get<LogRow[]>("/api/trace/" + id, t),
  logs: (t: string, opts: { limit?: number; flagged?: boolean; owasp?: string; agent?: string } = {}) => {
    const p = new URLSearchParams();
    p.set("limit", String(opts.limit ?? 60));
    if (opts.flagged !== undefined) p.set("flagged", String(opts.flagged));
    if (opts.owasp) p.set("owasp", opts.owasp);
    if (opts.agent) p.set("agent", opts.agent);
    return get<LogRow[]>("/api/logs?" + p.toString(), t);
  },
  log: (t: string, id: string) => get<LogRow>("/api/logs/" + id, t),
  // key vault
  keys: (t: string) => get<KeyRow[]>("/api/keys", t),
  addKey: (t: string, provider: string, key: string, label: string) =>
    send<KeyRow>("POST", "/api/keys", t, { provider, key, label }),
  revealKey: (t: string, id: string) => get<{ id: string; key: string }>(`/api/keys/${id}/reveal`, t),
  deleteKey: (t: string, id: string) => send<{ deleted: string }>("DELETE", `/api/keys/${id}`, t),
  async check(token: string): Promise<boolean> {
    try {
      await get<Stats>("/api/stats", token);
      return true;
    } catch {
      return false;
    }
  },
};
