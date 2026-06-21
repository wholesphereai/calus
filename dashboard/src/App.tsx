import { useEffect, useState, useCallback, useMemo } from "react";
import { LogOut, X } from "lucide-react";
import { api } from "./api";
import type { Stats, Threat, Bucket, LogRow, CallRow, AgentRow, KeyRow } from "./types";
import {
  StatCards, TimeChart, Threats, CallsTable, LogDetail, AgentsTable,
  KeysPanel, ConnectPanel, TokenGate, Icon, groupCalls, Empty,
} from "./components";

const TOKEN_KEY = "calus_admin_token";

type View = "overview" | "agents" | "threats" | "live" | "keys" | "connect";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "overview" },
  { id: "agents", label: "Agents", icon: "agents" },
  { id: "threats", label: "Threats", icon: "threats" },
  { id: "live", label: "Live calls", icon: "live" },
  { id: "keys", label: "API keys", icon: "keys" },
  { id: "connect", label: "Connect", icon: "connect" },
];

export default function App() {
  const [token, setToken] = useState<string>(() => localStorage.getItem(TOKEN_KEY) || "");
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [gateError, setGateError] = useState<string>("");
  const [view, setView] = useState<View>("overview");

  const [stats, setStats] = useState<Stats | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [series, setSeries] = useState<Bucket[]>([]);
  const [logs, setLogs] = useState<LogRow[]>([]);
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [keys, setKeys] = useState<KeyRow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [keysLoaded, setKeysLoaded] = useState(false);
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const [agentFilter, setAgentFilter] = useState<string>("");
  const [picked, setPicked] = useState<CallRow | null>(null);
  const [trace, setTrace] = useState<LogRow[]>([]);
  const [live, setLive] = useState(true);

  const calls = useMemo(() => groupCalls(logs), [logs]);

  useEffect(() => {
    if (!token) { setAuthed(false); return; }
    api.check(token).then((ok) => {
      setAuthed(ok);
      if (ok) localStorage.setItem(TOKEN_KEY, token);
      else setGateError("That token was rejected.");
    });
  }, [token]);

  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const [s, th, ts, lg, ag] = await Promise.all([
        api.stats(token),
        api.threats(token),
        api.timeseries(token, 24),
        api.logs(token, { limit: 80, flagged: onlyFlagged ? true : undefined, agent: agentFilter || undefined }),
        api.agents(token),
      ]);
      setStats(s); setThreats(th); setSeries(ts); setLogs(lg); setAgents(ag); setLive(true); setLoaded(true);
    } catch {
      setLive(false);
    }
  }, [token, onlyFlagged, agentFilter]);

  useEffect(() => {
    if (authed) {
      refresh();
      const id = setInterval(refresh, 4000);
      return () => clearInterval(id);
    }
  }, [authed, refresh]);

  const loadKeys = useCallback(() => {
    if (token) api.keys(token).then((k) => { setKeys(k); setKeysLoaded(true); }).catch(() => {});
  }, [token]);
  useEffect(() => { if (authed && view === "keys") loadKeys(); }, [authed, view, loadKeys]);

  const pick = async (c: CallRow) => {
    setPicked(c); setTrace([]);
    if (c.trace_id) {
      try { setTrace(await api.trace(token, c.trace_id)); } catch { /* no trace */ }
    }
  };

  if (authed === false || authed === null) {
    return (
      <TokenGate error={gateError}
        onSubmit={(t) => { setGateError(""); setAuthed(null); setToken(t.trim()); }} />
    );
  }

  const titles: Record<View, [string, string]> = {
    overview: ["Overview", "Live security posture across all traffic"],
    agents: ["Agents", "Every agent, its tools, and flagged activity"],
    threats: ["Threats", "Flagged traffic mapped to the OWASP LLM Top 10"],
    live: ["Live calls", agentFilter ? `Filtered to agent “${agentFilter}”` : "Every request and response, scanned in real time"],
    keys: ["API keys", "Encrypted vault for upstream provider keys"],
    connect: ["Connect", "Drop-in setup — no code changes, no SDK"],
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="mark">C</div>
          <div>
            <h1>Calus</h1>
            <div className="by">by Wholesphere</div>
          </div>
        </div>
        <div className="nav-group-label">Console</div>
        <nav className="nav">
          {NAV.map((n) => (
            <button key={n.id} className={view === n.id ? "on" : ""}
              aria-current={view === n.id ? "page" : undefined}
              onClick={() => { setView(n.id); if (n.id !== "live") setAgentFilter(""); }}>
              <Icon name={n.icon} />{n.label}
              {n.id === "agents" && agents.length > 0 && <span className="count">{agents.length}</span>}
              {n.id === "threats" && threats.length > 0 && <span className="count alert">{threats.reduce((a, t) => a + t.count, 0)}</span>}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <div className={"conn" + (live ? " live" : "")}><span className="dot" />{live ? "Live" : "Disconnected"}</div>
          <div className="side-actions">
            <button title="Sign out" onClick={() => { localStorage.removeItem(TOKEN_KEY); setToken(""); setAuthed(false); }}>
              <LogOut className="ic" />Sign out
            </button>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="titles">
            <h2>{titles[view][0]}</h2>
            <div className="sub">{titles[view][1]}</div>
          </div>
          <div className="actions">
            {view === "live" && (
              <div className="filters">
                {agentFilter && <button className="chip on" onClick={() => setAgentFilter("")}>agent: {agentFilter}<X className="x" /></button>}
                <button className={"chip" + (!onlyFlagged ? " on" : "")} onClick={() => setOnlyFlagged(false)}>All</button>
                <button className={"chip" + (onlyFlagged ? " on" : "")} onClick={() => setOnlyFlagged(true)}>Flagged</button>
              </div>
            )}
            <div className={"status-pill" + (live ? " live" : "")}><span className="dot" />{live ? "Live" : "Offline"}</div>
          </div>
        </header>

        <div className="content">
          {view === "overview" && (
            <>
              <StatCards stats={stats} />
              <div className="grid-mid">
                <div className="card flush">
                  <div className="panel-head"><h3>Traffic · last 24h</h3><span className="hint">total vs flagged</span></div>
                  <TimeChart data={series} loading={!loaded} />
                </div>
                <div className="card flush">
                  <div className="panel-head"><h3>Threats by OWASP</h3><span className="hint">flagged only</span></div>
                  <Threats threats={threats} loading={!loaded} />
                </div>
              </div>
              <div className="card flush">
                <div className="panel-head"><h3>Recent calls</h3><span className="hint">one row per request</span></div>
                <CallsTable calls={calls.slice(0, 12)} onPick={pick} loading={!loaded} />
              </div>
            </>
          )}

          {view === "agents" && (
            <div className="card flush">
              <AgentsTable agents={agents} onPick={(a) => { setAgentFilter(a.agent); setView("live"); }} loading={!loaded} />
            </div>
          )}

          {view === "threats" && (
            <>
              <StatCards stats={stats} />
              <div className="card flush">
                <div className="panel-head"><h3>OWASP LLM Top 10 — flagged traffic</h3><span className="hint">click a call to inspect</span></div>
                <Threats threats={threats} loading={!loaded} />
              </div>
              <div className="card flush">
                <div className="panel-head"><h3>Flagged calls</h3></div>
                {loaded && calls.filter((c) => c.flagged).length === 0
                  ? <Empty title="No flagged calls" sub="When traffic trips a detection rule, the offending calls show up here." />
                  : <CallsTable calls={calls.filter((c) => c.flagged)} onPick={pick} loading={!loaded} />}
              </div>
            </>
          )}

          {view === "live" && (
            <div className="card flush">
              <CallsTable calls={calls} onPick={pick} loading={!loaded} />
            </div>
          )}

          {view === "keys" && (
            <KeysPanel
              keys={keys}
              loading={!keysLoaded}
              onAdd={async (p, k, l) => { await api.addKey(token, p, k, l); loadKeys(); }}
              onReveal={async (id) => (await api.revealKey(token, id)).key}
              onUpdate={async (id, body) => { await api.updateKey(token, id, body); loadKeys(); }}
              onDelete={async (id) => { await api.deleteKey(token, id); loadKeys(); }}
            />
          )}

          {view === "connect" && <ConnectPanel base={api.base} token={token} />}
        </div>
      </main>

      {picked && <LogDetail call={picked} trace={trace} onClose={() => setPicked(null)} />}
    </div>
  );
}
