import { useEffect, useState, useCallback, useMemo } from "react";
import { LogOut, Sun, Moon } from "lucide-react";
import { api } from "./api";
import type { Stats, Threat, Bucket, LogRow, CallRow, AgentRow, KeyRow } from "./types";
import {
  StatCards, TimeChart, Threats, CallsTable, LogDetail, AgentsTable,
  KeysPanel, ConnectPanel, TokenGate, Icon, groupCalls, Empty, CalusLogoMark,
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

function greeting(): string {
  const h = new Date().getHours();
  if (h < 12) return "Good morning";
  if (h < 17) return "Good afternoon";
  return "Good evening";
}

const CHART_RANGES: [string, number][] = [["24h", 24], ["7d", 168], ["30d", 720], ["All", 8760]];

export default function App() {
  const [token, setToken] = useState<string>(() => localStorage.getItem(TOKEN_KEY) || "");
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [gateError, setGateError] = useState<string>("");
  const [view, setView] = useState<View>("overview");
  const [theme, setTheme] = useState<"light" | "dark">(() =>
    (localStorage.getItem("calus_theme") as "light" | "dark") || "light"
  );

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("calus_theme", theme);
  }, [theme]);

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
  const [owaspFilter, setOwaspFilter] = useState<string>("");
  const [picked, setPicked] = useState<CallRow | null>(null);
  const [trace, setTrace] = useState<LogRow[]>([]);
  const [live, setLive] = useState(true);
  const [chartHours, setChartHours] = useState(24);

  const calls = useMemo(() => groupCalls(logs), [logs]);

  useEffect(() => {
    if (!token) {
      // Localhost convenience: pull the admin token from the same-machine proxy
      // so the local demo is one-click. Remote callers get 403 -> show the gate.
      api.localAuth().then(setToken).catch(() => setAuthed(false));
      return;
    }
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
        api.timeseries(token, chartHours),
        api.logs(token, { limit: 80, flagged: onlyFlagged ? true : undefined, agent: agentFilter || undefined }),
        api.agents(token),
      ]);
      setStats(s); setThreats(th); setSeries(ts); setLogs(lg); setAgents(ag); setLive(true); setLoaded(true);
    } catch {
      setLive(false);
    }
  }, [token, onlyFlagged, agentFilter, chartHours]);

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
          <a href="https://usecalus.com/" target="_blank" rel="noopener noreferrer" className="mark">
            <CalusLogoMark size={32} />
          </a>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <button key={n.id}
              className={view === n.id ? "on" : ""}
              aria-label={n.label}
              title={n.label}
              aria-current={view === n.id ? "page" : undefined}
              onClick={() => { setView(n.id); if (n.id !== "live") setAgentFilter(""); if (n.id !== "threats") setOwaspFilter(""); }}>
              <Icon name={n.icon} />
            </button>
          ))}
        </nav>
        <div className="side-foot"></div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="titles">
            <h2>{titles[view][0]}</h2>
            {view === "agents" && loaded && (
              <div className="agent-pills">
                <span className="agent-pill">{agents.length} total</span>
                <span className="agent-pill active">
                  {agents.filter(a => Date.now() / 1000 - a.last_ts < 86400).length} active
                </span>
              </div>
            )}
          </div>
          <div className="actions">
            <button className="theme-btn" title={theme === "light" ? "Switch to dark" : "Switch to light"}
              aria-label="Toggle theme" onClick={() => setTheme(t => t === "light" ? "dark" : "light")}>
              {theme === "light" ? <Moon className="ic" /> : <Sun className="ic" />}
            </button>
            <button className="theme-btn" title="Sign out" aria-label="Sign out"
              onClick={() => { localStorage.removeItem(TOKEN_KEY); setToken(""); setAuthed(false); }}>
              <LogOut className="ic" />
            </button>
          </div>
        </header>

        <div className="content">
          {view === "overview" && (
            <>
              <div className="greeting-card">
                <div>
                  <div className="greeting-hi">{greeting()}</div>
                  <div className="greeting-sub">Here's your security posture at a glance.</div>
                </div>
                <div className="greeting-badge">{new Date().toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" })}</div>
              </div>
              <StatCards stats={stats} />
              <div className="card flush">
                <div className="panel-head">
                  <h3>Traffic</h3>
                  <div className="time-tabs">
                    {CHART_RANGES.map(([label, h]) => (
                      <button key={label} className={chartHours === h ? "on" : ""}
                        onClick={() => setChartHours(h)}>{label}</button>
                    ))}
                  </div>
                  <span className="hint">total vs flagged</span>
                </div>
                <TimeChart data={series} loading={!loaded} />
              </div>
            </>
          )}

          {view === "agents" && (
            <div className="card flush">
              <AgentsTable agents={agents} onPick={(a) => { setAgentFilter(a.agent); setView("live"); }} loading={!loaded} />
            </div>
          )}

          {view === "threats" && (
            <div className="card flush">
              <div className="live-filters">
                <button className={"chip" + (!owaspFilter ? " on" : "")}
                  onClick={() => setOwaspFilter("")}>All</button>
                {threats.map((t) => (
                  <button key={t.owasp} className={"chip" + (owaspFilter === t.owasp ? " on" : "")}
                    onClick={() => setOwaspFilter(t.owasp)}>
                    {t.name || t.owasp}
                  </button>
                ))}
              </div>
              {(() => {
                const filtered = calls.filter((c) => c.flagged && (!owaspFilter || c.owasp === owaspFilter));
                return filtered.length === 0 && loaded
                  ? <Empty title="No flagged calls" sub="When traffic trips a detection rule, the offending calls show up here." />
                  : <CallsTable calls={filtered} onPick={pick} loading={!loaded} />;
              })()}
            </div>
          )}

          {view === "live" && (
            <div className="card flush">
              <div className="live-filters">
                <button className={"chip" + (!agentFilter && !onlyFlagged ? " on" : "")}
                  onClick={() => { setAgentFilter(""); setOnlyFlagged(false); }}>All</button>
                {agents.map((a) => (
                  <button key={a.agent} className={"chip" + (agentFilter === a.agent ? " on" : "")}
                    onClick={() => { setAgentFilter(a.agent); setOnlyFlagged(false); }}>
                    {a.agent}
                  </button>
                ))}
                <button className={"chip" + (onlyFlagged ? " on" : "")}
                  onClick={() => { setAgentFilter(""); setOnlyFlagged(true); }}>Flagged</button>
              </div>
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
