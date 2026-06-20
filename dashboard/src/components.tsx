import { useState } from "react";
import type { Stats, Threat, Bucket, LogRow, AgentRow, KeyRow } from "./types";

/* ===================== helpers ===================== */
function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function fmtAgo(ts: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

export function Tag({ flagged }: { flagged: boolean }) {
  return <span className={"tag " + (flagged ? "attack" : "clean")}>{flagged ? "FLAGGED" : "CLEAN"}</span>;
}

/* ===================== icons (monochrome, stroke=currentColor) ===================== */
const PATHS: Record<string, string> = {
  overview: "M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z",
  agents: "M16 11a4 4 0 1 0-8 0 M2 21a8 8 0 0 1 20 0",
  threats: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z",
  live: "M4 6h16M4 12h16M4 18h10",
  keys: "M15 7a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM11 11L3 19v2h2l1-1h2v-2h2l2-2",
  connect: "M9 7H6a4 4 0 0 0 0 8h3M15 7h3a4 4 0 0 1 0 8h-3M8 11h8",
};
export function Icon({ name }: { name: string }) {
  return (
    <svg className="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
      <path d={PATHS[name] || ""} />
    </svg>
  );
}

/* ===================== stat cards ===================== */
export function StatCards({ stats }: { stats: Stats | null }) {
  const s = stats;
  return (
    <div className="grid-stats">
      <div className="card stat">
        <div className="label">Calls scanned</div>
        <div className="num">{s ? s.total.toLocaleString() : "—"}</div>
        <div className="foot">{s ? s.last_24h.toLocaleString() + " in last 24h" : ""}</div>
      </div>
      <div className="card stat alert">
        <div className="label">Flagged</div>
        <div className="num">{s ? s.flagged.toLocaleString() : "—"}</div>
        <div className="foot">{s ? Math.round(s.flag_rate * 1000) / 10 + "% of all calls" : ""}</div>
      </div>
      <div className="card stat">
        <div className="label">Agents seen</div>
        <div className="num">{s ? s.agents.toLocaleString() : "—"}</div>
        <div className="foot">distinct identities</div>
      </div>
      <div className="card stat">
        <div className="label">Avg scan time</div>
        <div className="num">{s ? s.avg_latency_ms.toFixed(0) : "—"}<span className="u">ms</span></div>
        <div className="foot">round-trip incl. provider</div>
      </div>
    </div>
  );
}

/* ===================== time chart (pure SVG, monochrome) ===================== */
export function TimeChart({ data }: { data: Bucket[] }) {
  const W = 640, H = 168, pad = 6;
  const max = Math.max(1, ...data.map((d) => d.total));
  const n = Math.max(1, data.length - 1);
  const x = (i: number) => pad + (i * (W - pad * 2)) / n;
  const y = (v: number) => H - pad - (v / max) * (H - pad * 2);
  const area = (key: "total" | "flagged") => {
    if (data.length === 0) return "";
    let p = `M ${x(0)} ${y(data[0][key])}`;
    data.forEach((d, i) => { p += ` L ${x(i)} ${y(d[key])}`; });
    p += ` L ${x(data.length - 1)} ${H - pad} L ${x(0)} ${H - pad} Z`;
    return p;
  };
  const line = (key: "total" | "flagged") =>
    data.map((d, i) => `${i === 0 ? "M" : "L"} ${x(i)} ${y(d[key])}`).join(" ");
  return (
    <div>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id="gTot" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(140,140,140,0.22)" />
            <stop offset="100%" stopColor="rgba(140,140,140,0)" />
          </linearGradient>
          <linearGradient id="gFlag" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="rgba(255,255,255,0.30)" />
            <stop offset="100%" stopColor="rgba(255,255,255,0)" />
          </linearGradient>
        </defs>
        <path d={area("total")} fill="url(#gTot)" />
        <path d={line("total")} fill="none" stroke="var(--muted)" strokeWidth="1.4" />
        <path d={area("flagged")} fill="url(#gFlag)" />
        <path d={line("flagged")} fill="none" stroke="var(--ink)" strokeWidth="1.8" />
      </svg>
      <div className="legend">
        <span><i style={{ background: "var(--muted)" }} />Total</span>
        <span><i style={{ background: "var(--ink)" }} />Flagged</span>
      </div>
    </div>
  );
}

/* ===================== threats (OWASP) ===================== */
export function Threats({ threats }: { threats: Threat[] }) {
  const max = Math.max(1, ...threats.map((t) => t.count));
  if (threats.length === 0) return <div className="empty">No threats recorded yet.</div>;
  return (
    <div>
      {threats.map((t) => (
        <div className="threat-row" key={t.owasp}>
          <div className="code">{t.owasp}</div>
          <div className="meta">
            <div className="nm">{t.name || "Unmapped"}</div>
            <div className="bar"><span style={{ width: (t.count / max) * 100 + "%" }} /></div>
          </div>
          <div className="cnt">{t.count}</div>
        </div>
      ))}
    </div>
  );
}

/* ===================== live calls ===================== */
export function LogsTable({ rows, onPick }: { rows: LogRow[]; onPick: (r: LogRow) => void }) {
  if (rows.length === 0) return <div className="empty">No calls yet. Send a request through the proxy.</div>;
  return (
    <table>
      <thead>
        <tr><th>Time</th><th>Agent</th><th>Dir</th><th>Model</th><th>Verdict</th><th>Conf</th><th>OWASP</th><th>Tools</th></tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.id} onClick={() => onPick(r)}>
            <td className="mono" style={{ color: "var(--muted)", fontSize: 12 }}>{fmtTime(r.ts)}</td>
            <td className="mono" style={{ fontSize: 12 }}>{r.agent || "—"}</td>
            <td><span className="dir">{r.direction}</span></td>
            <td><div className="model">{r.model || "—"}</div><div className="prov">{r.provider}</div></td>
            <td><Tag flagged={r.flagged} /></td>
            <td className="conf">{r.confidence != null ? r.confidence.toFixed(2) : "—"}</td>
            <td>{r.owasp ? <span className="owasp-pill">{r.owasp}</span> : <span style={{ color: "var(--muted-2)" }}>—</span>}</td>
            <td>
              {r.tool_calls.length ? r.tool_calls.map((t, i) => <span className="toolchip" key={i}>{t.name}</span>)
                : r.tools.length ? r.tools.map((t) => <span className="toolchip" key={t}>{t}</span>)
                : <span style={{ color: "var(--muted-2)" }}>—</span>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/* ===================== agents ===================== */
export function AgentsTable({ agents, onPick }: { agents: AgentRow[]; onPick: (a: AgentRow) => void }) {
  if (agents.length === 0) return <div className="empty">No agents yet. Set an agent name via the OpenAI <span className="mono">user</span> field or the <span className="mono">X-Calus-Agent</span> header.</div>;
  return (
    <table>
      <thead>
        <tr><th>Agent</th><th>Calls</th><th>Flagged</th><th>Tools available</th><th>Models</th><th>Last seen</th></tr>
      </thead>
      <tbody>
        {agents.map((a) => (
          <tr key={a.agent} onClick={() => onPick(a)}>
            <td><div className="agent-cell"><span className="av">{(a.agent || "?").slice(0, 1)}</span><span className="mono" style={{ fontSize: 12.5 }}>{a.agent}</span></div></td>
            <td className="mono">{a.calls}</td>
            <td className="mono">{a.flagged > 0 ? <span className="tag attack">{a.flagged}</span> : <span style={{ color: "var(--muted-2)" }}>0</span>}</td>
            <td>{a.tools.length ? a.tools.slice(0, 5).map((t) => <span className="toolchip" key={t}>{t}</span>) : <span style={{ color: "var(--muted-2)" }}>none</span>}</td>
            <td className="mono" style={{ fontSize: 12 }}>{a.models.map((m) => m.split("/").pop()).join(", ")}</td>
            <td style={{ color: "var(--muted)", fontSize: 12 }}>{fmtAgo(a.last_ts)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/* ===================== trace timeline (inside detail drawer) ===================== */
function TraceTimeline({ rows }: { rows: LogRow[] }) {
  return (
    <div className="trace">
      {rows.map((r) => (
        <div className={"tnode" + (r.flagged ? " flag" : "")} key={r.id}>
          <div className="lbl">{r.direction === "input" ? "▸ user / prompt" : "◂ model output"} · {fmtTime(r.ts)} {r.flagged && "· FLAGGED"}</div>
          {r.text_redacted && <div className="body" style={{ color: "var(--fg-2)" }}>{r.text_redacted}</div>}
          {r.tool_calls.map((t, i) => (
            <div className="tool-line" key={i}>
              <span className="nm">{t.name}()</span>
              {t.arguments && <span className="args">{t.arguments}</span>}
            </div>
          ))}
          {r.tools.length > 0 && r.direction === "input" && (
            <div className="body" style={{ marginTop: 6 }}>{r.tools.map((t) => <span className="toolchip" key={t}>{t}</span>)}</div>
          )}
        </div>
      ))}
    </div>
  );
}

export function LogDetail({ row, trace, onClose }: { row: LogRow; trace: LogRow[]; onClose: () => void }) {
  return (
    <>
      <div className="drawer-bg" onClick={onClose} />
      <div className="drawer">
        <button className="close" onClick={onClose}>×</button>
        <h3>Call detail</h3>
        <div style={{ marginBottom: 14 }}><Tag flagged={row.flagged} /></div>
        <div className="row"><span className="k">Agent</span><span className="mono">{row.agent || "—"}</span></div>
        <div className="row"><span className="k">Model</span><span className="mono">{row.model || "—"} · {row.provider}</span></div>
        <div className="row"><span className="k">Confidence</span><span className="mono">{row.confidence != null ? row.confidence.toFixed(3) : "—"}</span></div>
        <div className="row"><span className="k">OWASP</span><span>{row.owasp ? row.owasp + " · " + (row.owasp_name || "") : "—"}</span></div>
        <div className="row"><span className="k">Tiers run</span><span className="mono" style={{ fontSize: 12 }}>{row.tiers.join(" → ") || "—"}</span></div>
        <div className="row"><span className="k">Latency</span><span className="mono">{row.latency_ms != null ? row.latency_ms.toFixed(0) + " ms" : "—"}</span></div>

        {row.findings.length > 0 && (
          <div className="blk"><div className="t">Secrets / PII found (redacted)</div>
            <div>{row.findings.map((f) => <span className="finding" key={f}>{f}</span>)}</div></div>
        )}
        {row.reasons.length > 0 && (
          <div className="blk"><div className="t">Why it flagged</div>
            {row.reasons.map((r, i) => <div className="reason" key={i}>{r}</div>)}</div>
        )}
        <div className="blk">
          <div className="t">Full trace — request → tool calls → output</div>
          {trace.length ? <TraceTimeline rows={trace} /> : <div className="empty">single record</div>}
        </div>
      </div>
    </>
  );
}

/* ===================== API key vault ===================== */
const PROVIDERS = ["openai", "groq", "anthropic", "gemini", "mistral", "cohere", "together", "azure"];

export function KeysPanel({ keys, onAdd, onReveal, onDelete }: {
  keys: KeyRow[];
  onAdd: (provider: string, key: string, label: string) => Promise<void>;
  onReveal: (id: string) => Promise<string>;
  onDelete: (id: string) => Promise<void>;
}) {
  const [provider, setProvider] = useState("openai");
  const [label, setLabel] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [revealed, setRevealed] = useState<Record<string, string>>({});

  const add = async () => {
    if (!secret.trim()) return;
    setBusy(true);
    try { await onAdd(provider, secret.trim(), label.trim()); setSecret(""); setLabel(""); }
    finally { setBusy(false); }
  };
  const reveal = async (id: string) => {
    if (revealed[id]) { setRevealed((r) => { const n = { ...r }; delete n[id]; return n; }); return; }
    const full = await onReveal(id);
    setRevealed((r) => ({ ...r, [id]: full }));
  };

  return (
    <div>
      <div className="banner">
        Keys are stored <b>encrypted at rest</b> and shown masked — the full value is only fetched on demand via reveal.
        Calus uses a saved key to forward upstream when a request doesn't carry its own. Provider keys are <b>never</b> written to the call log.
      </div>
      <div className="card">
        <div className="keyform">
          <select value={provider} onChange={(e) => setProvider(e.target.value)}>
            {PROVIDERS.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <input placeholder="label (e.g. prod)" value={label} onChange={(e) => setLabel(e.target.value)} />
          <input placeholder="paste provider API key" type="password" value={secret}
            onChange={(e) => setSecret(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} />
          <button className="btn" onClick={add} disabled={busy}>{busy ? "Saving…" : "Add key"}</button>
        </div>
        {keys.length === 0 ? <div className="empty">No keys saved yet.</div> : (
          <table>
            <thead><tr><th>Provider</th><th>Label</th><th>Key</th><th></th></tr></thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id} style={{ cursor: "default" }}>
                  <td><span className="owasp-pill">{k.provider}</span></td>
                  <td>{k.label || <span style={{ color: "var(--muted-2)" }}>—</span>}</td>
                  <td className="mono" style={{ fontSize: 12.5 }}>{revealed[k.id] || k.masked}</td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    <button className="btn ghost sm" onClick={() => reveal(k.id)}>{revealed[k.id] ? "Hide" : "Reveal"}</button>
                    {" "}
                    <button className="btn ghost sm" onClick={() => onDelete(k.id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

/* ===================== connect (drop-in onboarding) ===================== */
function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard?.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1200); };
  return (
    <div className="code">
      <button className="copy" onClick={copy}>{copied ? "copied" : "copy"}</button>
      <pre>{code}</pre>
    </div>
  );
}

export function ConnectPanel({ base }: { base: string }) {
  const [tab, setTab] = useState("env");
  const url = base.replace(/\/$/, "");
  const snippets: Record<string, string> = {
    env: `# No code changes. Point any OpenAI-compatible app at Calus
# by setting one environment variable, then run your app as usual.

export OPENAI_BASE_URL="${url}/v1"
# (keep using your own provider key — Calus forwards it, never stores it)`,
    openai: `from openai import OpenAI

client = OpenAI(
    base_url="${url}/v1",          # ← only change: route through Calus
    api_key="sk-your-own-key",      # your real provider key
)
client.chat.completions.create(
    model="gpt-4o",                 # or "groq/llama-3.3-70b-versatile", "anthropic/claude-..."
    user="my-agent",                # names this agent in the Calus console
    messages=[{"role": "user", "content": "hello"}],
)`,
    claude: `# Claude Code / any tool that respects ANTHROPIC_BASE_URL or OPENAI_BASE_URL
export ANTHROPIC_BASE_URL="${url}"
export OPENAI_BASE_URL="${url}/v1"

# now run the tool normally — every call is observed by Calus`,
    langchain: `from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    base_url="${url}/v1",
    api_key="sk-your-own-key",
    model="gpt-4o",
)`,
    curl: `curl ${url}/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer sk-your-own-key" \\
  -d '{"model":"groq/llama-3.3-70b-versatile",
       "user":"my-agent",
       "messages":[{"role":"user","content":"hello"}]}'`,
  };
  const tabs = [["env", "No-code (env var)"], ["openai", "OpenAI SDK"], ["claude", "Claude Code"], ["langchain", "LangChain"], ["curl", "curl"]];
  return (
    <div className="card">
      <div className="banner">
        <b>Drop-in, no SDK.</b> Calus sits between your AI tools and the providers. Point your app at the URL below and every call gets
        instant threat detection, agent &amp; tool-call observability — with no code changes and nothing blocked.
      </div>
      <div className="row" style={{ borderBottom: "none", marginBottom: 6 }}>
        <span className="k">Your proxy endpoint</span>
        <span className="mono">{url}/v1</span>
      </div>
      <div className="tabs">
        {tabs.map(([k, lbl]) => (
          <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{lbl}</button>
        ))}
      </div>
      <CodeBlock code={snippets[tab]} />
      <div className="steps" style={{ marginTop: 18 }}>
        <div className="step"><div className="n">1</div><div><h4>Route through Calus</h4><div style={{ color: "var(--muted)", fontSize: 13 }}>Set the base URL (above). Keep your own provider key — Calus passes it upstream and never stores it.</div></div></div>
        <div className="step"><div className="n">2</div><div><h4>Name your agents</h4><div style={{ color: "var(--muted)", fontSize: 13 }}>Pass <span className="mono">user</span> (or an <span className="mono">X-Calus-Agent</span> header) so each agent and its tool calls show up separately in the console.</div></div></div>
        <div className="step"><div className="n">3</div><div><h4>Watch live</h4><div style={{ color: "var(--muted)", fontSize: 13 }}>Threats, OWASP mapping, agents, and every tool call appear here in real time. Detection-only — traffic is never altered.</div></div></div>
      </div>
    </div>
  );
}

/* ===================== token gate ===================== */
export function TokenGate({ onSubmit, error }: { onSubmit: (t: string) => void; error?: string }) {
  const [val, setVal] = useState("");
  return (
    <div className="gate">
      <div className="gate-card">
        <div className="mark">C</div>
        <h2>Calus console</h2>
        <div className="by">by Wholesphere</div>
        <p>Enter your admin token to view live detection traffic. It's the <span className="mono">CALUS_ADMIN_TOKEN</span> your proxy printed at startup.</p>
        <input type="password" placeholder="admin token" value={val} autoFocus
          onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") onSubmit(val); }} />
        <button className="btn" onClick={() => onSubmit(val)}>Connect</button>
        {error && <div className="err">{error}</div>}
      </div>
    </div>
  );
}
