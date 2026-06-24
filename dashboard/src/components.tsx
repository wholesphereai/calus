import { useState, type ReactNode } from "react";
import type { Stats, Threat, Bucket, LogRow, CallRow, AgentRow, KeyRow } from "./types";
import {
  LayoutGrid, Bot, Siren, Activity, KeyRound, Plug,
  Copy, Check, Eye, EyeOff, Pencil, Trash2, X, AlertCircle, Users, ShieldAlert,
  ArrowUpRight, ArrowDownRight, Wrench, Inbox, Lock, Cpu, Clock,
  Radio, ArrowRight, CornerDownLeft, MessageSquare, Plus, Info,
} from "lucide-react";

/* ===================== mini markdown (bold / lists / paragraphs) ===================== */
function inline(text: string): ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((p, i) => {
    if (p.startsWith("**") && p.endsWith("**")) return <strong key={i}>{p.slice(2, -2)}</strong>;
    if (p.startsWith("`") && p.endsWith("`")) return <code key={i}>{p.slice(1, -1)}</code>;
    return <span key={i}>{p}</span>;
  });
}
export function Markdown({ text }: { text: string }) {
  const out: ReactNode[] = [];
  let list: string[] = [];
  const flush = (k: number) => {
    if (list.length) { out.push(<ul key={"ul" + k}>{list.map((l, j) => <li key={j}>{inline(l)}</li>)}</ul>); list = []; }
  };
  text.split("\n").forEach((ln, i) => {
    const m = ln.match(/^\s*(?:[-*]|\d+\.)\s+(.*)/);
    if (m) list.push(m[1]);
    else { flush(i); if (ln.trim()) out.push(<p key={i}>{inline(ln)}</p>); }
  });
  flush(9999);
  return <div className="md">{out}</div>;
}

/* group raw input/output rows into one row per call (per trace) */
export function groupCalls(logs: LogRow[]): CallRow[] {
  const map = new Map<string, CallRow>();
  const order: string[] = [];
  for (const r of logs) {
    const tid = r.trace_id || r.id;
    let c = map.get(tid);
    if (!c) {
      c = { trace_id: tid, ts: r.ts, agent: r.agent, model: r.model, provider: r.provider,
            flagged: false, confidence: 0, owasp: null, owasp_name: null, prompt: null,
            response: null, tools: [], tool_calls: [], reasons: [], tiers: [], findings: [], latency_ms: null };
      map.set(tid, c); order.push(tid);
    }
    c.flagged = c.flagged || r.flagged;
    if ((r.confidence || 0) > (c.confidence || 0)) c.confidence = r.confidence;
    if (r.owasp && !c.owasp) { c.owasp = r.owasp; c.owasp_name = r.owasp_name; }
    if (r.direction === "input") { c.prompt = r.text_redacted; c.ts = r.ts; if (r.tiers.length) c.tiers = r.tiers; }
    if (r.direction === "output") { c.response = r.text_redacted; c.latency_ms = r.latency_ms; }
    if (r.tools.length) c.tools = Array.from(new Set([...c.tools, ...r.tools]));
    if (r.tool_calls.length) c.tool_calls = [...c.tool_calls, ...r.tool_calls];
    c.reasons = Array.from(new Set([...c.reasons, ...r.reasons]));
    c.findings = Array.from(new Set([...c.findings, ...r.findings]));
  }
  return order.map((t) => map.get(t)!);
}

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
  return (
    <span className={"tag " + (flagged ? "attack" : "clean")}>
      <span className="pip" />{flagged ? "Flagged" : "Clean"}
    </span>
  );
}

/* a full-sentence explanation of WHY a call was flagged (shown on press) */
export function flagExplain(c: { owasp?: string | null; owasp_name?: string | null; reasons: string[]; findings: string[] }): string {
  if (c.owasp && c.owasp_name) return `Matched ${c.owasp} — ${c.owasp_name}.`;
  const r = (c.reasons[0] || "").toLowerCase();
  if (r.includes("similar")) return "The text is very similar to a known attack in the signature set.";
  if (r.includes("obfusc") || r.includes("decoded")) return "An obfuscated / encoded payload was decoded and matched an attack.";
  if (r.includes("behavioral") || r.includes("agency") || r.includes("tool")) return "The agent's actions looked risky (e.g. excessive or high-risk tool calls).";
  if (c.findings.length) return "The text contained secrets or PII (now redacted).";
  return "The text matched one or more deterministic attack patterns.";
}

/* ===================== icons (lucide, mapped by nav id) ===================== */
const NAV_ICONS: Record<string, typeof LayoutGrid> = {
  overview: LayoutGrid, agents: Bot, threats: Siren, live: Activity, keys: KeyRound, connect: Plug,
};
export function Icon({ name }: { name: string }) {
  const Cmp = NAV_ICONS[name] || LayoutGrid;
  return <Cmp className="ic" strokeWidth={1.8} aria-hidden />;
}

/* ===================== empty + skeleton ===================== */
export function Empty({ icon: IconCmp = Inbox, title, sub }: { icon?: typeof Inbox; title: string; sub?: ReactNode }) {
  return (
    <div className="empty">
      <IconCmp className="ic" aria-hidden />
      <div className="et">{title}</div>
      {sub && <div className="es">{sub}</div>}
    </div>
  );
}
function SkeletonRows({ cols, rows = 5 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, r) => (
        <div className="sk-row" key={r}>
          {Array.from({ length: cols }).map((_, c) => (
            <span key={c} className="sk sk-line" style={{ flex: c === cols - 1 ? "0 0 60px" : 1, opacity: 1 - r * 0.12 }} />
          ))}
        </div>
      ))}
    </>
  );
}

/* ===================== stat cards ===================== */
export function StatCards({ stats }: { stats: Stats | null }) {
  const s = stats;
  const flagPct = s ? Math.round(s.flag_rate * 1000) / 10 : 0;
  const cards = [
    { icon: Cpu, label: "Calls scanned", num: s ? s.total.toLocaleString() : null,
      foot: s ? <><span className="tnum">{s.last_24h.toLocaleString()}</span> in last 24h</> : null },
    { icon: ShieldAlert, label: "Flagged", accent: true, num: s ? s.flagged.toLocaleString() : null,
      foot: s ? <><span className={"trend " + (flagPct > 0 ? "up" : "down")}>
        {flagPct > 0 ? <ArrowUpRight className="ic" /> : <ArrowDownRight className="ic" />}{flagPct}%</span> of all calls</> : null },
    { icon: Users, label: "Agents seen", num: s ? s.agents.toLocaleString() : null, foot: "distinct identities" },
    { icon: Clock, label: "Calus scan time", num: s ? <>~15<span className="u">ms</span></> : null,
      foot: s ? <span style={{ color: "var(--muted-2)", fontSize: 11 }}>↳ {s.avg_latency_ms.toFixed(0)}ms round-trip incl. provider</span> : null },
  ];
  return (
    <div className="grid-stats">
      {cards.map((c) => (
        <div className={"card stat" + (c.accent ? " accent" : "")} key={c.label}>
          <div className="label"><c.icon className="ic" />{c.label}</div>
          <div className="num">{c.num ?? <span className="sk" style={{ width: 84, height: 30, borderRadius: 8 }} />}</div>
          <div className="foot">{c.num != null ? c.foot : <span className="sk" style={{ width: 110, height: 12 }} />}</div>
        </div>
      ))}
    </div>
  );
}

/* ===================== time chart (pure SVG, indigo accent) ===================== */
function fmtBucket(ts: number): string {
  return new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function TimeChart({ data, loading }: { data: Bucket[]; loading?: boolean }) {
  const [hover, setHover] = useState<{ pct: number; i: number } | null>(null);
  const W = 640, H = 180, pad = 6;
  if (loading && data.length === 0) return <div className="chart-wrap"><span className="sk" style={{ width: "100%", height: 180, borderRadius: 10, display: "block" }} /></div>;
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

  const onMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const i = Math.min(data.length - 1, Math.max(0, Math.round(pct * (data.length - 1))));
    setHover({ pct, i });
  };

  const hx = hover ? x(hover.i) : null;
  const tipLeft = hover ? Math.min(85, Math.max(5, hover.pct * 100)) : 0;

  return (
    <>
      <div className="chart-wrap" style={{ position: "relative" }}
        onMouseMove={data.length ? onMouseMove : undefined}
        onMouseLeave={() => setHover(null)}>
        {hover && data[hover.i] && (
          <div className="chart-tip" style={{ left: `${tipLeft}%` }}>
            <div className="ct-time">{fmtBucket(data[hover.i].t)}</div>
            <div className="ct-row"><span className="ct-total">{data[hover.i].total}</span> calls</div>
            <div className="ct-row"><span className="ct-flag">{data[hover.i].flagged}</span> flagged</div>
          </div>
        )}
        <svg className="chart" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label="Traffic chart">
          <defs>
            <linearGradient id="gTot" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgba(91,91,214,0.14)" />
              <stop offset="100%" stopColor="rgba(91,91,214,0)" />
            </linearGradient>
            <linearGradient id="gFlag" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgba(209,69,59,0.16)" />
              <stop offset="100%" stopColor="rgba(209,69,59,0)" />
            </linearGradient>
          </defs>
          <path d={area("total")} fill="url(#gTot)" />
          <path d={line("total")} fill="none" stroke="#5b5bd6" strokeWidth="1.6" vectorEffect="non-scaling-stroke" />
          <path d={area("flagged")} fill="url(#gFlag)" />
          <path d={line("flagged")} fill="none" stroke="#d1453b" strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
          {hx !== null && hover && (
            <>
              <line x1={hx} x2={hx} y1={pad} y2={H - pad}
                stroke="var(--muted-2)" strokeWidth="0.8" strokeDasharray="3 2" vectorEffect="non-scaling-stroke" />
              <circle cx={hx} cy={y(data[hover.i].total)} r="3.5" fill="#5b5bd6" />
              <circle cx={hx} cy={y(data[hover.i].flagged)} r="3.5" fill="#d1453b" />
            </>
          )}
        </svg>
      </div>
      <div className="legend">
        <span><i style={{ background: "#5b5bd6" }} />Total traffic</span>
        <span><i style={{ background: "#d1453b" }} />Flagged</span>
      </div>
    </>
  );
}

/* ===================== threats (OWASP) ===================== */
export function Threats({ threats, loading }: { threats: Threat[]; loading?: boolean }) {
  const max = Math.max(1, ...threats.map((t) => t.count));
  if (loading && threats.length === 0) return <div style={{ padding: "0 20px 8px" }}><SkeletonRows cols={3} rows={4} /></div>;
  if (threats.length === 0) return <Empty icon={ShieldAlert} title="No threats recorded yet" sub="Flagged traffic mapped to the OWASP LLM Top 10 will appear here." />;
  return (
    <div className="threats">
      {threats.map((t) => (
        <div className="threat-row" key={t.owasp}>
          <div className="owasp-code">{t.owasp}</div>
          <div className="meta">
            <div className="nm">{t.name || "Unmapped"}</div>
            <div className="bar"><span style={{ width: (t.count / max) * 100 + "%" }} /></div>
          </div>
          <div className="cnt tnum">{t.count}</div>
        </div>
      ))}
    </div>
  );
}

/* ===================== calls (one row per request) ===================== */
export function CallsTable({ calls, onPick, loading }: { calls: CallRow[]; onPick: (c: CallRow) => void; loading?: boolean }) {
  if (loading && calls.length === 0) return <SkeletonRows cols={6} rows={6} />;
  if (calls.length === 0) return <Empty icon={MessageSquare} title="No calls yet" sub="Send a request through the proxy and it will appear here, scanned in real time." />;
  return (
    <div className="tbl-scroll">
      <table>
        <thead>
          <tr><th>Time</th><th>Agent</th><th>Prompt</th><th>Model</th><th>Verdict</th><th>Conf</th><th>Tools</th></tr>
        </thead>
        <tbody>
          {calls.map((c) => (
            <tr key={c.trace_id} className="clickable" onClick={() => onPick(c)}>
              <td className="cell-time mono">{fmtTime(c.ts)}</td>
              <td className="cell-agent mono">{c.agent || <span style={{ color: "var(--muted-2)" }}>—</span>}</td>
              <td className="prompt-cell">{c.prompt || <span style={{ color: "var(--muted-2)" }}>—</span>}</td>
              <td><div className="model">{(c.model || "—").split("/").pop()}</div>{c.provider && <div className="prov">{c.provider}</div>}</td>
              <td><Tag flagged={c.flagged} /></td>
              <td className="conf">{c.confidence != null ? c.confidence.toFixed(2) : "—"}</td>
              <td>
                <div className="chips">
                  {c.tool_calls.length ? c.tool_calls.map((t, i) => <span className="toolchip" key={i}><Wrench className="ic" />{t.name}</span>)
                    : c.tools.length ? c.tools.map((t) => <span className="toolchip" key={t}><Wrench className="ic" />{t}</span>)
                    : <span style={{ color: "var(--muted-2)" }}>—</span>}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ===================== agents ===================== */
export function AgentsTable({ agents, onPick, loading }: { agents: AgentRow[]; onPick: (a: AgentRow) => void; loading?: boolean }) {
  if (loading && agents.length === 0) return <SkeletonRows cols={6} rows={5} />;
  if (agents.length === 0) return (
    <Empty icon={Users} title="No agents yet"
      sub={<>Set an agent name via the OpenAI <span className="mono">user</span> field or the <span className="mono">X-Calus-Agent</span> header to see each agent here.</>} />
  );
  return (
    <div className="tbl-scroll">
      <table>
        <thead>
          <tr><th>Agent</th><th>Calls</th><th>Flagged</th><th>Tools available</th><th>Models</th><th>Last seen</th></tr>
        </thead>
        <tbody>
          {agents.map((a) => (
            <tr key={a.agent} className="clickable" onClick={() => onPick(a)}>
              <td><div className="agent-cell"><span className="av">{(a.agent || "?").slice(0, 1)}</span><span className="nm">{a.agent}</span></div></td>
              <td className="mono tnum">{a.calls}</td>
              <td>{a.flagged > 0 ? <span className="tag attack"><span className="pip" />{a.flagged}</span> : <span style={{ color: "var(--muted-2)" }} className="mono">0</span>}</td>
              <td><div className="chips">{a.tools.length ? a.tools.slice(0, 5).map((t) => <span className="toolchip" key={t}><Wrench className="ic" />{t}</span>) : <span style={{ color: "var(--muted-2)" }}>none</span>}</div></td>
              <td className="mono" style={{ fontSize: 12, color: "var(--muted)" }}>{a.models.map((m) => m.split("/").pop()).join(", ")}</td>
              <td className="cell-time">{fmtAgo(a.last_ts)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ===================== trace timeline (inside detail drawer) ===================== */
function looksJson(t: string | null): boolean {
  const s = (t || "").trim();
  if (!(s.startsWith("{") || s.startsWith("["))) return false;
  try { JSON.parse(s); return true; } catch { return false; }
}
function TraceTimeline({ rows }: { rows: LogRow[] }) {
  return (
    <div className="trace">
      {rows.map((r) => {
        const isTool = r.direction === "input" && looksJson(r.text_redacted);
        const LblIcon = r.direction === "output" ? CornerDownLeft : isTool ? Wrench : ArrowRight;
        const lbl = r.direction === "output" ? "Model output" : isTool ? "Tool result" : "User / prompt";
        return (
        <div className={"tnode" + (r.flagged ? " flag" : "")} key={r.id}>
          <div className="lbl"><LblIcon className="ic" />{lbl} · {fmtTime(r.ts)}{r.flagged && " · Flagged"}</div>
          {r.text_redacted && (r.direction === "output"
            ? <div className="body"><Markdown text={r.text_redacted} /></div>
            : <div className="body trace-text">{r.text_redacted}</div>)}
          {r.tool_calls.map((t, i) => (
            <div className="tool-line" key={i}>
              <span className="nm">{t.name}()</span>
              {t.arguments && <span className="args">{t.arguments}</span>}
            </div>
          ))}
          {r.tools.length > 0 && r.direction === "input" && !isTool && (
            <div className="chips" style={{ marginTop: 8 }}>{r.tools.map((t) => <span className="toolchip" key={t}><Wrench className="ic" />{t}</span>)}</div>
          )}
        </div>
        );
      })}
    </div>
  );
}

export function LogDetail({ call, trace, onClose }: { call: CallRow; trace: LogRow[]; onClose: () => void }) {
  const matchedReason = call.reasons.find((r) => r.startsWith("matched text:"));
  const matched = matchedReason ? matchedReason.replace(/^matched text:\s*/, "").replace(/^"|"$/g, "") : "";
  const otherReasons = call.reasons.filter((r) => !r.startsWith("matched text:"));
  return (
    <>
      <div className="drawer-bg" onClick={onClose} />
      <div className="drawer" role="dialog" aria-label="Call detail">
        <div className="drawer-head">
          <h3>Call detail</h3>
          <button className="close" onClick={onClose} aria-label="Close"><X className="ic" /></button>
        </div>
        <div style={{ marginBottom: 16 }}><Tag flagged={call.flagged} /></div>
        <div className="row"><span className="k">Agent</span><span className="v mono">{call.agent || "—"}</span></div>
        <div className="row"><span className="k">Model</span><span className="v mono">{call.model || "—"}{call.provider ? ` · ${call.provider}` : ""}</span></div>
        <div className="row"><span className="k">Confidence</span><span className="v mono tnum">{call.confidence != null ? call.confidence.toFixed(3) : "—"}</span></div>
        {call.owasp && <div className="row"><span className="k">OWASP</span><span className="v">{call.owasp} · {call.owasp_name || ""}</span></div>}
        <div className="row"><span className="k">Latency</span><span className="v mono tnum">{call.latency_ms != null ? call.latency_ms.toFixed(0) + " ms" : "—"}</span></div>

        {call.findings.length > 0 && (
          <div className="blk"><div className="t">Secrets / PII found (redacted)</div>
            <div className="chips">{call.findings.map((f) => <span className="finding" key={f}>{f}</span>)}</div></div>
        )}
        {call.flagged && (
          <div className="blk"><div className="t">Why it was flagged</div>
            <div className="flag-explain">{flagExplain(call)}</div>
            {matched && (
              <div className="matched-where">
                <span className="k">Matched text</span>
                <div className="hl">{matched}</div>
              </div>
            )}
            {otherReasons.length > 0 && <div className="reason-tech">{otherReasons.join(" · ")}</div>}
          </div>
        )}
        <div className="blk">
          <div className="t">Conversation — request → tool calls → output</div>
          {trace.length ? <TraceTimeline rows={trace} /> : <Empty icon={MessageSquare} title="No trace available" />}
        </div>
      </div>
    </>
  );
}

/* ===================== API key vault ===================== */
const PROVIDERS = ["openai", "groq", "anthropic", "gemini", "mistral", "cohere", "together", "azure"];

export function KeysPanel({ keys, onAdd, onReveal, onDelete, onUpdate, loading }: {
  keys: KeyRow[];
  onAdd: (provider: string, key: string, label: string) => Promise<void>;
  onReveal: (id: string) => Promise<string>;
  onDelete: (id: string) => Promise<void>;
  onUpdate: (id: string, body: { label?: string; key?: string }) => Promise<void>;
  loading?: boolean;
}) {
  const [provider, setProvider] = useState("openai");
  const [label, setLabel] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [copied, setCopied] = useState<string>("");
  const [editing, setEditing] = useState<string>("");
  const [editLabel, setEditLabel] = useState("");
  const [editKey, setEditKey] = useState("");

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
  const copy = async (id: string) => {
    const full = revealed[id] || (await onReveal(id));
    navigator.clipboard?.writeText(full);
    setCopied(id); setTimeout(() => setCopied(""), 1200);
  };
  const startEdit = (k: KeyRow) => { setEditing(k.id); setEditLabel(k.label || ""); setEditKey(""); };
  const saveEdit = async (id: string) => {
    await onUpdate(id, { label: editLabel, ...(editKey.trim() ? { key: editKey.trim() } : {}) });
    setEditing(""); setEditKey("");
  };

  return (
    <>
      <div className="banner">
        <Lock className="ic" />
        <span>Keys are stored <b>encrypted at rest</b> and shown masked — the full value is only fetched on demand via reveal.
        Calus uses a saved key to forward upstream when a request doesn't carry its own. Provider keys are <b>never</b> written to the call log.</span>
      </div>
      <div className="card flush">
        <div className="keyform">
          <select className="field" value={provider} onChange={(e) => setProvider(e.target.value)} aria-label="Provider">
            {PROVIDERS.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <input className="field" placeholder="label (e.g. prod)" value={label} onChange={(e) => setLabel(e.target.value)} aria-label="Label" />
          <input className="field" placeholder="paste provider API key" type="password" value={secret}
            onChange={(e) => setSecret(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} aria-label="API key" />
          <button className="btn" onClick={add} disabled={busy}><Plus className="ic" />{busy ? "Saving…" : "Add key"}</button>
        </div>
        {loading && keys.length === 0 ? <SkeletonRows cols={4} rows={3} />
          : keys.length === 0 ? <Empty icon={KeyRound} title="No keys saved yet" sub="Add an upstream provider key above. Calus forwards it only when a request doesn't carry its own." />
          : (
          <div className="tbl-scroll">
            <table>
              <thead><tr><th>Provider</th><th>Label</th><th>Key</th><th style={{ textAlign: "right" }}>Actions</th></tr></thead>
              <tbody>
                {keys.map((k) => {
                  const isEnv = k.source === "env";
                  const isEditing = editing === k.id;
                  return (
                    <tr key={k.id}>
                      <td><span className="owasp-pill">{k.provider}</span></td>
                      <td>
                        {isEditing ? (
                          <input className="field mono" style={{ width: 120 }} value={editLabel}
                            placeholder="label" onChange={(e) => setEditLabel(e.target.value)} />
                        ) : (k.label || <span style={{ color: "var(--muted-2)" }}>—</span>)}
                        {isEnv && <span className="env-tag">.env</span>}
                      </td>
                      <td className="key-masked">
                        {isEditing ? (
                          <input className="field mono" style={{ width: 220 }} type="password" value={editKey}
                            placeholder="new key (optional)" onChange={(e) => setEditKey(e.target.value)} />
                        ) : (revealed[k.id] || k.masked)}
                      </td>
                      <td>
                        <div className="key-actions">
                          {isEditing ? (
                            <>
                              <button className="btn sm" onClick={() => saveEdit(k.id)}><Check className="ic" />Save</button>
                              <button className="btn ghost sm" onClick={() => setEditing("")}>Cancel</button>
                            </>
                          ) : (
                            <>
                              <button className="btn ghost sm" onClick={() => reveal(k.id)}>{revealed[k.id] ? <><EyeOff className="ic" />Hide</> : <><Eye className="ic" />Reveal</>}</button>
                              <button className="btn ghost sm" onClick={() => copy(k.id)}>{copied === k.id ? <><Check className="ic" />Copied</> : <><Copy className="ic" />Copy</>}</button>
                              {!isEnv && <>
                                <button className="btn ghost sm" onClick={() => startEdit(k)}><Pencil className="ic" />Edit</button>
                                <button className="btn danger sm" onClick={() => onDelete(k.id)}><Trash2 className="ic" />Delete</button>
                              </>}
                              {isEnv && <span className="env-note">.env · read-only</span>}
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

/* ===================== connect (drop-in onboarding) ===================== */
function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => { navigator.clipboard?.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1200); };
  return (
    <div className="code">
      <button className="copy" onClick={copy}>{copied ? <><Check className="ic" />copied</> : <><Copy className="ic" />copy</>}</button>
      <pre>{code}</pre>
    </div>
  );
}

export function ConnectPanel({ base, token }: { base: string; token: string }) {
  const [setupTab, setSetupTab] = useState("docker");
  const [sdkTab, setSdkTab] = useState("env");
  const [show, setShow] = useState(false);
  const [copied, setCopied] = useState(false);
  const url = base.replace(/\/$/, "");
  const masked = token.length > 8 ? `${token.slice(0, 4)}${"•".repeat(18)}${token.slice(-4)}` : "••••••••";
  const copyToken = () => { navigator.clipboard?.writeText(token); setCopied(true); setTimeout(() => setCopied(false), 1200); };

  const setupSnippets: Record<string, string> = {
    docker:
`git clone https://github.com/wholesphereai/calus.git
cd calus
cp proxy/.env.example proxy/.env   # add provider keys
docker compose up --build

# Dashboard  →  http://localhost:5173
# Proxy      →  http://localhost:8000`,
    local:
`git clone https://github.com/wholesphereai/calus.git
cd calus

# Windows
python -m venv .venv && .venv\\Scripts\\activate
# macOS / Linux
# source .venv/bin/activate

python -m pip install -e calus          # engine

# Terminal 1 — proxy
cd proxy && pip install -r requirements.txt
cp .env.example .env
python -m uvicorn calus_proxy.main:app --port 8000

# Terminal 2 — dashboard
cd dashboard && npm install && npm run dev   # → http://localhost:5173`,
  };

  const sdkSnippets: Record<string, string> = {
    env:
`export OPENAI_BASE_URL="${url}/v1"
# Keep your own provider key — Calus forwards it, never stores it.
# Run your app as usual. No other changes needed.`,
    openai:
`from openai import OpenAI

client = OpenAI(
    base_url="${url}/v1",
    api_key="sk-your-own-key",
)
client.chat.completions.create(
    model="groq/llama-3.3-70b-versatile",
    user="my-agent",               # names the agent in Calus
    messages=[{"role": "user", "content": "Hello"}],
)`,
    node:
`import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "${url}/v1",
  apiKey: "sk-your-own-key",
  defaultHeaders: { "X-Calus-Agent": "my-agent" },
});

await client.chat.completions.create({
  model: "groq/llama-3.3-70b-versatile",
  messages: [{ role: "user", content: "Hello" }],
});`,
    langchain:
`from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="groq/llama-3.3-70b-versatile",
    base_url="${url}/v1",
    api_key="sk-your-own-key",
    default_headers={"X-Calus-Agent": "my-agent"},
)`,
    claude:
`export ANTHROPIC_BASE_URL="${url}"
export OPENAI_BASE_URL="${url}/v1"
claude   # every prompt now flows through Calus`,
    curl:
`curl ${url}/v1/chat/completions \\
  -H "Authorization: Bearer sk-your-own-key" \\
  -H "Content-Type: application/json" \\
  -H "X-Calus-Agent: my-agent" \\
  -d '{"model":"groq/llama-3.3-70b-versatile",
       "messages":[{"role":"user","content":"Hello"}]}'`,
  };

  const sdkTabs = [["env","Env var"],["openai","OpenAI Python"],["node","Node.js"],["langchain","LangChain"],["claude","Claude Code"],["curl","curl"]];

  return (
    <>
      {/* ── 1. Quick start ── */}
      <div className="card flush">
        <div className="panel-head">
          <h3>Quick start</h3>
        </div>
        <div style={{ padding: "14px 20px 0" }}>
          <div className="tabs">
            <button className={setupTab === "docker" ? "on" : ""} onClick={() => setSetupTab("docker")}>Docker (recommended)</button>
            <button className={setupTab === "local" ? "on" : ""} onClick={() => setSetupTab("local")}>Local (no Docker)</button>
          </div>
          {setupTab === "docker" && (
            <p className="setup-note">Admin token auto-generates if <span className="mono">CALUS_ADMIN_TOKEN</span> is blank in <span className="mono">proxy/.env</span>. Copy it from the proxy startup log into the dashboard. Set a fixed value only if you need it stable across restarts.</p>
          )}
        </div>
        <div style={{ padding: "10px 20px 20px" }}>
          <CodeBlock code={setupSnippets[setupTab]} />
        </div>
      </div>

      {/* ── 2. Connect your app ── */}
      <div className="card flush">
        <div className="panel-head">
          <h3>Connect your app</h3>
          <span className="hint">drop-in · no code changes · nothing blocked</span>
        </div>
        <div style={{ padding: "0 20px" }}>
          <div className="endpoint-row" style={{ borderBottom: "1px solid var(--line)" }}>
            <span style={{ color: "var(--muted)", fontWeight: 500, fontSize: 12.5 }}>Proxy endpoint</span>
            <span className="mono" style={{ fontSize: 12.5, color: "var(--fg-2)" }}>{url}/v1</span>
          </div>
          <div className="endpoint-row">
            <span style={{ color: "var(--muted)", fontWeight: 500, fontSize: 12.5 }}>Admin token</span>
            <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className="mono" style={{ fontSize: 12.5, color: "var(--fg-2)" }}>{show ? token : masked}</span>
              <button className="btn ghost sm" onClick={() => setShow(s => !s)}>{show ? <><EyeOff className="ic" />Hide</> : <><Eye className="ic" />Reveal</>}</button>
              <button className="btn ghost sm" onClick={copyToken}>{copied ? <><Check className="ic" />Copied</> : <><Copy className="ic" />Copy</>}</button>
            </span>
          </div>
        </div>
        <div style={{ padding: "14px 20px 0", borderTop: "1px solid var(--line)" }}>
          <div className="tabs">
            {sdkTabs.map(([k, lbl]) => (
              <button key={k} className={sdkTab === k ? "on" : ""} onClick={() => setSdkTab(k)}>{lbl}</button>
            ))}
          </div>
        </div>
        <div style={{ padding: "10px 20px 20px" }}>
          <CodeBlock code={sdkSnippets[sdkTab]} />
        </div>
      </div>

      {/* ── 3. Name your agents ── */}
      <div className="card flush">
        <div className="panel-head">
          <h3>Name your agents</h3>
          <span className="hint">without a name, every call lands as "unknown"</span>
        </div>
        <div style={{ padding: "14px 20px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div>
            <div className="blk-label">Via user field — OpenAI body</div>
            <CodeBlock code={`client.chat.completions.create(\n    user="my-agent",   # ← add this\n    ...\n)`} />
          </div>
          <div>
            <div className="blk-label">Via header — any framework</div>
            <CodeBlock code={`# OpenAI SDK\nOpenAI(default_headers={"X-Calus-Agent": "my-agent"})\n\n# curl / fetch\n-H "X-Calus-Agent: my-agent"`} />
          </div>
        </div>
        <div style={{ padding: "0 20px 16px", fontSize: 12, color: "var(--muted)", lineHeight: 1.55 }}>
          Both methods are equivalent — the agent appears by name in the Agents tab with its call count, flagged activity, and tool traces.
        </div>
      </div>
    </>
  );
}

/* ===================== logo mark ===================== */
export function CalusLogoMark({ size = 24 }: { size?: number }) {
  return (
    <img src="/logo-white.png" alt="Calus" width={size} height={size}
      className="logo-mark"
      style={{ objectFit: "contain", display: "block" }} />
  );
}

/* ===================== token gate ===================== */
export function TokenGate({ onSubmit, error }: { onSubmit: (t: string) => void; error?: string }) {
  const [val, setVal] = useState("");
  return (
    <div className="gate">
      <div className="gate-card">
        <div className="mark"><CalusLogoMark size={56} /></div>
        <h2>Calus console</h2>
        <p>Enter your admin token to view live detection traffic. It's the <span className="mono">CALUS_ADMIN_TOKEN</span> your proxy printed at startup.</p>
        <input type="password" placeholder="admin token" value={val} autoFocus
          onChange={(e) => setVal(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") onSubmit(val); }} />
        <button className="btn" onClick={() => onSubmit(val)}>Connect</button>
        {error && <div className="err"><AlertCircle className="ic" />{error}</div>}
      </div>
    </div>
  );
}

/* re-export icons used directly by App */
export { Radio, Info };
