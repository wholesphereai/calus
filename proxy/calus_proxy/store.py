"""Secure, dependency-free SQLite store for proxy call logs + the API-key vault.

Security notes:
- Parameterized queries everywhere (no string-built SQL).
- Provider API keys used for forwarding are never written to the call log.
- Saved keys live in the `vault` table ENCRYPTED (see crypto.py); the plaintext
  is only ever held in memory while forwarding a request.
- Prompt/response text is optional and redacted before write (see config).
- The DB file should sit on an encrypted volume for at-rest protection.
"""
import sqlite3
import json
import time
import threading
import uuid
from contextlib import contextmanager

from . import crypto

# Tables only. New columns are added by migration, and indexes are created AFTER
# migration — so an index on a freshly-added column never runs before the column
# exists on a pre-existing DB.
_TABLES = """
CREATE TABLE IF NOT EXISTS calls (
    id            TEXT PRIMARY KEY,
    ts            REAL NOT NULL,
    trace_id      TEXT,            -- correlates the input + output of one request
    agent         TEXT,            -- agent / user identifier (OpenAI 'user' or header)
    model         TEXT,
    provider      TEXT,
    direction     TEXT,            -- 'input' | 'output'
    flagged       INTEGER NOT NULL DEFAULT 0,
    confidence    REAL,
    owasp         TEXT,
    owasp_name    TEXT,
    reasons       TEXT,            -- json array
    tiers         TEXT,            -- json array
    tools         TEXT,            -- json array: tool/function names available
    tool_calls    TEXT,            -- json array: {name, arguments} actually invoked
    latency_ms    REAL,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    text_redacted TEXT,            -- redacted preview, may be NULL
    findings      TEXT             -- json: secrets/PII types found (redaction), no values
);

CREATE TABLE IF NOT EXISTS vault (
    id         TEXT PRIMARY KEY,
    ts         REAL NOT NULL,
    provider   TEXT NOT NULL,      -- openai | groq | anthropic | gemini | ...
    label      TEXT,               -- human name, e.g. "prod openai"
    masked     TEXT,               -- safe preview, e.g. "sk-…b1F0"
    ciphertext TEXT NOT NULL       -- encrypted full key (crypto.encrypt)
);
"""

_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_calls_ts ON calls(ts DESC);
CREATE INDEX IF NOT EXISTS idx_calls_flagged ON calls(flagged);
CREATE INDEX IF NOT EXISTS idx_calls_owasp ON calls(owasp);
CREATE INDEX IF NOT EXISTS idx_calls_agent ON calls(agent);
CREATE INDEX IF NOT EXISTS idx_calls_trace ON calls(trace_id);
"""

# columns added after v1 — migrate older DBs in place
_MIGRATIONS = ["trace_id", "agent", "tools", "tool_calls"]


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(_TABLES)
            cols = {r["name"] for r in c.execute("PRAGMA table_info(calls)")}
            for col in _MIGRATIONS:
                if col not in cols:
                    c.execute(f"ALTER TABLE calls ADD COLUMN {col} TEXT")
            c.executescript(_INDEXES)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        # WAL + a busy timeout keep concurrent request writes and dashboard reads
        # from tripping "database is locked".
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
        except Exception:
            pass
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ----------------------------- call log -----------------------------
    def record(self, **row) -> str:
        rid = row.get("id") or uuid.uuid4().hex
        cols = ("id", "ts", "trace_id", "agent", "model", "provider", "direction",
                "flagged", "confidence", "owasp", "owasp_name", "reasons", "tiers",
                "tools", "tool_calls", "latency_ms", "prompt_tokens",
                "completion_tokens", "text_redacted", "findings")
        vals = (
            rid, row.get("ts", time.time()), row.get("trace_id"), row.get("agent"),
            row.get("model"), row.get("provider"), row.get("direction"),
            1 if row.get("flagged") else 0, row.get("confidence"),
            row.get("owasp"), row.get("owasp_name"),
            json.dumps(row.get("reasons") or []), json.dumps(row.get("tiers") or []),
            json.dumps(row.get("tools") or []), json.dumps(row.get("tool_calls") or []),
            row.get("latency_ms"), row.get("prompt_tokens"), row.get("completion_tokens"),
            row.get("text_redacted"), json.dumps(row.get("findings") or []),
        )
        with self._lock, self._conn() as c:
            c.execute(f"INSERT INTO calls ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
        return rid

    def logs(self, limit=50, offset=0, flagged=None, owasp=None, agent=None):
        q = "SELECT * FROM calls"
        where, args = [], []
        if flagged is not None:
            where.append("flagged = ?"); args.append(1 if flagged else 0)
        if owasp:
            where.append("owasp = ?"); args.append(owasp)
        if agent:
            where.append("agent = ?"); args.append(agent)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        args += [int(limit), int(offset)]
        with self._conn() as c:
            return [self._row(r) for r in c.execute(q, args).fetchall()]

    def get(self, rid):
        with self._conn() as c:
            r = c.execute("SELECT * FROM calls WHERE id = ?", (rid,)).fetchone()
            return self._row(r) if r else None

    def trace(self, trace_id):
        """Both directions (input + output) of one request, oldest first."""
        with self._conn() as c:
            rows = c.execute("SELECT * FROM calls WHERE trace_id = ? ORDER BY ts ASC",
                             (trace_id,)).fetchall()
            return [self._row(r) for r in rows]

    def stats(self):
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM calls").fetchone()["n"]
            flagged = c.execute("SELECT COUNT(*) n FROM calls WHERE flagged=1").fetchone()["n"]
            last24 = c.execute("SELECT COUNT(*) n FROM calls WHERE ts > ?",
                               (time.time() - 86400,)).fetchone()["n"]
            avg = c.execute("SELECT AVG(latency_ms) a FROM calls").fetchone()["a"]
            agents = c.execute("SELECT COUNT(DISTINCT agent) n FROM calls "
                               "WHERE agent IS NOT NULL AND agent != ''").fetchone()["n"]
            return {"total": total, "flagged": flagged, "clean": total - flagged,
                    "last_24h": last24, "avg_latency_ms": round(avg, 1) if avg else 0.0,
                    "flag_rate": round(flagged / total, 4) if total else 0.0,
                    "agents": agents}

    def threats(self):
        with self._conn() as c:
            rows = c.execute(
                "SELECT owasp, owasp_name, COUNT(*) n FROM calls "
                "WHERE flagged=1 AND owasp IS NOT NULL AND owasp != '' "
                "GROUP BY owasp ORDER BY n DESC").fetchall()
            return [{"owasp": r["owasp"], "name": r["owasp_name"], "count": r["n"]} for r in rows]

    def agents(self):
        """Per-agent rollup: traffic, flagged count, tools seen, last activity."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT agent, COUNT(*) calls, "
                "SUM(flagged) flagged, MAX(ts) last_ts "
                "FROM calls WHERE agent IS NOT NULL AND agent != '' "
                "GROUP BY agent ORDER BY last_ts DESC").fetchall()
            out = []
            for r in rows:
                tools = set()
                models = set()
                for tr in c.execute("SELECT tools, model FROM calls WHERE agent = ?", (r["agent"],)):
                    try:
                        tools.update(json.loads(tr["tools"]) if tr["tools"] else [])
                    except Exception:
                        pass
                    if tr["model"]:
                        models.add(tr["model"])
                out.append({"agent": r["agent"], "calls": r["calls"],
                            "flagged": r["flagged"] or 0,
                            "tools": sorted(tools), "models": sorted(models),
                            "last_ts": r["last_ts"]})
            return out

    def timeseries(self, hours=24, buckets=24):
        now = time.time(); span = hours * 3600; width = span / buckets
        out = [{"t": now - span + i * width, "total": 0, "flagged": 0} for i in range(buckets)]
        with self._conn() as c:
            for r in c.execute("SELECT ts, flagged FROM calls WHERE ts > ?", (now - span,)):
                i = min(int((r["ts"] - (now - span)) / width), buckets - 1)
                if i >= 0:
                    out[i]["total"] += 1
                    out[i]["flagged"] += r["flagged"]
        return out

    # ----------------------------- key vault ----------------------------
    def add_key(self, provider: str, secret: str, label: str = "") -> dict:
        kid = uuid.uuid4().hex
        rec = {"id": kid, "ts": time.time(), "provider": provider.strip().lower(),
               "label": label.strip(), "masked": crypto.mask(secret),
               "ciphertext": crypto.encrypt(secret)}
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO vault (id, ts, provider, label, masked, ciphertext) "
                      "VALUES (?,?,?,?,?,?)",
                      (rec["id"], rec["ts"], rec["provider"], rec["label"],
                       rec["masked"], rec["ciphertext"]))
        return {k: rec[k] for k in ("id", "ts", "provider", "label", "masked")}

    def list_keys(self):
        with self._conn() as c:
            rows = c.execute("SELECT id, ts, provider, label, masked FROM vault "
                             "ORDER BY ts DESC").fetchall()
            return [dict(r) for r in rows]

    def reveal_key(self, kid: str):
        with self._conn() as c:
            r = c.execute("SELECT ciphertext FROM vault WHERE id = ?", (kid,)).fetchone()
            return crypto.decrypt(r["ciphertext"]) if r else None

    def key_for_provider(self, provider: str):
        """Most recently added saved key for a provider (decrypted), or None."""
        with self._conn() as c:
            r = c.execute("SELECT ciphertext FROM vault WHERE provider = ? "
                          "ORDER BY ts DESC LIMIT 1", (provider.strip().lower(),)).fetchone()
            return crypto.decrypt(r["ciphertext"]) if r else None

    def update_key(self, kid: str, label=None, secret=None) -> bool:
        sets, args = [], []
        if label is not None:
            sets.append("label = ?"); args.append(label.strip())
        if secret:
            sets.append("masked = ?"); args.append(crypto.mask(secret))
            sets.append("ciphertext = ?"); args.append(crypto.encrypt(secret))
        if not sets:
            return True
        args.append(kid)
        with self._lock, self._conn() as c:
            cur = c.execute(f"UPDATE vault SET {', '.join(sets)} WHERE id = ?", args)
            return cur.rowcount > 0

    def delete_key(self, kid: str) -> bool:
        with self._lock, self._conn() as c:
            cur = c.execute("DELETE FROM vault WHERE id = ?", (kid,))
            return cur.rowcount > 0

    @staticmethod
    def _row(r):
        d = dict(r)
        d["flagged"] = bool(d["flagged"])
        for k in ("reasons", "tiers", "findings", "tools", "tool_calls"):
            try:
                d[k] = json.loads(d[k]) if d.get(k) else []
            except Exception:
                d[k] = []
        return d
