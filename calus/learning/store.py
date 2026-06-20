"""
CALUS.learning.store
~~~~~~~~~~~~~~~~~~~~~~~~~~
All persistence for the self-improvement engine.

Tables:
  threat_corpus   — every detected threat message (normalized + raw)
  benign_corpus   — every clean message (sample, capped at MAX_BENIGN)
  learned_patterns — generated patterns with scores and status
  pattern_hits    — runtime hit log for learned patterns
  fp_reports      — false-positive reports for pruning
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional

log = logging.getLogger(__name__)

DB_PATH   = Path.home() / ".CALUS" / "CALUS.db"
MAX_BENIGN = 5000   # cap benign corpus size to avoid bloat


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init() -> None:
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS threat_corpus (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            TEXT    NOT NULL,
            raw_text      TEXT    NOT NULL,
            norm_text     TEXT    NOT NULL,
            severity      TEXT    NOT NULL,
            layers_hit    TEXT    NOT NULL,
            graph         TEXT,
            node          TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_tc_ts ON threat_corpus(ts);

        CREATE TABLE IF NOT EXISTS benign_corpus (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT    NOT NULL,
            norm_text TEXT    NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS learned_patterns (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_created      TEXT NOT NULL,
            ts_updated      TEXT NOT NULL,
            pattern_text    TEXT NOT NULL UNIQUE,
            pattern_regex   TEXT NOT NULL,
            attack_family   TEXT NOT NULL,
            score           REAL NOT NULL DEFAULT 0.0,
            precision_score REAL NOT NULL DEFAULT 0.0,
            specificity     REAL NOT NULL DEFAULT 0.0,
            coverage        INTEGER NOT NULL DEFAULT 0,
            times_hit       INTEGER NOT NULL DEFAULT 0,
            false_positives INTEGER NOT NULL DEFAULT 0,
            source_count    INTEGER NOT NULL DEFAULT 1,
            status          TEXT NOT NULL DEFAULT 'pending',
            accepted_ts     TEXT,
            disabled_ts     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lp_status ON learned_patterns(status);

        CREATE TABLE IF NOT EXISTS pattern_hits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            pattern_id  INTEGER NOT NULL,
            node        TEXT,
            severity    TEXT
        );

        CREATE TABLE IF NOT EXISTS fp_reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            pattern_id  INTEGER NOT NULL,
            text_sample TEXT
        );
        """)


try:
    init()
except Exception as _e:
    log.debug("[CALUS:store] init failed: %s", _e)


# ── Write ──────────────────────────────────────────────────────────────────

def add_threat(raw: str, norm: str, severity: str, layers: list,
               graph: str = None, node: str = None) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO threat_corpus (ts,raw_text,norm_text,severity,layers_hit,graph,node) "
            "VALUES (?,?,?,?,?,?,?)",
            (datetime.utcnow().isoformat(), raw, norm, severity,
             json.dumps(layers), graph, node)
        )
        return cur.lastrowid


def add_benign(norm: str) -> None:
    with _conn() as c:
        count = c.execute("SELECT COUNT(*) FROM benign_corpus").fetchone()[0]
        if count >= MAX_BENIGN:
            # Delete oldest 10% to make room
            c.execute("""DELETE FROM benign_corpus WHERE id IN (
                SELECT id FROM benign_corpus ORDER BY id ASC LIMIT ?)""",
                (MAX_BENIGN // 10,))
        try:
            c.execute("INSERT OR IGNORE INTO benign_corpus (ts,norm_text) VALUES (?,?)",
                      (datetime.utcnow().isoformat(), norm))
        except Exception:
            pass


def upsert_pattern(pattern_text: str, pattern_regex: str, attack_family: str,
                   score: float, precision: float, specificity: float,
                   coverage: int, source_count: int) -> int:
    now = datetime.utcnow().isoformat()
    with _conn() as c:
        existing = c.execute(
            "SELECT id,source_count FROM learned_patterns WHERE pattern_text=?",
            (pattern_text,)
        ).fetchone()
        if existing:
            new_src = max(existing["source_count"], source_count)
            c.execute("""UPDATE learned_patterns
                SET ts_updated=?, score=?, precision_score=?, specificity=?,
                    coverage=?, source_count=?, pattern_regex=?
                WHERE id=?""",
                (now, score, precision, specificity, coverage, new_src,
                 pattern_regex, existing["id"]))
            return existing["id"]
        cur = c.execute("""INSERT INTO learned_patterns
            (ts_created,ts_updated,pattern_text,pattern_regex,attack_family,
             score,precision_score,specificity,coverage,source_count)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (now, now, pattern_text, pattern_regex, attack_family,
             score, precision, specificity, coverage, source_count))
        return cur.lastrowid


def record_hit(pattern_id: int, node: str = None, severity: str = None) -> None:
    with _conn() as c:
        c.execute("INSERT INTO pattern_hits (ts,pattern_id,node,severity) VALUES (?,?,?,?)",
                  (datetime.utcnow().isoformat(), pattern_id, node, severity))
        c.execute("UPDATE learned_patterns SET times_hit=times_hit+1 WHERE id=?",
                  (pattern_id,))


def report_fp(pattern_id: int, text_sample: str = None) -> None:
    with _conn() as c:
        c.execute("INSERT INTO fp_reports (ts,pattern_id,text_sample) VALUES (?,?,?)",
                  (datetime.utcnow().isoformat(), pattern_id, (text_sample or "")[:200]))
        c.execute("UPDATE learned_patterns SET false_positives=false_positives+1 WHERE id=?",
                  (pattern_id,))
        row = c.execute(
            "SELECT false_positives, times_hit FROM learned_patterns WHERE id=?",
            (pattern_id,)
        ).fetchone()
        if row and row["times_hit"] > 0:
            fp_rate = row["false_positives"] / row["times_hit"]
            if fp_rate > 0.3 and row["false_positives"] >= 3:
                c.execute(
                    "UPDATE learned_patterns SET status='disabled',disabled_ts=? WHERE id=?",
                    (datetime.utcnow().isoformat(), pattern_id)
                )
                log.info("[CALUS:store] pattern %d auto-disabled (fp_rate=%.2f)", pattern_id, fp_rate)


def accept(pattern_id: int) -> None:
    with _conn() as c:
        c.execute("UPDATE learned_patterns SET status='accepted',accepted_ts=? WHERE id=?",
                  (datetime.utcnow().isoformat(), pattern_id))


def reject(pattern_id: int) -> None:
    with _conn() as c:
        c.execute("UPDATE learned_patterns SET status='rejected' WHERE id=?", (pattern_id,))


# ── Read ───────────────────────────────────────────────────────────────────

def load_active_patterns() -> List[dict]:
    """Return all accepted patterns for loading into Aho-Corasick."""
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM learned_patterns WHERE status='accepted' ORDER BY score DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def pending_patterns(min_score: float = 0.0) -> List[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM learned_patterns WHERE status='pending' AND score>=? ORDER BY score DESC",
            (min_score,)
        ).fetchall()
    return [dict(r) for r in rows]


def threat_sample(limit: int = 2000) -> List[str]:
    with _conn() as c:
        rows = c.execute(
            "SELECT norm_text FROM threat_corpus ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [r["norm_text"] for r in rows]


def benign_sample(limit: int = 2000) -> List[str]:
    with _conn() as c:
        rows = c.execute(
            "SELECT norm_text FROM benign_corpus ORDER BY RANDOM() LIMIT ?", (limit,)
        ).fetchall()
    return [r["norm_text"] for r in rows]


def threat_count() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM threat_corpus").fetchone()[0]


def benign_count() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM benign_corpus").fetchone()[0]


def stats() -> dict:
    with _conn() as c:
        tc  = c.execute("SELECT COUNT(*) FROM threat_corpus").fetchone()[0]
        bc  = c.execute("SELECT COUNT(*) FROM benign_corpus").fetchone()[0]
        lp  = c.execute("SELECT COUNT(*) FROM learned_patterns").fetchone()[0]
        pen = c.execute("SELECT COUNT(*) FROM learned_patterns WHERE status='pending'").fetchone()[0]
        acc = c.execute("SELECT COUNT(*) FROM learned_patterns WHERE status='accepted'").fetchone()[0]
        rej = c.execute("SELECT COUNT(*) FROM learned_patterns WHERE status='rejected'").fetchone()[0]
        dis = c.execute("SELECT COUNT(*) FROM learned_patterns WHERE status='disabled'").fetchone()[0]
        hits = c.execute("SELECT SUM(times_hit) FROM learned_patterns WHERE status='accepted'").fetchone()[0] or 0
        fps  = c.execute("SELECT SUM(false_positives) FROM learned_patterns").fetchone()[0] or 0
    return {
        "threat_corpus": tc,  "benign_corpus": bc,
        "patterns_total": lp, "pending": pen,
        "accepted": acc,      "rejected": rej,
        "disabled": dis,      "hits_by_learned": hits,
        "false_positives": fps,
    }
