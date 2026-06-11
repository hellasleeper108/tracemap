"""
db.py — SQLite schema and all query functions.
Database lives at ~/.local/share/tracemap/tracemap.db
"""

import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path.home() / ".local" / "share" / "tracemap" / "tracemap.db"


def set_db_path(path: str):
    global DB_PATH
    DB_PATH = Path(path)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS geo_cache (
                ip          TEXT PRIMARY KEY,
                country     TEXT,
                countryCode TEXT,
                city        TEXT,
                lat         REAL,
                lon         REAL,
                org         TEXT,
                isp         TEXT,
                fetched_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connections_log (
                id         INTEGER PRIMARY KEY,
                ip         TEXT    NOT NULL,
                port       TEXT,
                local_port TEXT,
                process    TEXT,
                seen_at    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_log_ip     ON connections_log(ip);
            CREATE INDEX IF NOT EXISTS idx_log_seen   ON connections_log(seen_at);

            CREATE TABLE IF NOT EXISTS threat_cache (
                ip          TEXT    PRIMARY KEY,
                abuse_score INTEGER,
                reports     INTEGER,
                checked_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS traceroutes (
                id        INTEGER PRIMARY KEY,
                target_ip TEXT    NOT NULL,
                ran_at    INTEGER NOT NULL,
                hops      TEXT
            );

            CREATE TABLE IF NOT EXISTS dns_cache (
                ip          TEXT    PRIMARY KEY,
                hostname    TEXT    NOT NULL DEFAULT '',
                resolved_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reputation_cache (
                source     TEXT    NOT NULL,
                ip         TEXT    NOT NULL,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (source, ip)
            );

            CREATE TABLE IF NOT EXISTS threat_sources (
                ip         TEXT    NOT NULL,
                source     TEXT    NOT NULL,
                score      INTEGER NOT NULL DEFAULT 0,
                raw        TEXT    NOT NULL DEFAULT '{}',
                checked_at INTEGER NOT NULL,
                PRIMARY KEY (ip, source)
            );

            CREATE TABLE IF NOT EXISTS alert_rules (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type  TEXT    NOT NULL,
                condition  TEXT    NOT NULL DEFAULT '{}',
                action     TEXT    NOT NULL DEFAULT '{"type":"desktop"}',
                enabled    INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alert_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id    INTEGER,
                rule_type  TEXT    NOT NULL,
                ip         TEXT    NOT NULL DEFAULT '',
                msg        TEXT    NOT NULL,
                read       INTEGER NOT NULL DEFAULT 0,
                sent       INTEGER NOT NULL DEFAULT 0,
                ts         INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alert_events_sent ON alert_events(sent);
            CREATE INDEX IF NOT EXISTS idx_alert_events_ts   ON alert_events(ts);

            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip         TEXT    PRIMARY KEY,
                blocked_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ip_notes (
                ip         TEXT    PRIMARY KEY,
                note       TEXT    NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL
            );
        """)


# ── geo_cache ──────────────────────────────────────────────────────────────────

def get_geo(ip: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM geo_cache WHERE ip = ?", (ip,)
        ).fetchone()
        return dict(row) if row else None


def set_geo(ip: str, data: dict):
    with _connect() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO geo_cache
                (ip, country, countryCode, city, lat, lon, org, isp, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            data.get("country"),
            data.get("countryCode"),
            data.get("city"),
            data.get("lat"),
            data.get("lon"),
            data.get("org"),
            data.get("isp"),
            int(time.time()),
        ))


# ── connections_log ────────────────────────────────────────────────────────────

def log_connections(conns: list[dict]):
    if not conns:
        return
    now = int(time.time())
    with _connect() as conn:
        conn.executemany("""
            INSERT INTO connections_log (ip, port, local_port, process, seen_at)
            VALUES (:ip, :port, :local_port, :process, :seen_at)
        """, [{**c, "seen_at": now} for c in conns])


def get_history(ip: str, limit: int = 500) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("""
            SELECT ip, port, process, seen_at
            FROM connections_log
            WHERE ip = ?
            ORDER BY seen_at DESC
            LIMIT ?
        """, (ip, limit)).fetchall()
        return [dict(r) for r in rows]


def get_first_seen(ip: str) -> int | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT MIN(seen_at) AS t FROM connections_log WHERE ip = ?", (ip,)
        ).fetchone()
        return row["t"] if row else None


# ── threat_cache ───────────────────────────────────────────────────────────────

def get_threat(ip: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM threat_cache WHERE ip = ?", (ip,)
        ).fetchone()
        return dict(row) if row else None


def set_threat(ip: str, data: dict):
    with _connect() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO threat_cache (ip, abuse_score, reports, checked_at)
            VALUES (?, ?, ?, ?)
        """, (ip, data.get("abuse_score", 0), data.get("reports", 0), int(time.time())))


def get_ips_needing_threat_check(ttl: int, limit: int = 50) -> list[str]:
    """IPs seen in connections_log that have no threat record or a stale one."""
    cutoff = int(time.time()) - ttl
    with _connect() as conn:
        rows = conn.execute("""
            SELECT DISTINCT cl.ip
            FROM connections_log cl
            LEFT JOIN threat_cache tc ON cl.ip = tc.ip
            WHERE tc.ip IS NULL OR tc.checked_at < ?
            ORDER BY cl.seen_at DESC
            LIMIT ?
        """, (cutoff, limit)).fetchall()
        return [r["ip"] for r in rows]


# ── traceroutes ────────────────────────────────────────────────────────────────

def store_traceroute(ip: str, hops: list[dict]):
    with _connect() as conn:
        conn.execute("DELETE FROM traceroutes WHERE target_ip = ?", (ip,))
        conn.execute("""
            INSERT INTO traceroutes (target_ip, ran_at, hops)
            VALUES (?, ?, ?)
        """, (ip, int(time.time()), json.dumps(hops)))


DNS_TTL = 86400  # 24 hours


def get_hostname(ip: str) -> str | None:
    """Return cached hostname if fresh (within DNS_TTL), else None."""
    cutoff = int(time.time()) - DNS_TTL
    with _connect() as conn:
        row = conn.execute(
            "SELECT hostname FROM dns_cache WHERE ip = ? AND resolved_at > ?",
            (ip, cutoff)
        ).fetchone()
        return row["hostname"] if row else None


def set_hostname(ip: str, hostname: str):
    with _connect() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO dns_cache (ip, hostname, resolved_at)
            VALUES (?, ?, ?)
        """, (ip, hostname, int(time.time())))


def get_traceroute(ip: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM traceroutes WHERE target_ip = ? ORDER BY ran_at DESC LIMIT 1", (ip,)
        ).fetchone()
        if not row:
            return None
        return {
            "ip":     row["target_ip"],
            "ran_at": row["ran_at"],
            "hops":   json.loads(row["hops"]),
        }


# ── reputation_cache ───────────────────────────────────────────────────────────

def get_reputation_fetched_at(source: str) -> int | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT MAX(fetched_at) AS t FROM reputation_cache WHERE source = ?", (source,)
        ).fetchone()
        return row["t"]


def bulk_set_reputation(source: str, ips: list[str]):
    """Atomically replace all IPs for a source."""
    now = int(time.time())
    with _connect() as conn:
        conn.execute("DELETE FROM reputation_cache WHERE source = ?", (source,))
        conn.executemany(
            "INSERT INTO reputation_cache (source, ip, fetched_at) VALUES (?, ?, ?)",
            [(source, ip, now) for ip in ips],
        )


def is_reputation_flagged(source: str, ip: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM reputation_cache WHERE source = ? AND ip = ?", (source, ip)
        ).fetchone()
        return row is not None


def get_reputation_ips(source: str) -> list[str]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ip FROM reputation_cache WHERE source = ?", (source,)
        ).fetchall()
        return [r["ip"] for r in rows]


# ── threat_sources ─────────────────────────────────────────────────────────────

def set_threat_source(ip: str, source: str, score: int, raw: dict):
    with _connect() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO threat_sources (ip, source, score, raw, checked_at)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, source, score, json.dumps(raw), int(time.time())))


def get_threat_sources(ip: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT source, score, raw, checked_at FROM threat_sources WHERE ip = ?", (ip,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_ips_needing_source_check(source: str, ttl: int, limit: int = 20) -> list[str]:
    cutoff = int(time.time()) - ttl
    with _connect() as conn:
        rows = conn.execute("""
            SELECT DISTINCT cl.ip
            FROM connections_log cl
            LEFT JOIN threat_sources ts ON cl.ip = ts.ip AND ts.source = ?
            WHERE ts.ip IS NULL OR ts.checked_at < ?
            ORDER BY cl.seen_at DESC
            LIMIT ?
        """, (source, cutoff, limit)).fetchall()
        return [r["ip"] for r in rows]


# ── alert_rules ────────────────────────────────────────────────────────────────

def get_alert_rules(enabled_only: bool = False) -> list[dict]:
    with _connect() as conn:
        q = "SELECT * FROM alert_rules"
        if enabled_only:
            q += " WHERE enabled = 1"
        q += " ORDER BY created_at"
        rows = conn.execute(q).fetchall()
        return [dict(r) for r in rows]


def get_alert_rule(rule_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        return dict(row) if row else None


def create_alert_rule(rule_type: str, condition: str = "{}", action: str = '{"type":"desktop"}') -> int:
    with _connect() as conn:
        cur = conn.execute("""
            INSERT INTO alert_rules (rule_type, condition, action, enabled, created_at)
            VALUES (?, ?, ?, 1, ?)
        """, (rule_type, condition, action, int(time.time())))
        return cur.lastrowid


def update_alert_rule(rule_id: int, enabled: int | None = None,
                      condition: str | None = None, action: str | None = None):
    parts: list[str] = []
    vals:  list      = []
    if enabled   is not None: parts.append("enabled = ?");   vals.append(int(enabled))
    if condition is not None: parts.append("condition = ?"); vals.append(condition)
    if action    is not None: parts.append("action = ?");    vals.append(action)
    if not parts:
        return
    vals.append(rule_id)
    with _connect() as conn:
        conn.execute(f"UPDATE alert_rules SET {', '.join(parts)} WHERE id = ?", vals)


def delete_alert_rule(rule_id: int):
    with _connect() as conn:
        conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))


# ── alert_events ───────────────────────────────────────────────────────────────

def create_alert_event(rule_id: int | None, rule_type: str, ip: str, msg: str) -> int:
    with _connect() as conn:
        cur = conn.execute("""
            INSERT INTO alert_events (rule_id, rule_type, ip, msg, read, sent, ts)
            VALUES (?, ?, ?, ?, 0, 0, ?)
        """, (rule_id, rule_type, ip, msg, int(time.time())))
        return cur.lastrowid


def get_alert_events(limit: int = 100) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alert_events ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_unread_alert_count() -> int:
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM alert_events WHERE read = 0"
        ).fetchone()
        return row["n"]


def pop_pending_alerts() -> list[dict]:
    """Return all unsent events and mark them sent=1 atomically."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alert_events WHERE sent = 0 ORDER BY ts ASC"
        ).fetchall()
        if rows:
            ids = [r["id"] for r in rows]
            conn.execute(
                f"UPDATE alert_events SET sent = 1 WHERE id IN ({','.join('?'*len(ids))})", ids
            )
        return [dict(r) for r in rows]


def mark_alerts_read(ids: list[int] | None = None):
    with _connect() as conn:
        if ids:
            conn.execute(
                f"UPDATE alert_events SET read = 1 WHERE id IN ({','.join('?'*len(ids))})", ids
            )
        else:
            conn.execute("UPDATE alert_events SET read = 1")


# ── timeline / historical connections ──────────────────────────────────────────

def get_timeline(window_hours: int = 24) -> list[dict]:
    now   = int(time.time())
    start = now - window_hours * 3600
    with _connect() as conn:
        rows = conn.execute("""
            SELECT (seen_at / 3600) * 3600 AS hour_ts,
                   COUNT(DISTINCT ip)       AS count
            FROM connections_log
            WHERE seen_at > ?
            GROUP BY hour_ts
            ORDER BY hour_ts ASC
        """, (start,)).fetchall()
    by_ts = {r["hour_ts"]: r["count"] for r in rows}
    cur   = (start // 3600) * 3600
    end   = (now   // 3600) * 3600
    result = []
    while cur <= end:
        result.append({"hour_ts": cur, "count": by_ts.get(cur, 0)})
        cur += 3600
    return result


# ── blocked_ips ────────────────────────────────────────────────────────────────

def add_blocked_ip(ip: str):
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at) VALUES (?, ?)",
            (ip, int(time.time()))
        )


def remove_blocked_ip(ip: str):
    with _connect() as conn:
        conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))


def is_blocked_ip(ip: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)
        ).fetchone()
        return row is not None


def get_blocked_ips() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ip, blocked_at FROM blocked_ips ORDER BY blocked_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


# ── timeline / historical connections ──────────────────────────────────────────

def get_connections_at(timestamp: int, window: int = 300) -> list[dict]:
    lo = timestamp - window
    hi = timestamp + window
    with _connect() as conn:
        rows = conn.execute("""
            SELECT cl.ip, cl.port, cl.local_port, cl.process,
                   MAX(cl.seen_at)  AS seen_at,
                   g.country, g.countryCode, g.city, g.lat, g.lon, g.org, g.isp,
                   t.abuse_score,   t.reports   AS threat_reports
            FROM connections_log cl
            LEFT JOIN geo_cache    g ON cl.ip = g.ip
            LEFT JOIN threat_cache t ON cl.ip = t.ip
            WHERE cl.seen_at BETWEEN ? AND ?
            GROUP BY cl.ip, cl.port
            ORDER BY seen_at DESC
        """, (lo, hi)).fetchall()
        return [dict(r) for r in rows]


# ── ip_notes ───────────────────────────────────────────────────────────────────

def get_note(ip: str) -> str:
    with _connect() as conn:
        row = conn.execute("SELECT note FROM ip_notes WHERE ip = ?", (ip,)).fetchone()
        return row["note"] if row else ""


def set_note(ip: str, note: str):
    with _connect() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO ip_notes (ip, note, updated_at)
            VALUES (?, ?, ?)
        """, (ip, note, int(time.time())))


# ── connection log retention ───────────────────────────────────────────────────

def prune_connection_log(days: int):
    """Delete connections_log rows older than `days` days. No-op if days <= 0."""
    if days <= 0:
        return
    cutoff = int(time.time()) - days * 86400
    with _connect() as conn:
        conn.execute("DELETE FROM connections_log WHERE seen_at < ?", (cutoff,))


# ── export helpers ─────────────────────────────────────────────────────────────

def get_all_threats(limit: int = 500) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM threat_cache ORDER BY checked_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_export_connections(limit: int = 5000) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("""
            SELECT ip, port, process, seen_at
            FROM connections_log
            ORDER BY seen_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_db_stats() -> dict:
    tables = [
        "geo_cache", "connections_log", "threat_cache", "traceroutes",
        "dns_cache", "reputation_cache", "threat_sources", "alert_rules",
        "alert_events", "blocked_ips", "ip_notes",
    ]
    row_counts: dict[str, int] = {}
    with _connect() as conn:
        for table in tables:
            try:
                row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
                row_counts[table] = row["n"]
            except Exception:
                row_counts[table] = 0
    db_size = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    return {"row_counts": row_counts, "db_size_bytes": db_size}
