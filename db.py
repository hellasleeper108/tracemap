"""
db.py — SQLite schema and all query functions.
Database lives at ~/.local/share/tracemap/tracemap.db
"""

import sqlite3
import time
from pathlib import Path

DB_PATH = Path.home() / ".local" / "share" / "tracemap" / "tracemap.db"


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
