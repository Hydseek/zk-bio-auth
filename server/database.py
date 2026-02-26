"""
database.py - SQLite Database Layer
Student 3: Architecture & Communication

Tables:
  users        - registered user accounts
  fragments    - encrypted Fragment B per user
  auth_logs    - authentication event log
"""

import sqlite3
import json
import logging
import os

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("ZK_DB_PATH", os.path.join(os.path.dirname(__file__), "zk_auth.db"))


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db():
    """Create tables if they don't already exist."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id     TEXT PRIMARY KEY,
                created_at  INTEGER NOT NULL,
                enrolled    INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS fragments (
                user_id     TEXT PRIMARY KEY REFERENCES users(user_id),
                fragment_b  TEXT NOT NULL,   -- JSON blob (encrypted)
                stored_at   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         TEXT,
                event_type      TEXT,         -- 'enroll' | 'auth_success' | 'auth_fail'
                cosine_distance REAL,
                timestamp       INTEGER,
                client_ip       TEXT
            );
        """)
    logger.info("Database initialised.")


# ─────────────────────────────────────────────
# USER OPERATIONS
# ─────────────────────────────────────────────
def upsert_user(user_id: str, timestamp: int):
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users(user_id, created_at, enrolled) VALUES(?,?,0)",
            (user_id, timestamp),
        )


def mark_enrolled(user_id: str):
    with get_connection() as conn:
        conn.execute("UPDATE users SET enrolled=1 WHERE user_id=?", (user_id,))


def user_exists(user_id: str) -> bool:
    with get_connection() as conn:
        row = conn.execute("SELECT 1 FROM users WHERE user_id=?", (user_id,)).fetchone()
    return row is not None


def get_all_users() -> list:
    with get_connection() as conn:
        rows = conn.execute("SELECT user_id, created_at, enrolled FROM users").fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# FRAGMENT OPERATIONS
# ─────────────────────────────────────────────
def store_fragment_b(user_id: str, fragment_b: dict, timestamp: int):
    payload = json.dumps(fragment_b)
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO fragments(user_id, fragment_b, stored_at)
               VALUES(?,?,?)
               ON CONFLICT(user_id) DO UPDATE SET fragment_b=excluded.fragment_b,
                                                   stored_at=excluded.stored_at""",
            (user_id, payload, timestamp),
        )
    logger.info(f"Fragment B stored for '{user_id}'")


def retrieve_fragment_b(user_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT fragment_b FROM fragments WHERE user_id=?", (user_id,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row["fragment_b"])


def delete_fragment_b(user_id: str):
    with get_connection() as conn:
        conn.execute("DELETE FROM fragments WHERE user_id=?", (user_id,))
    logger.info(f"Fragment B deleted for '{user_id}' (right to be forgotten)")


# ─────────────────────────────────────────────
# AUDIT LOG
# ─────────────────────────────────────────────
def log_event(user_id: str, event_type: str, timestamp: int,
              cosine_distance: float = None, client_ip: str = ""):
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO auth_logs(user_id, event_type, cosine_distance, timestamp, client_ip)
               VALUES(?,?,?,?,?)""",
            (user_id, event_type, cosine_distance, timestamp, client_ip),
        )


def get_auth_logs(user_id: str = None, limit: int = 50) -> list:
    query = "SELECT * FROM auth_logs"
    params: tuple = ()
    if user_id:
        query += " WHERE user_id=?"
        params = (user_id,)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params += (limit,)
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]
