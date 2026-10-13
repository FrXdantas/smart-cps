"""SQLite local em data/auth.db — usuários, API keys e histórico de logins.

Usa sqlite3 da stdlib (sem ORM). Esquema cria-se sob demanda na primeira chamada.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from ..core.config import PROJECT_ROOT

DB_PATH = PROJECT_ROOT / "data" / "auth.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    login           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK(role IN ('admin','user')),
    api_key_hash    TEXT,
    api_key_prefix  TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT
);

CREATE TABLE IF NOT EXISTS login_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    login       TEXT NOT NULL,
    at          TEXT NOT NULL DEFAULT (datetime('now')),
    ip          TEXT,
    user_agent  TEXT,
    method      TEXT NOT NULL CHECK(method IN ('password','api_key')),
    success     INTEGER NOT NULL CHECK(success IN (0,1)),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_login_history_at ON login_history(at DESC);
CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id, at DESC);
"""


def _ensure_parent() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def connect():
    """Conexão SQLite com row_factory por dicionário (Row) e foreign_keys=ON."""
    _ensure_parent()
    conn = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()


def init_schema() -> None:
    """Cria as tabelas se não existirem. Idempotente."""
    with connect() as conn:
        conn.executescript(_SCHEMA)


def user_count() -> int:
    init_schema()
    with connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"])
