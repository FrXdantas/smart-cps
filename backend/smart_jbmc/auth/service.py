"""Lógica de autenticação: bcrypt, criação/listagem de usuários, API keys."""

import secrets
from typing import Any

import bcrypt

from . import db


# -------- senha --------

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


# -------- usuários --------

def create_user(login: str, password: str, role: str = "user") -> dict[str, Any]:
    """Cria usuário; falha (ValueError) se login duplicado ou role inválido."""
    if role not in ("admin", "user"):
        raise ValueError("role deve ser 'admin' ou 'user'")
    login = login.strip().lower()
    if not login:
        raise ValueError("login não pode ser vazio")
    if not password or len(password) < 4:
        raise ValueError("senha deve ter pelo menos 4 caracteres")

    db.init_schema()
    with db.connect() as conn:
        existing = conn.execute("SELECT 1 FROM users WHERE login = ?", (login,)).fetchone()
        if existing:
            raise ValueError(f"login já existe: {login}")
        cur = conn.execute(
            "INSERT INTO users (login, password_hash, role) VALUES (?, ?, ?)",
            (login, hash_password(password), role),
        )
        return get_user_by_id(cur.lastrowid)  # type: ignore[arg-type]


def get_user_by_login(login: str) -> dict[str, Any] | None:
    db.init_schema()
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE login = ?", (login.strip().lower(),)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(uid: int) -> dict[str, Any] | None:
    db.init_schema()
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    db.init_schema()
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, login, role, api_key_prefix, created_at, last_login "
            "FROM users ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_user(uid: int) -> bool:
    db.init_schema()
    with db.connect() as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (uid,))
        return cur.rowcount > 0


def update_last_login(uid: int) -> None:
    with db.connect() as conn:
        conn.execute(
            "UPDATE users SET last_login = datetime('now') WHERE id = ?", (uid,)
        )


# -------- API keys --------

API_KEY_PREFIX = "sjk_"  # smart-jbmc key


def issue_api_key(uid: int) -> str:
    """Gera nova API key, grava o hash e devolve o segredo em claro (uma única vez)."""
    secret = API_KEY_PREFIX + secrets.token_urlsafe(32)
    with db.connect() as conn:
        cur = conn.execute(
            "UPDATE users SET api_key_hash = ?, api_key_prefix = ? WHERE id = ?",
            (hash_password(secret), secret[: len(API_KEY_PREFIX) + 8], uid),
        )
        if cur.rowcount == 0:
            raise ValueError(f"usuário {uid} não encontrado")
    return secret


def revoke_api_key(uid: int) -> None:
    with db.connect() as conn:
        conn.execute(
            "UPDATE users SET api_key_hash = NULL, api_key_prefix = NULL WHERE id = ?",
            (uid,),
        )


def authenticate_api_key(presented: str) -> dict[str, Any] | None:
    """Compara a key apresentada contra TODAS as keys ativas (varredura linear).
    Aceitável porque a base de usuários é pequena (intranet)."""
    if not presented or not presented.startswith(API_KEY_PREFIX):
        return None
    db.init_schema()
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM users WHERE api_key_hash IS NOT NULL"
        ).fetchall()
        for row in rows:
            if verify_password(presented, row["api_key_hash"]):
                return dict(row)
    return None


# -------- autenticação --------

def authenticate(login: str, password: str) -> dict[str, Any] | None:
    """Retorna o usuário se as credenciais conferem, senão None."""
    user = get_user_by_login(login)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


# -------- histórico de login --------

def record_login(
    login: str,
    success: bool,
    method: str,
    user_id: int | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    db.init_schema()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO login_history (user_id, login, ip, user_agent, method, success) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, login.strip().lower(), ip, user_agent, method, 1 if success else 0),
        )


def list_login_history(limit: int = 200, user_id: int | None = None) -> list[dict[str, Any]]:
    db.init_schema()
    with db.connect() as conn:
        if user_id is None:
            rows = conn.execute(
                "SELECT h.*, u.login AS user_login FROM login_history h "
                "LEFT JOIN users u ON u.id = h.user_id "
                "ORDER BY h.at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT h.*, u.login AS user_login FROM login_history h "
                "LEFT JOIN users u ON u.id = h.user_id "
                "WHERE h.user_id = ? ORDER BY h.at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]
