"""Cookie de sessão assinado (HMAC-SHA256, stdlib).

Formato: base64url(payload_json) + "." + base64url(hmac).
Sem deps externas — apenas hashlib, hmac, secrets, base64.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from ..core.config import PROJECT_ROOT, load_env

COOKIE_NAME = "smart_jbmc_session"
DEFAULT_TTL = 12 * 3600  # 12 horas
_SECRET_PATH = PROJECT_ROOT / "data" / ".session_secret"


def _load_or_create_secret() -> bytes:
    """Lê SESSION_SECRET do .env; se ausente, gera e grava em data/.session_secret (chmod 600)."""
    load_env()
    raw = os.environ.get("SESSION_SECRET")
    if raw:
        return raw.encode("utf-8")
    if _SECRET_PATH.is_file():
        return _SECRET_PATH.read_bytes()
    _SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    new = secrets.token_bytes(32)
    _SECRET_PATH.write_bytes(new)
    try:
        _SECRET_PATH.chmod(0o600)
    except OSError:
        pass
    return new


def _b64encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def encode(user_id: int, login: str, role: str, ttl: int = DEFAULT_TTL) -> str:
    payload = {
        "uid": user_id,
        "login": login,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
    }
    secret = _load_or_create_secret()
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64encode(sig)}"


def decode(token: str) -> dict | None:
    """Decodifica e valida o token; retorna o payload ou None."""
    if not token or "." not in token:
        return None
    try:
        body, sig = token.split(".", 1)
        secret = _load_or_create_secret()
        expected = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64decode(sig)):
            return None
        payload = json.loads(_b64decode(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except (ValueError, KeyError, json.JSONDecodeError):
        return None


def is_cookie_secure() -> bool:
    load_env()
    return os.environ.get("AUTH_COOKIE_SECURE", "0") == "1"
