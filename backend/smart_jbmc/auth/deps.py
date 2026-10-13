"""Dependências FastAPI para autenticação.

`current_user` aceita:
  - cookie de sessão (SPA via navegador), ou
  - cabeçalho ``Authorization: Bearer <api-key>`` (CLI / clientes programáticos).
"""

from typing import Any

from fastapi import Depends, HTTPException, Request, status

from . import service
from .session import COOKIE_NAME, decode


def _from_cookie(request: Request) -> dict[str, Any] | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    payload = decode(token)
    if not payload:
        return None
    user = service.get_user_by_id(int(payload["uid"]))
    return user


def _from_bearer(request: Request) -> dict[str, Any] | None:
    header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not header or not header.lower().startswith("bearer "):
        return None
    presented = header.split(None, 1)[1].strip()
    return service.authenticate_api_key(presented)


def current_user(request: Request) -> dict[str, Any]:
    user = _from_cookie(request) or _from_bearer(request)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="autenticação necessária",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def optional_user(request: Request) -> dict[str, Any] | None:
    """Como `current_user`, mas devolve None em vez de 401.

    Para rota que existe para os dois públicos e muda o QUE responde conforme
    quem pergunta — hoje só `/api/health`, que precisa continuar respondendo a
    monitoramento anônimo sem entregar versão e caminhos do servidor.
    """
    return _from_cookie(request) or _from_bearer(request)


def require_admin(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="apenas administradores",
        )
    return user
