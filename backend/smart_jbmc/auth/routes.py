"""Rotas /api/auth/* — login, logout, gestão de usuários e histórico."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import service
from .deps import current_user, require_admin
from .session import COOKIE_NAME, DEFAULT_TTL, encode, is_cookie_secure

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------- schemas ----------

class LoginRequest(BaseModel):
    login: str
    password: str


class UserOut(BaseModel):
    id: int
    login: str
    role: str
    api_key_prefix: str | None = None
    created_at: str | None = None
    last_login: str | None = None


class CreateUserRequest(BaseModel):
    login: str
    password: str = Field(..., min_length=4)
    role: str = "user"


class ApiKeyOut(BaseModel):
    api_key: str
    prefix: str


# ---------- helpers ----------

def _user_out(u: dict[str, Any]) -> UserOut:
    return UserOut(
        id=u["id"],
        login=u["login"],
        role=u["role"],
        api_key_prefix=u.get("api_key_prefix"),
        created_at=u.get("created_at"),
        last_login=u.get("last_login"),
    )


def _client_meta(request: Request) -> tuple[str | None, str | None]:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua


# ---------- endpoints ----------

@router.post("/login")
def login(req: LoginRequest, request: Request, response: Response):
    ip, ua = _client_meta(request)
    user = service.authenticate(req.login, req.password)
    if not user:
        service.record_login(req.login, success=False, method="password", ip=ip, user_agent=ua)
        raise HTTPException(status_code=401, detail="credenciais inválidas")

    service.update_last_login(user["id"])
    service.record_login(
        req.login, success=True, method="password",
        user_id=user["id"], ip=ip, user_agent=ua,
    )
    token = encode(user["id"], user["login"], user["role"])
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=DEFAULT_TTL,
        httponly=True,
        samesite="lax",
        secure=is_cookie_secure(),
        path="/",
    )
    return {"ok": True, "user": _user_out(user).model_dump()}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: dict[str, Any] = Depends(current_user)) -> UserOut:
    return _user_out(user)


# ---- gestão de usuários (admin) ----

@router.get("/users", response_model=list[UserOut])
def list_users(_: dict = Depends(require_admin)) -> list[UserOut]:
    return [_user_out(u) for u in service.list_users()]


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(req: CreateUserRequest, _: dict = Depends(require_admin)) -> UserOut:
    try:
        user = service.create_user(req.login, req.password, req.role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _user_out(user)


@router.delete("/users/{uid}")
def delete_user(uid: int, admin: dict = Depends(require_admin)):
    if uid == admin["id"]:
        raise HTTPException(status_code=400, detail="você não pode excluir a si mesmo")
    if not service.delete_user(uid):
        raise HTTPException(status_code=404, detail="usuário não encontrado")
    return {"ok": True}


@router.post("/users/{uid}/api-key", response_model=ApiKeyOut)
def rotate_api_key(uid: int, _: dict = Depends(require_admin)) -> ApiKeyOut:
    try:
        key = service.issue_api_key(uid)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return ApiKeyOut(api_key=key, prefix=key[:12])


@router.delete("/users/{uid}/api-key")
def revoke_api_key(uid: int, _: dict = Depends(require_admin)):
    service.revoke_api_key(uid)
    return {"ok": True}


# ---- histórico de login ----

@router.get("/history")
def login_history(
    limit: int = 200,
    user_id: int | None = None,
    _: dict = Depends(require_admin),
):
    return service.list_login_history(limit=limit, user_id=user_id)
