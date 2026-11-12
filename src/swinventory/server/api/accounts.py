"""ID/PW 로그인, 관리자 계정·JWT 발급/회수. 비밀번호·토큰 원문은 조회 응답에 포함하지 않는다."""
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from swinventory.server.accounts import Accounts


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr


class NewUser(Input):
    username: str = Field(min_length=3, max_length=64)
    password: SecretStr
    role: Literal["read", "admin"] = "read"


class ChangeUser(Input):
    role: Literal["read", "admin"] | None = None
    active: bool | None = None
    password: SecretStr | None = None


class NewToken(Input):
    name: str = Field(min_length=1, max_length=100)
    role: Literal["ingest", "read", "admin"] = "read"
    user_id: str | None = Field(None, max_length=32)
    expires_hours: int = Field(24, ge=1, le=720)


class Password(Input):
    current_password: SecretStr
    new_password: SecretStr


def bearer(authorization: str | None) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def build_router(accounts: Accounts, require_read, require_admin) -> APIRouter:
    router = APIRouter(prefix="/v1")

    @router.post("/auth/login")
    def login(body: Login, request: Request, response: Response):
        response.headers["Cache-Control"] = "no-store"
        password = body.password.get_secret_value()
        if not 1 <= len(password) <= 128 or any(ord(c) < 32 for c in body.username):
            raise HTTPException(401, "ID 또는 비밀번호가 올바르지 않습니다.")
        return accounts.login(body.username, password, request.client.host if request.client else "unknown")

    @router.get("/auth/me", dependencies=[Depends(require_read)])
    def me(authorization: str | None = Header(None)):
        token = bearer(authorization)
        p = accounts.principal(token)
        if p:
            return {"username": p["username"], "kind": p["kind"]}
        return {"username": None, "kind": "legacy"}

    @router.post("/auth/logout", dependencies=[Depends(require_read)])
    def logout(authorization: str | None = Header(None)):
        with accounts.repo.auth_lock():
            p = accounts.principal(bearer(authorization))
            if p:
                accounts.repo.revoke_token(p["id"])
        return {"ok": True}

    @router.post("/auth/password", dependencies=[Depends(require_read)])
    def password(body: Password, authorization: str | None = Header(None)):
        accounts.change_password(bearer(authorization), body.current_password.get_secret_value(), body.new_password.get_secret_value())
        return {"ok": True}

    @router.get("/users", dependencies=[Depends(require_admin)])
    def users():
        return accounts.repo.list_users()

    @router.post("/users", status_code=201, dependencies=[Depends(require_admin)])
    def new_user(body: NewUser, authorization: str | None = Header(None)):
        with accounts.admin(bearer(authorization)):
            return accounts.create_user(body.username, body.password.get_secret_value(), body.role)

    @router.patch("/users/{user_id}", dependencies=[Depends(require_admin)])
    def change_user(user_id: str, body: ChangeUser, authorization: str | None = Header(None)):
        values = body.model_dump(exclude_unset=True)
        if any(v is None for v in values.values()):
            raise HTTPException(422, "값을 비워서 변경할 수 없습니다.")
        if body.password is not None:
            values["password"] = body.password.get_secret_value()
        with accounts.admin(bearer(authorization)):
            return accounts.update_user(user_id, values)

    @router.get("/tokens", dependencies=[Depends(require_admin)])
    def tokens():
        users = {u["id"]: u for u in accounts.repo.list_users()}
        now = int(accounts.clock().timestamp())
        rows = accounts.repo.list_tokens()
        for row in rows:
            user = users.get(row["user_id"])
            row["status"] = ("회수됨" if row["revoked"] else "만료" if row["expires_at"] <= now
                else "계정 변경으로 무효" if row["user_id"] and (not user or not user["active"] or user["generation"] != row["generation"])
                else "유효")
        return rows

    @router.post("/tokens", status_code=201, dependencies=[Depends(require_admin)])
    def new_token(body: NewToken, response: Response, authorization: str | None = Header(None)):
        if not body.name.strip() or any(ord(c) < 32 for c in body.name):
            raise HTTPException(422, "토큰 이름에 제어문자를 넣을 수 없습니다.")
        response.headers["Cache-Control"] = "no-store"
        with accounts.admin(bearer(authorization)):
            return accounts.issue_api(body.name.strip(), body.role, body.user_id, body.expires_hours)

    @router.delete("/tokens/{token_id}", dependencies=[Depends(require_admin)])
    def revoke(token_id: str, authorization: str | None = Header(None)):
        with accounts.admin(bearer(authorization)):
            if not accounts.repo.revoke_token(token_id):
                raise HTTPException(404, "토큰을 찾을 수 없습니다.")
        return {"ok": True}

    return router
