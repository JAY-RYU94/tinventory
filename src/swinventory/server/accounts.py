"""사용자·비밀번호·회수 가능한 JWT. 계정 변경과 발급의 경쟁은 저장소 auth_lock 으로 직렬화한다."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from contextlib import contextmanager
from typing import Callable, Mapping

import jwt
from fastapi import HTTPException

from swinventory.server.repo.base import InventoryRepository
from swinventory.server.secrets import SecretBox
from swinventory.server.timeutil import normalize_ts

ITERATIONS = 600_000
ISSUER, AUDIENCE = "swinventory", "swinventory-api"
_USER = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}\Z")


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
    return f"pbkdf2_sha256${ITERATIONS}${salt}${digest}"


def password_matches(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt, expected = encoded.split("$")
        if scheme != "pbkdf2_sha256" or int(rounds) != ITERATIONS:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def check_password(password: str) -> None:
    if not 12 <= len(password) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise HTTPException(422, "비밀번호는 제어문자 없이 12~128자로 입력하세요.")


def username_key(username: str) -> str:
    value = username.strip().lower()
    if not _USER.fullmatch(value):
        raise HTTPException(422, "ID는 영문 소문자·숫자·점·밑줄·하이픈으로 3~64자입니다.")
    return value


def public_user(user: dict) -> dict:
    return {k: user[k] for k in ("id", "username", "role", "active", "created_at")}


class Accounts:
    def __init__(self, repo: InventoryRepository, clock: Callable, box: Callable[[], SecretBox], env: Mapping[str, str]):
        self.repo, self.clock, self.box = repo, clock, box
        key = env.get("SWINV_JWT_SECRET", "")
        if key and len(key.encode()) < 32:
            raise ValueError("SWINV_JWT_SECRET 는 32바이트 이상이어야 합니다.")
        self._key = key.encode() if key else None
        self.legacy_roles: Callable[[str], set[str]] = lambda _: set()
        # 존재하지 않는 ID 도 같은 KDF 를 수행해 ID 존재 여부의 시간 차이를 줄인다.
        self._dummy = f"pbkdf2_sha256${ITERATIONS}$" + "00" * 16 + "$" + "00" * 32
        username, password = env.get("SWINV_ADMIN_USERNAME"), env.get("SWINV_ADMIN_PASSWORD")
        if bool(username) != bool(password):
            raise ValueError("SWINV_ADMIN_USERNAME 과 SWINV_ADMIN_PASSWORD 는 함께 설정하세요.")
        if username and password:
            with repo.auth_lock():
                if not repo.list_users():
                    self.create_user(username, password, "admin")

    def signing_key(self) -> bytes:
        return self._key if self._key is not None else self.box().derive_key(b"swinventory.jwt.hs256.v1")

    def create_user(self, username: str, password: str, role: str) -> dict:
        username = username_key(username)
        check_password(password)
        if self.repo.get_user(username, by_name=True):
            raise HTTPException(409, "이미 사용 중인 ID입니다.")
        user = dict(id=secrets.token_hex(16), username=username, password_hash=password_hash(password), role=role,
                    active=True, generation=1, failed_logins=0, locked_until=0, created_at=normalize_ts(self.clock()))
        self.repo.create_user(user)
        return public_user(user)

    def update_user(self, user_id: str, changes: dict) -> dict:
        user = self.repo.get_user(user_id)
        if not user:
            raise HTTPException(404, "사용자를 찾을 수 없습니다.")
        if not changes:
            raise HTTPException(422, "변경할 값을 입력하세요.")
        if user["active"] and user["role"] == "admin" and (changes.get("active") is False or changes.get("role", "admin") != "admin"):
            if sum(u["active"] and u["role"] == "admin" for u in self.repo.list_users()) <= 1:
                raise HTTPException(409, "마지막 활성 관리자는 권한을 내리거나 비활성화할 수 없습니다.")
        if "password" in changes:
            check_password(changes["password"])
            changes["password_hash"] = password_hash(changes.pop("password"))
        changes.update(generation=user["generation"] + 1, failed_logins=0, locked_until=0)
        self.repo.update_user(user_id, changes)
        return public_user({**user, **changes})

    def _issue(self, user: dict | None, role: str, kind: str, name: str, hours: int) -> dict:
        now = int(self.clock().timestamp())
        tid = secrets.token_hex(16)
        claims = dict(iss=ISSUER, aud=AUDIENCE, sub=user["id"] if user else "service", jti=tid,
                      iat=now, nbf=now, exp=now + hours * 3600, scope=role, kind=kind)
        token = jwt.encode(claims, self.signing_key(), algorithm="HS256")
        self.repo.add_token(dict(id=tid, token_hash=hashlib.sha256(token.encode()).hexdigest(), user_id=user["id"] if user else None,
            generation=user["generation"] if user else 0, name=name, role=role, kind=kind,
            created_at=normalize_ts(self.clock()), expires_at=claims["exp"], revoked=False))
        return dict(id=tid, access_token=token, token_type="bearer", expires_in=hours * 3600, expires_at=claims["exp"], role=role)

    def login(self, username: str, password: str, ip: str) -> dict:
        result, error = None, None
        with self.repo.auth_lock():
            now = int(self.clock().timestamp())
            attempts = self.repo.login_attempt(hashlib.sha256(ip.encode()).hexdigest(), now)
            user = self.repo.get_user(username.strip().lower(), by_name=True)
            if attempts > 30 or (user and user["locked_until"] > now):
                error = HTTPException(429, "로그인 시도가 많습니다. 15분 후 다시 시도하세요.", headers={"Retry-After": "900"})
            else:
                correct = password_matches(password, user["password_hash"] if user else self._dummy)
                if not user or not correct or not user["active"]:
                    if user:
                        failed = user["failed_logins"] + 1
                        self.repo.update_user(user["id"], dict(failed_logins=failed, locked_until=now + 900 if failed >= 5 else 0))
                    error = HTTPException(401, "ID 또는 비밀번호가 올바르지 않습니다.")
                else:
                    self.repo.update_user(user["id"], dict(failed_logins=0, locked_until=0))
                    result = self._issue(user, user["role"], "session", "웹 로그인", 8)
        # 실패 횟수의 트랜잭션을 먼저 커밋해야 예외가 롤백시키지 않는다.
        if error:
            raise error
        return result

    def principal(self, token: str) -> dict | None:
        if len(token) > 8192 or token.count(".") != 2:
            return None
        try:
            claims = jwt.decode(token, self.signing_key(), algorithms=["HS256"], issuer=ISSUER, audience=AUDIENCE,
                options={"require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"], "verify_exp": False, "verify_iat": False, "verify_nbf": False})
            now = int(self.clock().timestamp())
            if any(type(claims[k]) is not int for k in ("exp", "iat", "nbf")) or claims["exp"] <= now or claims["nbf"] > now or claims["iat"] > now:
                return None
            row = self.repo.find_token(hashlib.sha256(token.encode()).hexdigest())
            if not row or row["revoked"] or row["expires_at"] <= now or row["id"] != claims["jti"]:
                return None
            if (claims.get("scope"), claims.get("kind"), claims["sub"]) != (row["role"], row["kind"], row["user_id"] or "service"):
                return None
            if row["user_id"] and (not row["user_active"] or row["generation"] != row["user_generation"] or (row["role"] == "admin" and row["user_role"] != "admin")):
                return None
            return row
        except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
            return None

    def roles(self, token: str) -> set[str]:
        principal = self.principal(token)
        if not principal:
            return set()
        return {"admin", "read"} if principal["role"] == "admin" else {principal["role"]}

    @contextmanager
    def admin(self, token: str):
        with self.repo.auth_lock():
            # 의존성 통과 후 잠금을 기다리는 동안 회수·권한 변경됐을 수 있다.
            if "admin" not in (self.legacy_roles(token) | self.roles(token)):
                raise HTTPException(403, "관리자 권한이 필요합니다.")
            yield

    def issue_api(self, name: str, role: str, user_id: str | None, hours: int) -> dict:
        user = self.repo.get_user(user_id) if user_id else None
        if role != "ingest" and (not user or not user["active"] or (role == "admin" and user["role"] != "admin")):
            raise HTTPException(422, "활성 사용자를 선택하고 사용자 권한 범위 안에서 발급하세요.")
        if role == "ingest" and user_id:
            raise HTTPException(422, "수집 토큰은 사용자 없이 발급하세요.")
        return self._issue(user, role, "api", name, hours)

    def change_password(self, token: str, current: str, new: str) -> None:
        check_password(new)
        error = None
        with self.repo.auth_lock():
            principal = self.principal(token)
            if not principal or principal["kind"] != "session" or not principal["user_id"]:
                raise HTTPException(403, "ID·비밀번호로 로그인한 사용자만 변경할 수 있습니다.")
            user = self.repo.get_user(principal["user_id"])
            now = int(self.clock().timestamp())
            if user["locked_until"] > now:
                error = HTTPException(429, "로그인 시도가 많습니다. 15분 후 다시 시도하세요.")
            elif len(current) > 128 or not password_matches(current, user["password_hash"]):
                failed = user["failed_logins"] + 1
                self.repo.update_user(user["id"], dict(failed_logins=failed, locked_until=now + 900 if failed >= 5 else 0))
                error = HTTPException(400, "현재 비밀번호가 올바르지 않습니다.")
            else:
                self.update_user(user["id"], {"password": new})
        if error:
            raise error
