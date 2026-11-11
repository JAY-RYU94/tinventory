from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Callable

from fastapi import Header, HTTPException, status


@dataclass(frozen=True)
class ApiSettings:
    """역할별 Bearer 토큰. ingest(수집 전용) / read(조회) / admin(조회 + 태그 수정)."""

    ingest_tokens: tuple[str, ...] = ()
    read_tokens: tuple[str, ...] = ()
    admin_tokens: tuple[str, ...] = ()
    stale_after_hours: float = 48.0
    max_body_bytes: int = 32 * 1024 * 1024  # 패키지 10만 건 ≈ 15MB 를 수용
    public_url: str | None = None  # 프록시 뒤에서 설치 명령에 넣을 서버 주소(SWINV_PUBLIC_URL)
    ai_endpoint_allowlist: tuple[str, ...] = ()  # 비어 있으면 제한 없음(링크 로컬·메타데이터 주소는 항상 거부)

    def __post_init__(self) -> None:
        for group in (self.ingest_tokens, self.read_tokens, self.admin_tokens):
            if any(not t for t in group):
                raise ValueError("빈 토큰은 허용하지 않는다")


class Authenticator:
    def __init__(self, settings: ApiSettings):
        self._groups = (("ingest", settings.ingest_tokens), ("read", settings.read_tokens),
                        ("admin", settings.admin_tokens))

    def roles_of(self, token: str) -> set[str]:
        """모든 후보와 compare_digest 로 비교한다(일치 시 조기 종료하지 않음)."""
        roles: set[str] = set()
        probe = token.encode()
        for role, tokens in self._groups:
            for t in tokens:
                if hmac.compare_digest(t.encode(), probe):
                    roles.add(role)
        if "admin" in roles:
            roles.add("read")
        return roles

    def _caller_roles(self, authorization: str | None) -> set[str]:
        """Authorization 헤더의 토큰이 가진 역할. 헤더가 없거나 Bearer 형식이 아니거나 모르는 토큰이면 401(토큰은 에러에 싣지 않는다)."""
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token",
                                headers={"WWW-Authenticate": "Bearer"})
        roles = self.roles_of(token.strip())
        if not roles:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token",
                                headers={"WWW-Authenticate": "Bearer"})
        return roles

    def require(self, role: str) -> Callable[..., None]:
        def dependency(authorization: str | None = Header(default=None)) -> None:
            if role not in self._caller_roles(authorization):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")

        return dependency

    def caller_role(self) -> Callable[..., str]:
        """조회 권한 이상인 호출자의 가장 높은 역할("admin" 또는 "read")을 돌려주는 의존성. 수집 전용 토큰은 403.
        화면이 관리자 전용 버튼을 보일지 정하는 안내일 뿐이다 — 실제 차단은 각 라우트의 require 가 따로 한다."""
        def dependency(authorization: str | None = Header(default=None)) -> str:
            roles = self._caller_roles(authorization)
            if "read" not in roles:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
            return "admin" if "admin" in roles else "read"

        return dependency
