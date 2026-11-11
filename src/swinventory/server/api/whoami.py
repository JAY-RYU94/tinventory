"""호출자 역할 조회. 화면이 관리자 전용 버튼(태그 편집·삭제·설정)을 보일지 정하는 데만 쓴다.

여기서 알려 주는 역할은 안내일 뿐이다 — 쓰기 라우트는 각자 require_admin 으로 따로 막는다(화면을 속여도 서버가 거부한다).
"""
from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Depends


def build_router(caller_role: Callable[..., str]) -> APIRouter:
    router = APIRouter(prefix="/v1")

    @router.get("/whoami")
    def whoami(role: str = Depends(caller_role)) -> dict:
        """{"role": "admin" | "read"}. 토큰이 없거나 틀리면 401, 수집 전용 토큰이면 403."""
        return {"role": role}

    return router
