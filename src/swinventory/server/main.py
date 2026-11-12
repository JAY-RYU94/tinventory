"""uvicorn 진입점: uvicorn swinventory.server.main:create_app_from_env --factory

환경변수: SWINV_DB_URL(기본 sqlite:///swinventory.db), SWINV_INGEST_TOKENS / SWINV_READ_TOKENS /
SWINV_ADMIN_TOKENS(쉼표 구분), SWINV_STALE_AFTER_HOURS(기본 48), SWINV_MAX_BODY_BYTES(기본 32MiB),
SWINV_SECRET_KEY / SWINV_SECRET_FILE(설정 암호화 키), SWINV_AI_ENDPOINT_ALLOWLIST(AI 엔드포인트 호스트 허용 목록), OPENAI_API_KEY(AI 키 폴백),
SWINV_AGENT_DIR(배포할 에이전트·설치 스크립트 디렉터리), SWINV_PUBLIC_URL(프록시 뒤에서 설치 명령에 넣을 서버 주소),
SWINV_ADMIN_USERNAME / SWINV_ADMIN_PASSWORD(첫 관리자 생성), SWINV_JWT_SECRET(선택 서명 키)
"""
from __future__ import annotations

import os
from typing import Mapping

from fastapi import FastAPI

from swinventory.server.app import ApiSettings, create_app
from swinventory.server.repo.sql import SqlInventoryRepository


def _tokens(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    return tuple(t.strip() for t in env.get(name, "").split(",") if t.strip())


def repo_from_env(env: Mapping[str, str] = os.environ) -> SqlInventoryRepository:
    return SqlInventoryRepository.from_url(env.get("SWINV_DB_URL", "sqlite:///swinventory.db"))


def create_app_from_env(env: Mapping[str, str] = os.environ) -> FastAPI:
    settings = ApiSettings(
        ingest_tokens=_tokens(env, "SWINV_INGEST_TOKENS"),
        read_tokens=_tokens(env, "SWINV_READ_TOKENS"),
        admin_tokens=_tokens(env, "SWINV_ADMIN_TOKENS"),
        stale_after_hours=float(env.get("SWINV_STALE_AFTER_HOURS", "48")),
        max_body_bytes=int(env.get("SWINV_MAX_BODY_BYTES", str(32 * 1024 * 1024))),
        ai_endpoint_allowlist=_tokens(env, "SWINV_AI_ENDPOINT_ALLOWLIST"),
        public_url=env.get("SWINV_PUBLIC_URL") or None,
    )
    repo = repo_from_env(env)
    if not (settings.ingest_tokens or settings.read_tokens or settings.admin_tokens or env.get("SWINV_ADMIN_USERNAME")
            or any(u["active"] and u["role"] == "admin" for u in repo.list_users())):
        raise SystemExit("토큰 또는 관리자 계정이 필요합니다(SWINV_*_TOKENS 또는 SWINV_ADMIN_USERNAME/PASSWORD). 인증 없이 기동하지 않는다.")
    return create_app(repo, settings, env=env)
