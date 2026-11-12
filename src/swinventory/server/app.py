from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Mapping

import logging
import os
import threading

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse

from swinventory.server.agents import AgentCatalog
from swinventory.server.ai.config import AiConfigStore
from swinventory.server.ai.llm import LlmFactory, default_llm_factory
from swinventory.server.ai.service import ReportService
from swinventory.server.api import accounts as accounts_api
from swinventory.server.accounts import Accounts
from swinventory.server.api import assets as assets_api
from swinventory.server.api import containers as containers_api
from swinventory.server.api import enroll as enroll_api
from swinventory.server.api import ingest as ingest_api
from swinventory.server.api import network as network_api
from swinventory.server.api import read as read_api
from swinventory.server.api import reports as reports_api
from swinventory.server.api import settings as settings_api
from swinventory.server.api import whoami as whoami_api
from swinventory.server.assets import AssetService
from swinventory.server.auth import ApiSettings, Authenticator
from swinventory.server.middleware import BodySizeLimitMiddleware, RejectNulMiddleware, SecurityHeadersMiddleware
from swinventory.server.policy import KernelPolicyStore
from swinventory.server.repo.base import InventoryRepository
from swinventory.server.secrets import SecretBox
from swinventory.server.services.ingest import IngestService

__all__ = ["ApiSettings", "create_app"]

log = logging.getLogger("swinventory.server")
WEB_DIR = Path(__file__).parent / "web"


class InventoryApp(FastAPI):
    """본문 상한 미들웨어를 ServerErrorMiddleware 바깥에 둔다(그 안쪽에서는 413 이 500 으로 바뀐다)."""

    max_body_bytes: int = 32 * 1024 * 1024

    def build_middleware_stack(self):  # noqa: ANN201
        return RejectNulMiddleware(BodySizeLimitMiddleware(super().build_middleware_stack(), self.max_body_bytes))


def _lazy_secret_box(env: Mapping[str, str]) -> Callable[[], SecretBox]:
    """비밀 키(파일)는 처음 필요할 때 만든다 — AI 기능을 쓰지 않는 배포는 키 파일을 만들지 않는다."""
    lock, box = threading.Lock(), []

    def get() -> SecretBox:
        with lock:
            if not box:
                box.append(SecretBox.from_env(env, default_key_file=str(Path.home() / ".swinventory" / "secret.key")))
            return box[0]

    return get


def create_app(repo: InventoryRepository, settings: ApiSettings,
               clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc), *,
               secret_box: SecretBox | None = None, llm_factory: LlmFactory = default_llm_factory,
               env: Mapping[str, str] | None = None, agent_dir: Path | str | None = None) -> FastAPI:
    """모든 의존성(저장소·설정·시계·비밀 키·LLM)을 주입받는 앱 팩토리."""
    env = os.environ if env is None else env
    box = (lambda: secret_box) if secret_box is not None else _lazy_secret_box(env)
    policy_store = KernelPolicyStore(repo, clock)
    ai_store = AiConfigStore(repo, box, env, settings.ai_endpoint_allowlist, clock)
    reports = ReportService(repo, ai_store, policy_store.load, llm_factory, clock, settings.stale_after_hours)
    accounts = Accounts(repo, clock, box, env)
    auth = Authenticator(settings, accounts)
    accounts.legacy_roles = auth.static_roles_of
    app = InventoryApp(title="swinventory", version="0.1.0")
    app.max_body_bytes = settings.max_body_bytes
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic 기본 오류의 input 에 로그인 비밀번호·비밀 필드가 반사되지 않게 한다.
        if request.url.path.startswith(("/v1/auth/", "/v1/users", "/v1/tokens")):
            return JSONResponse(status_code=422, content={"detail": "입력값의 형식과 길이를 확인하세요."})
        return await request_validation_exception_handler(request, exc)


    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict:
        """로드밸런서/컨테이너 헬스체크(무인증). 내부 오류 내용은 응답에 싣지 않는다."""
        try:
            repo.ping()
        except Exception:  # noqa: BLE001
            log.exception("healthz: DB 연결 실패")
            raise HTTPException(503, "unhealthy") from None
        return {"status": "ok"}

    app.include_router(ingest_api.build_router(IngestService(repo, clock), auth.require("ingest")))
    app.include_router(whoami_api.build_router(auth.caller_role()))
    app.include_router(accounts_api.build_router(accounts, auth.require("read"), auth.require("admin")))
    asset_service = AssetService(repo)
    app.include_router(read_api.build_router(
        repo, auth.require("read"), auth.require("admin"), clock, settings.stale_after_hours, policy_store.load, asset_service))
    app.include_router(containers_api.build_router(repo, asset_service, auth.require("read"), auth.require("admin"), clock))
    app.include_router(assets_api.build_router(repo, asset_service, auth.require("read"), auth.require("admin"), clock))
    catalog = AgentCatalog(agent_dir if agent_dir is not None else env.get("SWINV_AGENT_DIR"))
    app.include_router(enroll_api.build_router(catalog, settings.ingest_tokens, settings.public_url, auth.require("read"), auth.require("admin")))
    app.include_router(network_api.build_router(repo, auth.require("read"), asset_service))
    app.include_router(settings_api.build_router(auth.require("read"), auth.require("admin"), policy_store, ai_store, reports))
    app.include_router(reports_api.build_router(repo, auth.require("read"), auth.require("admin"), reports))
    # 화면(정적 파일). API 라우트 뒤에 마운트해야 /v1·/healthz·/docs 가 가려지지 않는다.
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
    return app
