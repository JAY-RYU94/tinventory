from __future__ import annotations

from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from swinventory.server.ai.config import AiConfigError, AiConfigStore, AiSettingsIn
from swinventory.server.ai.service import ReportService
from swinventory.server.policy import KernelPolicy, KernelPolicyStore, PolicyError


class PolicyIn(BaseModel):
    rules: list[dict[str, Any]]


def build_router(require_read: Callable[..., None], require_admin: Callable[..., None], policy_store: KernelPolicyStore,
                 ai_store: AiConfigStore, reports: ReportService) -> APIRouter:
    router = APIRouter(prefix="/v1/settings")
    admin = [Depends(require_admin)]

    @router.get("/kernel-policy", dependencies=[Depends(require_read)])
    def get_policy() -> dict:
        return {"rules": policy_store.load().to_dicts()}

    @router.put("/kernel-policy", dependencies=admin)
    def put_policy(body: PolicyIn) -> dict:
        """OS 계열별 최소 허용 커널(실행 중 커널 기준). 빈 목록이면 하한선 없음. 저장 즉시 모든 화면·리포트에 반영된다."""
        try:
            policy = KernelPolicy.from_dicts(body.rules)
        except PolicyError as exc:
            raise HTTPException(422, str(exc)) from None
        policy_store.save(policy)
        return {"rules": policy.to_dicts()}

    @router.get("/ai", dependencies=admin)
    def get_ai() -> dict:
        return ai_store.public()

    @router.put("/ai", dependencies=admin)
    def put_ai(body: AiSettingsIn) -> dict:
        try:
            return ai_store.update(body)
        except AiConfigError as exc:
            raise HTTPException(422, str(exc)) from None

    @router.post("/ai/test", dependencies=admin)
    def test_ai() -> dict:
        return reports.test_connection()

    return router
