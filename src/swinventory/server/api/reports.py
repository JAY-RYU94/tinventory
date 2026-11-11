from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Depends, HTTPException

from swinventory.server.ai.config import AiNotConfigured
from swinventory.server.ai.llm import LlmError
from swinventory.server.ai.service import ReportBusy, ReportService
from swinventory.server.repo.base import InventoryRepository


def build_router(repo: InventoryRepository, require_read: Callable[..., None], require_admin: Callable[..., None],
                 service: ReportService) -> APIRouter:
    router = APIRouter(prefix="/v1/reports")
    read = [Depends(require_read)]

    @router.get("/facts", dependencies=read)
    def facts() -> dict:
        """AI 에 넘기는 집계 그대로. AI 설정 없이도 볼 수 있다(리포트 근거 확인용)."""
        return service.facts()

    @router.post("", dependencies=[Depends(require_admin)])
    def generate() -> dict:
        """집계(facts)를 LLM 에 보내 종합 분석 리포트를 만들고 저장한다. 동기 호출(수십 초 걸릴 수 있음)."""
        try:
            return service.generate()
        except AiNotConfigured as exc:
            raise HTTPException(409, str(exc)) from None
        except ReportBusy as exc:
            raise HTTPException(429, str(exc)) from None
        except LlmError as exc:
            raise HTTPException(502, f"AI 호출 실패: {exc}") from None

    @router.get("", dependencies=read)
    def list_reports() -> list[dict]:
        return repo.list_reports()

    @router.get("/{report_id}", dependencies=read)
    def get_report(report_id: int) -> dict:
        report = repo.get_report(report_id)
        if report is None:
            raise HTTPException(404, "report not found")
        return report

    @router.delete("/{report_id}", dependencies=[Depends(require_admin)])
    def delete_report(report_id: int) -> dict:
        if not repo.delete_report(report_id):
            raise HTTPException(404, "report not found")
        return {"deleted": report_id}

    return router
