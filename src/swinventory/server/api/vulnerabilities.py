"""CVE/KEV 조회와 근거가 있는 제품 영향 평가 API."""
from __future__ import annotations

import re
from typing import Callable, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

from swinventory.server.accounts import Accounts
from swinventory.server.api.models import has_control
from swinventory.server.repo.base import ConflictError, InventoryRepository
from swinventory.server.timeutil import normalize_ts
from swinventory.server.vulnerabilities import VulnerabilityFeedService

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
_IMPACT = {"confirmed", "needs_review", "no_observed_match", "not_assessed", "not_affected"}


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProductMatch(Input):
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$", max_length=32)
    source: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=512)
    arch: str = Field(max_length=32)
    status: Literal["affected_confirmed", "needs_review", "not_affected"]
    evidence: str = Field(min_length=8, max_length=2000)
    conditions: str = Field(default="", max_length=1000)
    affected_versions: list[str] = Field(default_factory=list, max_length=100)
    expected_revision: int | None = Field(default=None, ge=1)

    @field_validator("source", "name", "arch", "evidence", "conditions")
    @classmethod
    def clean_text(cls, value: str) -> str:
        value = value.strip()
        if has_control(value):
            raise ValueError("제어문자를 사용할 수 없습니다.")
        return value

    @field_validator("affected_versions")
    @classmethod
    def versions_unique(cls, values: list[str]) -> list[str]:
        cleaned = [v.strip() for v in values]
        if any(not v or len(v) > 256 or has_control(v) for v in cleaned) or len(cleaned) != len(set(cleaned)):
            raise ValueError("영향 버전 목록을 확인하세요.")
        return cleaned


def _bearer(authorization: str | None) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def build_router(repo: InventoryRepository, accounts: Accounts, feeds: VulnerabilityFeedService,
                 require_read: Callable[..., None], require_admin: Callable[..., None],
                 clock: Callable) -> APIRouter:
    router = APIRouter(prefix="/v1")

    @router.get("/vulnerability-feeds", dependencies=[Depends(require_read)])
    def feeds_status():
        return repo.vulnerability_feed_status()

    @router.post("/vulnerabilities/sync", dependencies=[Depends(require_admin)])
    def sync(authorization: str | None = Header(None)):
        # 개인 관리자 세션만 호출 가능하다. 환경 API 키/토큰은 URL·응답·감사 기록에 넣지 않는다.
        principal = accounts.principal(_bearer(authorization))
        if not principal or principal.get("kind") != "session" or principal.get("user_role") != "admin":
            raise HTTPException(403, "개인 관리자 로그인 세션이 필요합니다.")
        with accounts.admin(_bearer(authorization)):
            pass
        return feeds.sync()

    @router.get("/vulnerabilities", dependencies=[Depends(require_read)])
    def vulnerabilities(q: str = Query("", max_length=200), kev: bool = False,
                        impact: str | None = Query(None), host: str | None = Query(None, max_length=128), page: int = Query(1, ge=1),
                        page_size: int = Query(50, ge=1, le=200)):
        if impact is not None and impact not in _IMPACT:
            raise HTTPException(422, "영향 상태를 확인하세요.")
        total, items = repo.list_vulnerabilities(q=q.strip(), kev_only=kev, impact_status=impact,
            offset=(page - 1) * page_size, limit=page_size, host_id=host)
        return {"items": items, "total": total, "page": page, "page_size": page_size,
                "feeds": repo.vulnerability_feed_status()}

    @router.get("/vulnerabilities/{cve_id}", dependencies=[Depends(require_read)])
    def vulnerability(cve_id: str):
        if not _CVE.fullmatch(cve_id):
            raise HTTPException(422, "CVE ID 형식을 확인하세요.")
        row = repo.vulnerability_detail(cve_id)
        if row is None:
            raise HTTPException(404, "CVE를 찾을 수 없습니다.")
        return row

    @router.put("/vulnerabilities/matches", dependencies=[Depends(require_admin)])
    def set_match(body: ProductMatch, authorization: str | None = Header(None)):
        if body.status == "affected_confirmed" and not body.affected_versions:
            raise HTTPException(422, "영향을 확인한 정확한 설치 버전을 한 개 이상 입력하세요.")
        if body.status != "affected_confirmed" and body.affected_versions:
            raise HTTPException(422, "확정 영향 이외의 판정에는 영향 버전을 등록할 수 없습니다.")
        principal = accounts.principal(_bearer(authorization))
        if not principal or principal.get("kind") != "session" or principal.get("user_role") != "admin":
            raise HTTPException(403, "개인 관리자 로그인 세션이 필요합니다.")
        values = {k: getattr(body, k) for k in ("status", "evidence", "conditions", "affected_versions")}
        try:
            with accounts.admin(_bearer(authorization)):
                return repo.update_vulnerability_match(body.cve_id, body.source, body.name, body.arch, values,
                    principal["user_id"], normalize_ts(clock()), body.expected_revision)
        except KeyError as exc:
            if str(exc) == "'CVE not found'":
                raise HTTPException(404, "CVE를 찾을 수 없습니다.") from None
            raise HTTPException(404, "설치 소프트웨어를 찾을 수 없습니다.") from None
        except ConflictError:
            raise HTTPException(409, "영향 판정이 다른 관리자로부터 변경되었습니다. 최신 근거를 다시 불러오세요.") from None

    return router
