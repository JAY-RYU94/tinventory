"""자산 대장 API. 쓰기는 관리자, 읽기는 read 토큰. 수집 호스트와의 연결은 assetview 가 읽을 때 계산한다."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Callable, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator, model_validator

from swinventory.common.hardware import clean_text
from swinventory.server.api.csvutil import csv_response
from swinventory.server.api.models import strip_controls
from swinventory.server.api.params import FORMAT
from swinventory.server.assetview import canonical_ip
from swinventory.server.assets import AssetService
from swinventory.server.repo.base import ConflictError, InventoryRepository
from swinventory.server.timeutil import normalize_ts

_HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")


class AssetIn(BaseModel):
    """PUT 은 전체 교체다 — 빠진 선택 필드는 비워진다."""

    asset_no: str = Field(min_length=1, max_length=64, description="자산번호(대소문자 무시 유일)")
    kind: Literal["physical", "virtual"]
    serial: str = Field(default="", max_length=128)
    hostname: str = Field(default="", max_length=255)
    domain: str = Field(default="", max_length=255)
    ip: str = Field(default="", max_length=45, description="관리 IP(대장 값). 수집된 IP 와 다르면 불일치로 표시")
    parent_asset_id: int | None = Field(default=None, description="VM 이 올라간 물리 장비의 자산 id")
    host_id: str | None = Field(default=None, max_length=128, description="수집 호스트와 자동 연결이 안 될 때 관리자가 지정하는 명시 연결")
    note: str = Field(default="", max_length=500)

    @field_validator("asset_no", "serial", "hostname", "domain", "ip", "host_id", "note", mode="before")
    @classmethod
    def _clean(cls, v: Any) -> Any:  # NUL·제어문자는 PostgreSQL 에서 500 이 되므로 거부하지 않고 제거한다
        return clean_text(strip_controls(v)) if isinstance(v, str) else v

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str) -> str:
        if v and not _HOSTNAME.match(v):
            raise ValueError("호스트명 형식이 아니다")
        return v

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        v = v.lower().strip(".")
        if v and not _DOMAIN.match(v):
            raise ValueError("도메인 형식이 아니다")
        return v

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        if not v:
            return v
        canon = canonical_ip(v)
        if not canon:
            raise ValueError("IP 주소 형식이 아니다")
        return canon

    @field_validator("host_id")
    @classmethod
    def _host_id(cls, v: str | None) -> str | None:
        return v or None

    @model_validator(mode="after")
    def _parent_only_for_virtual(self) -> "AssetIn":
        if self.kind == "physical" and self.parent_asset_id is not None:
            raise ValueError("물리 장비는 상위 호스트를 가질 수 없다")
        return self


_STATUS = Query(None, pattern="^(linked|uncollected|unregistered|mismatch)$",
                description="linked=연결됨, uncollected=대장에만 있음(미수집), unregistered=수집됐지만 대장에 없음, "
                            "mismatch=대장과 수집값이 어긋난 행(flags 가 있는 모든 상태)")
_KIND = Query(None, pattern="^(physical|virtual|container|unknown)$")
_CSV_COLUMNS = ["asset_no", "kind", "status", "hostname", "domain", "ip", "serial", "virt", "parent_asset_no", "host_id",
                "match_by", "flags", "note"]


def _flat(row: dict[str, Any]) -> dict[str, Any]:
    a = row["asset"] or {}
    return {**row, "asset_no": a.get("asset_no"), "note": a.get("note", ""), "flags": ";".join(row["flags"])}


def _status_matches(row: dict[str, Any], status: str | None) -> bool:
    """mismatch 는 연결 상태가 아니라 flags(kind·serial·ip 불일치)가 하나라도 있는지로 판정한다."""
    if status is None:
        return True
    return bool(row["flags"]) if status == "mismatch" else row["status"] == status


def _matches(row: dict[str, Any], needle: str) -> bool:
    a = row["asset"] or {}
    hay = [row["hostname"], row["domain"], row["serial"], row["ip"], *row["ips"], row["parent_asset_no"] or "",
           *(str(a.get(k) or "") for k in ("asset_no", "serial", "hostname", "domain", "ip", "note"))]
    return any(needle in h.lower() for h in hay)


def build_router(repo: InventoryRepository, service: AssetService, require_read: Callable[..., None],
                 require_admin: Callable[..., None], clock: Callable[[], datetime]) -> APIRouter:
    router = APIRouter(prefix="/v1/assets")
    read, admin = [Depends(require_read)], [Depends(require_admin)]

    def now() -> str:
        return normalize_ts(clock())

    def validate(body: AssetIn, self_id: int | None) -> dict[str, Any]:
        values = body.model_dump()
        assets = repo.list_assets()
        by_id = {a["id"]: a for a in assets}
        if body.parent_asset_id is not None:
            parent = by_id.get(body.parent_asset_id)
            if parent is None or body.parent_asset_id == self_id:
                raise HTTPException(422, "상위 호스트로 지정한 자산이 없거나 자기 자신이다")
            if parent["kind"] != "physical":
                raise HTTPException(422, "상위 호스트는 물리 장비 자산이어야 한다")
        key = body.asset_no.casefold()
        if any(a["id"] != self_id and a["asset_no"].casefold() == key for a in assets):
            raise HTTPException(409, f"자산번호 {body.asset_no!r} 가 이미 있다")
        if body.host_id is not None:
            if repo.get_host(body.host_id) is None:
                raise HTTPException(422, "명시 연결로 지정한 호스트가 없다")
            if any(a["id"] != self_id and a["host_id"] == body.host_id for a in assets):
                raise HTTPException(409, "그 호스트는 이미 다른 자산에 연결돼 있다")
        if self_id is not None and body.kind != "physical":
            children = [a["asset_no"] for a in assets if a["parent_asset_id"] == self_id]
            if children:
                raise HTTPException(409, f"이 장비 위에 VM 이 있어 가상으로 바꿀 수 없다: {', '.join(children[:10])}")
        return values

    def row_of(asset_id: int) -> dict[str, Any] | None:
        return next((r for r in service.book().rows() if r["asset"] and r["asset"]["id"] == asset_id), None)

    @router.get("", dependencies=read, response_model=None)
    def list_(kind: str | None = _KIND, status: str | None = _STATUS, q: str | None = Query(None, max_length=200),
              fmt: str = FORMAT) -> Response | list[dict]:
        needle = (q or "").strip().lower()
        rows = [r for r in service.book().rows()
                if (kind is None or r["kind"] == kind) and _status_matches(r, status) and (not needle or _matches(r, needle))]
        rows.sort(key=lambda r: (r["status"] == "unregistered", (r["asset"] or {}).get("asset_no", "").casefold(), r["hostname"].casefold()))
        if fmt == "csv":
            return csv_response([_flat(r) for r in rows], _CSV_COLUMNS, "assets.csv")
        return rows

    @router.get("/summary", dependencies=read)
    def summary() -> dict:
        return service.book().summary()

    @router.get("/{asset_id}", dependencies=read)
    def detail(asset_id: int) -> dict:
        row = row_of(asset_id)
        if row is None:
            raise HTTPException(404, "asset not found")
        row["vms"] = [{"id": a["id"], "asset_no": a["asset_no"], "hostname": a["hostname"]}
                      for a in repo.list_assets() if a["parent_asset_id"] == asset_id]
        return row

    @router.post("", dependencies=admin, status_code=201)
    def create(body: AssetIn) -> dict:
        values = validate(body, None)
        try:
            asset_id = repo.create_asset(values, now())
        except ConflictError:
            raise HTTPException(409, "자산번호 또는 호스트 연결이 이미 사용 중이다") from None
        return repo.get_asset(asset_id) or {}

    @router.put("/{asset_id}", dependencies=admin)
    def update(asset_id: int, body: AssetIn) -> dict:
        if repo.get_asset(asset_id) is None:
            raise HTTPException(404, "asset not found")
        values = validate(body, asset_id)
        try:
            if not repo.update_asset(asset_id, values, now()):
                raise HTTPException(404, "asset not found")
        except ConflictError:
            raise HTTPException(409, "자산번호 또는 호스트 연결이 이미 사용 중이다") from None
        return repo.get_asset(asset_id) or {}

    @router.delete("/{asset_id}", dependencies=admin)
    def delete(asset_id: int) -> dict:
        children = [a["asset_no"] for a in repo.list_assets() if a["parent_asset_id"] == asset_id]
        if children:
            raise HTTPException(409, f"이 장비 위에 VM 이 있어 삭제할 수 없다: {', '.join(children[:10])}")
        if not repo.delete_asset(asset_id):
            raise HTTPException(404, "asset not found")
        return {"deleted": asset_id}

    return router
