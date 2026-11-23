"""업무용 애플리케이션 분류와 조직 내 사용 승인 요청 API."""
from __future__ import annotations

from typing import Callable, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from swinventory.server.accounts import Accounts
from swinventory.server.api.models import has_control
from swinventory.server.assets import AssetService
from swinventory.server.repo.base import ConflictError, InventoryRepository
from swinventory.server.timeutil import normalize_ts

_CATEGORIES = {"business_app", "os_package", "development_dependency", "needs_review"}
_STATUSES = {"submitted", "reviewing", "needs_changes", "approved", "rejected", "withdrawn"}
_REQUEST_SORTS = {"product", "status", "security", "targets", "requester", "assignee", "due", "request_no"}
_BATCH_SORTS = {"host", "requester", "status", "due", "batch_no"}
_IMPACT_STATES = {"confirmed", "needs_review", "not_affected", "no_observed_match", "not_assessed"}


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Classification(Input):
    source: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=512)
    arch: str = Field(max_length=32)
    category: str
    product_name: str = Field(default="", max_length=512)
    publisher: str = Field(default="", max_length=255)
    evidence: str = Field(min_length=1, max_length=1000)
    expected_revision: int | None = Field(default=None, ge=1)

    @field_validator("source", "name", "arch", "product_name", "publisher", "evidence")
    @classmethod
    def clean_text(cls, value: str) -> str:
        value = value.strip()
        if has_control(value):
            raise ValueError("제어문자를 사용할 수 없습니다.")
        return value

class NewRequest(Input):
    source: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=512)
    arch: str = Field(max_length=32)
    version: str = Field(min_length=1, max_length=256)
    purpose: str = Field(min_length=5, max_length=2000)
    license_evidence: str = Field(min_length=3, max_length=2000)
    host_ids: list[str] = Field(min_length=1, max_length=100)

    @field_validator("source", "name", "arch", "version", "purpose", "license_evidence")
    @classmethod
    def clean_text(cls, value: str) -> str:
        value = value.strip()
        if has_control(value):
            raise ValueError("제어문자를 사용할 수 없습니다.")
        return value

    @field_validator("source", "name", "version", "purpose", "license_evidence")
    @classmethod
    def require_nonblank(cls, value: str) -> str:
        if not value:
            raise ValueError("공백만 있는 값은 사용할 수 없습니다.")
        return value

    @field_validator("host_ids")
    @classmethod
    def unique_hosts(cls, value: list[str]) -> list[str]:
        if not value or any(not item or len(item) > 128 or has_control(item) for item in value):
            raise ValueError("대상 호스트를 확인하세요.")
        if len(set(value)) != len(value):
            raise ValueError("대상 호스트가 중복되었습니다.")
        return value

    @model_validator(mode="after")
    def enforce_lengths_after_strip(self):
        if len(self.source) < 1 or len(self.name) < 1 or len(self.version) < 1:
            raise ValueError("제품 식별값과 버전을 확인하세요.")
        if len(self.purpose) < 5 or len(self.license_evidence) < 3:
            raise ValueError("목적과 사용권 근거를 확인하세요.")
        return self


class RequestAction(Input):
    action: Literal["assign", "request_changes", "resubmit", "approve", "reject", "withdraw", "revoke_approval"]
    expected_revision: int = Field(ge=1)
    reason: str = Field(default="", max_length=2000)
    assignee_id: str | None = Field(default=None, max_length=32)
    due_at: str | None = Field(default=None, max_length=64)
    approval_until: str | None = Field(default=None, max_length=64)
    purpose: str | None = Field(default=None, min_length=5, max_length=2000)
    license_evidence: str | None = Field(default=None, min_length=3, max_length=2000)

    @field_validator("reason", "purpose", "license_evidence")
    @classmethod
    def clean_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if has_control(value):
            raise ValueError("제어문자를 사용할 수 없습니다.")
        return value

    @model_validator(mode="after")
    def enforce_resubmission_lengths(self):
        if self.purpose is not None and len(self.purpose) < 5:
            raise ValueError("목적을 확인하세요.")
        if self.license_evidence is not None and len(self.license_evidence) < 3:
            raise ValueError("사용권 근거를 확인하세요.")
        return self


class BatchItem(Input):
    source: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=512)
    arch: str = Field(max_length=32)
    version: str = Field(min_length=1, max_length=256)

    @field_validator("source", "name", "arch", "version")
    @classmethod
    def clean_product_text(cls, value: str) -> str:
        value = value.strip()
        if has_control(value):
            raise ValueError("제어문자를 사용할 수 없습니다.")
        return value

    @field_validator("source", "name", "version")
    @classmethod
    def nonblank_key(cls, value: str) -> str:
        if not value:
            raise ValueError("제품 식별값을 확인하세요.")
        return value


class NewBatch(Input):
    host_id: str = Field(min_length=1, max_length=128)
    items: list[BatchItem] = Field(min_length=1, max_length=100)
    purpose: str = Field(min_length=5, max_length=2000)
    license_evidence: str = Field(min_length=3, max_length=2000)

    @field_validator("host_id", "purpose", "license_evidence")
    @classmethod
    def clean_batch_text(cls, value: str) -> str:
        value = value.strip()
        if not value or has_control(value):
            raise ValueError("입력값을 확인하세요.")
        return value

    @model_validator(mode="after")
    def enforce_shared_field_lengths(self):
        if len(self.purpose) < 5 or len(self.license_evidence) < 3:
            raise ValueError("목적과 사용권 근거를 확인하세요.")
        return self

    @model_validator(mode="after")
    def unique_items(self):
        keys = [(item.source, item.name, item.arch, item.version) for item in self.items]
        if len(set(keys)) != len(keys):
            raise ValueError("중복 소프트웨어 항목이 있습니다.")
        return self


class BatchActionItem(Input):
    request_id: int = Field(ge=1)
    expected_revision: int = Field(ge=1)


class BatchAction(Input):
    action: Literal["assign", "request_changes", "resubmit", "approve", "reject", "withdraw", "revoke_approval"]
    items: list[BatchActionItem] = Field(min_length=1, max_length=100)
    reason: str = Field(default="", max_length=2000)
    assignee_id: str | None = Field(default=None, max_length=32)
    due_at: str | None = Field(default=None, max_length=64)
    approval_until: str | None = Field(default=None, max_length=64)
    purpose: str | None = Field(default=None, min_length=5, max_length=2000)
    license_evidence: str | None = Field(default=None, min_length=3, max_length=2000)

    @field_validator("reason", "purpose", "license_evidence")
    @classmethod
    def clean_batch_action_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if has_control(value):
            raise ValueError("제어문자를 사용할 수 없습니다.")
        return value

    @model_validator(mode="after")
    def enforce_resubmission_lengths(self):
        if self.purpose is not None and len(self.purpose) < 5:
            raise ValueError("목적을 확인하세요.")
        if self.license_evidence is not None and len(self.license_evidence) < 3:
            raise ValueError("사용권 근거를 확인하세요.")
        return self

    @model_validator(mode="after")
    def unique_selected(self):
        ids = [item.request_id for item in self.items]
        if len(set(ids)) != len(ids):
            raise ValueError("중복 요청 항목이 있습니다.")
        return self


def _bearer(authorization: str | None) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def _actor(accounts: Accounts, authorization: str | None, role: str) -> dict:
    principal = accounts.principal(_bearer(authorization))
    if (not principal or principal.get("kind") != "session" or not principal.get("user_id")
            or principal.get("user_role") != role):
        raise HTTPException(403, "개인 사용자 로그인 세션이 필요합니다.")
    return principal


def _conflict_message(error: ConflictError) -> str:
    message = str(error)
    if message == "exact installed business application changed":
        return "요청 이후 현재 설치 버전 또는 업무용 앱 분류가 변경되어 승인할 수 없습니다."
    if message == "exact software approval already exists":
        return "현재 유효한 사용 승인이 이미 있어 승인할 수 없습니다."
    if message in {"batch child host scope changed", "batch approval scope changed"}:
        return "요청 항목의 호스트 범위가 변경되어 처리할 수 없습니다."
    return "요청이 다른 사용자에 의해 변경되었습니다. 최신 이력을 다시 불러오세요."


def _timestamp(value: str | None, label: str, *, future_after: str | None = None) -> str:
    if not value:
        raise HTTPException(422, f"{label}을 입력하세요.")
    text = value.strip()
    # 날짜만 오는 값은 서비스 시간대가 모호하므로 받지 않는다.
    if not (text.endswith(("Z", "z")) or "+" in text[10:] or "-" in text[10:]):
        raise HTTPException(422, f"{label}에는 시간대 오프셋을 포함하세요.")
    try:
        result = normalize_ts(text)
    except (ValueError, TypeError):
        raise HTTPException(422, f"{label}의 날짜와 시간을 확인하세요.") from None
    if future_after is not None and result <= future_after:
        raise HTTPException(422, f"{label}은 현재 이후여야 합니다.")
    return result


def build_router(repo: InventoryRepository, accounts: Accounts, require_read: Callable[..., None],
                 require_request: Callable[..., None], require_admin: Callable[..., None],
                 caller_role: Callable[..., str], clock: Callable) -> APIRouter:
    router = APIRouter(prefix="/v1")
    asset_service = AssetService(repo)

    def enrich_batch(batch: dict, asset_book=None) -> dict:
        host = batch.get("host")
        if host and host.get("host_id"):
            view = (asset_book or asset_service.book()).host_view(host["host_id"])
            host.update({key: view[key] for key in ("asset_id", "asset_no", "primary_owner", "secondary_owner")})
        return batch

    def approval_role(role: str = Depends(caller_role)) -> str:
        return role

    approval_role.required_role = "request"  # 관리자는 상위 권한으로 허용되며 조회 역할은 차단된다.

    @router.get("/software-products", dependencies=[Depends(require_read)])
    def products(q: str = Query("", max_length=200), category: str | None = Query(None),
                 page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
        if category is not None and category not in _CATEGORIES:
            raise HTTPException(422, "분류값을 확인하세요.")
        total, items = repo.list_software_products(q.strip(), category, (page - 1) * page_size, page_size)
        return {"items": items, "total": total, "page": page, "page_size": page_size}

    @router.get("/hosts/{host_id}/software-summary", dependencies=[Depends(require_read)])
    def host_software_summary(host_id: str, role: str = Depends(caller_role),
                              authorization: str | None = Header(None)):
        host = repo.get_host(host_id)
        if host is None:
            raise HTTPException(404, "호스트를 찾을 수 없습니다.")
        include_request_state = role in {"admin", "request"}
        requester_id = None
        if role == "request":
            requester_id = _actor(accounts, authorization, "request")["user_id"]
        items = repo.host_software_summary(host_id, normalize_ts(clock()), requester_id=requester_id,
                                           include_request_state=include_request_state)
        return {"host_id": host_id, "last_seen": host.last_seen, "items": items}

    @router.get("/software-classification-history", dependencies=[Depends(require_read)])
    def classification_history(source: str = Query(min_length=1, max_length=64),
                               name: str = Query(min_length=1, max_length=512), arch: str = Query("", max_length=32)):
        return repo.software_classification_history(source, name, arch)

    @router.put("/software-products/classification", dependencies=[Depends(require_admin)])
    def classify(body: Classification, authorization: str | None = Header(None)):
        if body.category not in _CATEGORIES:
            raise HTTPException(422, "분류값을 확인하세요.")
        if not body.evidence:
            raise HTTPException(422, "분류 근거를 입력하세요.")
        values = {k: getattr(body, k) for k in ("category", "product_name", "publisher", "evidence")}
        try:
            with accounts.admin(_bearer(authorization)):
                actor = _actor(accounts, authorization, "admin")
                return repo.set_software_classification(body.source, body.name, body.arch, values,
                    actor["user_id"], normalize_ts(clock()), body.expected_revision)
        except KeyError:
            raise HTTPException(404, "설치 인벤토리에서 소프트웨어를 찾을 수 없습니다.") from None
        except ConflictError:
            raise HTTPException(409, "분류가 다른 관리자로부터 변경되었습니다. 최신 값을 다시 불러오세요.") from None

    @router.get("/software-request-scopes/me", dependencies=[Depends(require_request)])
    def my_scope(authorization: str | None = Header(None)):
        actor = _actor(accounts, authorization, "request")
        return {"user_id": actor["user_id"], "host_ids": repo.get_software_request_scope(actor["user_id"])}

    @router.get("/software-request-scopes/{user_id}", dependencies=[Depends(require_admin)])
    def get_scope(user_id: str):
        user = repo.get_user(user_id)
        if not user or user["role"] != "request":
            raise HTTPException(404, "요청 권한이 있는 사용자를 찾을 수 없습니다.")
        return {"user_id": user_id, "host_ids": repo.get_software_request_scope(user_id)}

    @router.put("/software-request-scopes/{user_id}", dependencies=[Depends(require_admin)])
    def set_scope(user_id: str, body: dict, authorization: str | None = Header(None)):
        if set(body) != {"host_ids"} or not isinstance(body.get("host_ids"), list) or len(body["host_ids"]) > 1000:
            raise HTTPException(422, "host_ids 배열을 입력하세요.")
        host_ids = body["host_ids"]
        if any(not isinstance(h, str) or not h or len(h) > 128 or has_control(h) for h in host_ids) or len(set(host_ids)) != len(host_ids):
            raise HTTPException(422, "대상 호스트를 확인하세요.")
        user = repo.get_user(user_id)
        if not user or user["role"] != "request":
            raise HTTPException(404, "요청 권한이 있는 사용자를 찾을 수 없습니다.")
        for host_id in host_ids:
            if repo.get_host(host_id) is None:
                raise HTTPException(422, f"등록된 호스트가 아닙니다: {host_id}")
        with accounts.admin(_bearer(authorization)):
            actor = _actor(accounts, authorization, "admin")
            repo.replace_software_request_scope(user_id, host_ids, actor["user_id"], normalize_ts(clock()))
        return {"user_id": user_id, "host_ids": sorted(host_ids)}

    @router.get("/software-request-scopes/{user_id}/history", dependencies=[Depends(require_admin)])
    def scope_history(user_id: str):
        user = repo.get_user(user_id)
        if not user or user["role"] != "request":
            raise HTTPException(404, "요청 권한이 있는 사용자를 찾을 수 없습니다.")
        return repo.software_request_scope_history(user_id)

    @router.post("/software-requests", status_code=201, dependencies=[Depends(require_request)])
    def create_request(body: NewRequest, authorization: str | None = Header(None)):
        at = normalize_ts(clock())
        try:
            with repo.auth_lock():
                actor = _actor(accounts, authorization, "request")
                classification = repo.get_software_classification(body.source, body.name, body.arch)
                if not classification or classification["category"] != "business_app":
                    raise HTTPException(422, "업무용 앱으로 분류된 제품만 사용 승인을 요청할 수 있습니다.")
                allowed = set(repo.get_software_request_scope(actor["user_id"]))
                if not set(body.host_ids) <= allowed:
                    raise HTTPException(403, "요청 권한 범위에 포함된 호스트만 선택할 수 있습니다.")
                if not repo.software_product_installed(body.source, body.name, body.arch, body.version, body.host_ids):
                    raise HTTPException(422, "선택한 모든 호스트에 지정 버전이 설치되어 있어야 합니다.")
                request_id = repo.create_software_request({
                    "requester_id": actor["user_id"], "source": body.source, "name": body.name,
                    "arch": body.arch, "product_name": classification["product_name"] or body.name,
                    "version": body.version, "purpose": body.purpose,
                    "license_evidence": body.license_evidence, "assignee_id": None,
                    "due_at": None, "approval_until": None, "decision_reason": "",
                }, body.host_ids, actor["user_id"], at)
                return repo.get_software_request(request_id)
        except ConflictError as exc:
            kind = str(exc)
            if kind == "overlapping request":
                raise HTTPException(409, {"kind": "duplicate_request"}) from None
            if kind == "already approved":
                raise HTTPException(409, {"kind": "already_approved"}) from None
            raise HTTPException(409, "요청이 동시에 변경되었습니다.") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @router.post("/software-request-batches", status_code=201, dependencies=[Depends(require_request)])
    def create_request_batch(body: NewBatch, authorization: str | None = Header(None)):
        at = normalize_ts(clock())
        try:
            with repo.auth_lock():
                actor = _actor(accounts, authorization, "request")
                allowed = set(repo.get_software_request_scope(actor["user_id"]))
                if body.host_id not in allowed:
                    raise HTTPException(403, "요청 권한 범위에 포함된 호스트만 선택할 수 있습니다.")
                if repo.get_host(body.host_id) is None:
                    raise HTTPException(422, "등록된 호스트가 아닙니다.")
                items = [item.model_dump() for item in body.items]
                for item in items:
                    classification = repo.get_software_classification(item["source"], item["name"], item["arch"])
                    if not classification or classification["category"] != "business_app":
                        raise HTTPException(422, "업무용 앱으로 분류된 제품만 승인 요청할 수 있습니다.")
                    if not repo.software_product_installed(item["source"], item["name"], item["arch"],
                                                           item["version"], [body.host_id]):
                        raise HTTPException(422, "선택한 호스트에 지정 버전이 설치되어 있어야 합니다.")
                batch_id = repo.create_software_request_batch({"host_id": body.host_id,
                    "purpose": body.purpose, "license_evidence": body.license_evidence},
                    items, actor["user_id"], at)
            batch = repo.get_software_request_batch(batch_id, at)
            if batch is None:
                raise HTTPException(500, "요청 묶음을 만들지 못했습니다.")
            return enrich_batch(batch)
        except ConflictError as exc:
            if str(exc) == "overlapping request":
                raise HTTPException(409, "선택한 소프트웨어 중 진행 중인 승인 요청이 있습니다.") from None
            if str(exc) == "already approved":
                raise HTTPException(409, "선택한 소프트웨어 중 현재 유효한 사용 승인이 있습니다.") from None
            raise HTTPException(409, "요청이 동시에 변경되었습니다.") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @router.get("/software-request-batches", dependencies=[Depends(require_read)])
    def request_batches(role: str = Depends(approval_role), authorization: str | None = Header(None),
                        q: str = Query("", max_length=200), scope: str = Query("all"),
                        status: str | None = Query(None), host: str | None = Query(None, max_length=128),
                        security_impact: str | None = Query(None), sort: str | None = Query(None),
                        direction: str = Query("asc", pattern="^(asc|desc)$"),
                        mine: bool = False, assigned_to_me: bool = False,
                        page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
        if role == "read":
            raise HTTPException(403, "요청 권한 또는 관리자 권한이 필요합니다.")
        if scope not in {"pending", "all", "assigned", "overdue"}:
            raise HTTPException(422, "요청 범위를 확인하세요.")
        if scope == "assigned" and role != "admin":
            raise HTTPException(403, "관리자 담당자 범위는 관리자만 조회할 수 있습니다.")
        if status is not None and status not in _STATUSES:
            raise HTTPException(422, "요청 상태를 확인하세요.")
        if security_impact is not None and security_impact not in _IMPACT_STATES:
            raise HTTPException(422, "보안 영향 상태를 확인하세요.")
        if sort is not None and sort not in _BATCH_SORTS:
            raise HTTPException(422, "정렬 기준을 확인하세요.")
        if assigned_to_me and role != "admin":
            raise HTTPException(403, "관리자 담당자 필터는 관리자만 사용할 수 있습니다.")
        if assigned_to_me and mine:
            raise HTTPException(422, "요청자 본인과 담당자 본인 필터는 함께 사용할 수 없습니다.")
        owner = None
        if role == "request" or mine:
            owner = _actor(accounts, authorization, "request" if role == "request" else "admin")["user_id"]
        assignee = _actor(accounts, authorization, "admin")["user_id"] if assigned_to_me else None
        cutoff = normalize_ts(clock()) if scope == "overdue" else None
        total, items = repo.list_software_request_batches(requester_id=owner, scope=scope, status=status,
            host_id=host, security_impact=security_impact, q=q.strip(), overdue_before=cutoff,
            assignee_id=assignee, sort=sort, direction=direction, offset=(page - 1) * page_size,
            limit=page_size)
        asset_book = asset_service.book()
        for item in items:
            enrich_batch(item, asset_book)
        return {"items": items, "total": total, "page": page, "page_size": page_size}

    @router.get("/software-request-batches/{batch_id}", dependencies=[Depends(require_read)])
    def request_batch_detail(batch_id: int, role: str = Depends(approval_role),
                             authorization: str | None = Header(None)):
        if role == "read":
            raise HTTPException(403, "요청 권한 또는 관리자 권한이 필요합니다.")
        batch = repo.get_software_request_batch(batch_id, normalize_ts(clock()))
        if batch is None:
            raise HTTPException(404, "요청 묶음을 찾을 수 없습니다.")
        if role == "request":
            actor = _actor(accounts, authorization, "request")
            if batch["requester_id"] != actor["user_id"]:
                raise HTTPException(404, "요청 묶음을 찾을 수 없습니다.")
        now = normalize_ts(clock())
        for item in batch["items"]:
            for approval in item["approvals"]:
                approval["effective_state"] = ("revoked" if approval["state"] == "revoked" else
                    "expired" if approval["valid_until"] < now else "active")
        return enrich_batch(batch)

    @router.post("/software-request-batches/{batch_id}/actions", dependencies=[Depends(require_read)])
    def request_batch_action(batch_id: int, body: BatchAction, role: str = Depends(approval_role),
                             authorization: str | None = Header(None)):
        if role == "read":
            raise HTTPException(403, "요청 권한 또는 관리자 권한이 필요합니다.")
        admin_action = body.action in {"assign", "request_changes", "approve", "reject", "revoke_approval"}
        if admin_action and role != "admin":
            raise HTTPException(403, "관리자 권한이 필요합니다.")
        now = normalize_ts(clock())
        try:
            if role == "admin":
                with accounts.admin(_bearer(authorization)):
                    actor = _actor(accounts, authorization, "admin")
                    _apply_batch_action(repo, batch_id, body, actor["user_id"], role, now)
            else:
                with repo.auth_lock():
                    actor = _actor(accounts, authorization, "request")
                    _apply_batch_action(repo, batch_id, body, actor["user_id"], role, now)
            result = repo.get_software_request_batch(batch_id, now)
            if result is None:
                raise HTTPException(404, "요청 묶음을 찾을 수 없습니다.")
            for item in result["items"]:
                for approval in item["approvals"]:
                    approval["effective_state"] = ("revoked" if approval["state"] == "revoked" else
                        "expired" if approval["valid_until"] < now else "active")
            return enrich_batch(result)
        except ConflictError as exc:
            raise HTTPException(409, _conflict_message(exc)) from None
        except KeyError:
            raise HTTPException(404, "요청 묶음을 찾을 수 없습니다.") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @router.get("/software-requests", dependencies=[Depends(require_read)])
    def requests(role: str = Depends(approval_role), authorization: str | None = Header(None),
                 status: str | None = Query(None), q: str = Query("", max_length=200),
                 scope: str | None = Query(None), pending: bool = False, mine: bool = False,
                 assigned_to_me: bool = False, unassigned: bool = False, overdue: bool = False,
                 sort: str | None = Query(None), direction: str = Query("asc", pattern="^(asc|desc)$"),
                 security_impact: str | None = Query(None),
                 page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
        if role == "read":
            raise HTTPException(403, "요청 권한 또는 관리자 권한이 필요합니다.")
        if status == "pending":
            pending, status = True, None
        if scope is not None and scope != "pending":
            raise HTTPException(422, "요청 범위를 확인하세요.")
        if scope == "pending":
            pending = True
        if pending and status is not None:
            raise HTTPException(422, "pending 범위와 단일 상태 필터는 함께 사용할 수 없습니다.")
        if status is not None and status not in _STATUSES:
            raise HTTPException(422, "요청 상태를 확인하세요.")
        if sort is not None and sort not in _REQUEST_SORTS:
            raise HTTPException(422, "정렬 기준을 확인하세요.")
        if security_impact is not None and security_impact not in {"confirmed", "needs_review", "not_affected",
                                                                    "no_observed_match", "not_assessed"}:
            raise HTTPException(422, "보안 영향 상태를 확인하세요.")
        if assigned_to_me and role != "admin":
            raise HTTPException(403, "관리자 담당자 필터는 관리자만 사용할 수 있습니다.")
        if assigned_to_me and mine:
            raise HTTPException(422, "요청자 본인과 담당자 본인 필터는 함께 사용할 수 없습니다.")
        owner = None
        if role == "request" or mine:
            actor = _actor(accounts, authorization, "request" if role == "request" else "admin")
            owner = actor["user_id"]
        assignee = None
        if assigned_to_me:
            assignee = _actor(accounts, authorization, "admin")["user_id"]
        cutoff = normalize_ts(clock()) if overdue else None
        total, items = repo.list_software_requests(requester_id=owner, status=status, q=q.strip(),
            unassigned=unassigned, overdue_before=cutoff, offset=(page - 1) * page_size, limit=page_size,
            assignee_id=assignee, pending=pending, sort=sort, direction=direction,
            security_impact=security_impact)
        return {"items": items, "total": total, "page": page, "page_size": page_size}

    @router.get("/software-requests/{request_id}", dependencies=[Depends(require_read)])
    def request_detail(request_id: int, role: str = Depends(approval_role), authorization: str | None = Header(None)):
        if role == "read":
            raise HTTPException(403, "요청 권한 또는 관리자 권한이 필요합니다.")
        item = repo.get_software_request(request_id)
        if item is None:
            raise HTTPException(404, "요청을 찾을 수 없습니다.")
        if role == "request":
            actor = _actor(accounts, authorization, "request")
            if item["requester_id"] != actor["user_id"]:
                raise HTTPException(404, "요청을 찾을 수 없습니다.")
        now = normalize_ts(clock())
        for approval in item["approvals"]:
            approval["effective_state"] = ("revoked" if approval["state"] == "revoked" else
                "expired" if approval["valid_until"] < now else "active")
        return item

    @router.post("/software-requests/{request_id}/actions", dependencies=[Depends(require_read)])
    def request_action(request_id: int, body: RequestAction, role: str = Depends(approval_role),
                       authorization: str | None = Header(None)):
        if role == "read":
            raise HTTPException(403, "요청 권한 또는 관리자 권한이 필요합니다.")
        action, reason, now = body.action, body.reason, normalize_ts(clock())
        admin_action = action in {"assign", "request_changes", "approve", "reject", "revoke_approval"}
        if admin_action and role != "admin":
            raise HTTPException(403, "관리자 권한이 필요합니다.")
        try:
            if role == "admin":
                with accounts.admin(_bearer(authorization)):
                    actor = _actor(accounts, authorization, "admin")
                    return _apply_action(repo, request_id, body, actor["user_id"], role, now)
            with repo.auth_lock():
                actor = _actor(accounts, authorization, "request")
                return _apply_action(repo, request_id, body, actor["user_id"], role, now)
        except ConflictError as exc:
            raise HTTPException(409, _conflict_message(exc)) from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    return router


def _prepare_action(repo: InventoryRepository, request_id: int, item: dict, body,
                    expected_revision: int, actor_id: str, role: str, now: str) -> dict:
    status = item["status"]
    action, reason = body.action, body.reason.strip()
    values: dict = {}
    detail: dict = {}
    approvals = None
    revoke = False

    if action == "assign":
        if status not in {"submitted", "reviewing", "needs_changes"} or not body.assignee_id:
            raise HTTPException(409, "검토가 진행 중인 요청과 담당자를 선택하세요.")
        assignee = repo.get_user(body.assignee_id)
        if not assignee or not assignee["active"] or assignee["role"] != "admin":
            raise HTTPException(422, "활성 관리자 담당자를 선택하세요.")
        due = _timestamp(body.due_at, "처리 기한", future_after=now)
        values.update(status="reviewing", assignee_id=body.assignee_id, due_at=due)
        detail.update(assignee_id=body.assignee_id, due_at=due)
    elif action == "request_changes":
        if status not in {"submitted", "reviewing"} or not reason:
            raise HTTPException(409, "접수 또는 검토 중인 요청에 보완 사유를 입력하세요.")
        values.update(status="needs_changes", decision_reason=reason)
    elif action == "resubmit":
        if role != "request" or status != "needs_changes" or not body.purpose or not body.license_evidence:
            raise HTTPException(409, "보완 요청된 본인 요청에 목적과 사용권 근거를 다시 입력하세요.")
        values.update(status="submitted", purpose=body.purpose, license_evidence=body.license_evidence,
                      decision_reason="")
        detail.update(purpose=body.purpose, license_evidence=body.license_evidence)
    elif action == "approve":
        if status != "reviewing" or not reason:
            raise HTTPException(409, "검토 중인 요청에 승인 사유를 입력하세요.")
        until = _timestamp(body.approval_until, "승인 유효 기한", future_after=now)
        values.update(status="approved", approval_until=until, decision_reason=reason)
        approvals = [dict(request_id=request_id, source=item["source"], name=item["name"], arch=item["arch"],
            version=item["version"], host_id=host["host_id"], state="active", valid_from=now, valid_until=until,
            decided_by=actor_id, reason=reason, ended_at=None, end_reason="") for host in item["hosts"]]
        detail.update(approval_until=until, host_ids=[h["host_id"] for h in item["hosts"]])
    elif action == "reject":
        if status not in {"submitted", "reviewing", "needs_changes"} or not reason:
            raise HTTPException(409, "결정 전 요청에 반려 사유를 입력하세요.")
        values.update(status="rejected", decision_reason=reason)
    elif action == "withdraw":
        if role != "request" or status not in {"submitted", "reviewing", "needs_changes"}:
            raise HTTPException(409, "결정 전 본인 요청만 철회할 수 있습니다.")
        values.update(status="withdrawn", decision_reason=reason or "요청자가 철회")
    elif action == "revoke_approval":
        if status != "approved" or not reason:
            raise HTTPException(409, "승인된 요청에 취소 사유를 입력하세요.")
        if not any(a["state"] == "active" and a["valid_from"] <= now and a["valid_until"] >= now
                   and a["ended_at"] is None for a in item["approvals"]):
            raise HTTPException(409, "현재 유효한 승인 범위가 없습니다.")
        values.update(decision_reason=reason)
        revoke = True
    else:
        raise HTTPException(422, "요청 작업을 확인하세요.")

    return {"request_id": request_id, "expected_revision": expected_revision, "values": values,
            "action": action, "reason": reason, "detail": detail, "approvals": approvals,
            "revoke_approvals": revoke}


def _apply_action(repo: InventoryRepository, request_id: int, body: RequestAction,
                  actor_id: str, role: str, now: str) -> dict:
    item = repo.get_software_request(request_id)
    if item is None:
        raise HTTPException(404, "요청을 찾을 수 없습니다.")
    if item["revision"] != body.expected_revision:
        raise HTTPException(409, "요청이 다른 사용자에 의해 변경되었습니다. 최신 이력을 다시 불러오세요.")
    if role == "request" and item["requester_id"] != actor_id:
        raise HTTPException(404, "요청을 찾을 수 없습니다.")
    plan = _prepare_action(repo, request_id, item, body, body.expected_revision, actor_id, role, now)
    if item.get("batch_id") is not None:
        repo.update_software_request_batch(item["batch_id"], [plan], actor_id, now)
    else:
        repo.update_software_request(request_id, body.expected_revision, plan["values"], actor_id,
            plan["action"], plan["reason"], plan["detail"], now, approvals=plan["approvals"],
            revoke_approvals=plan["revoke_approvals"])
    result = repo.get_software_request(request_id)
    for approval in result["approvals"]:
        approval["effective_state"] = ("revoked" if approval["state"] == "revoked" else
            "expired" if approval["valid_until"] < now else "active")
    return result


def _apply_batch_action(repo: InventoryRepository, batch_id: int, body: BatchAction,
                        actor_id: str, role: str, now: str) -> None:
    batch = repo.get_software_request_batch(batch_id, now)
    if batch is None:
        raise HTTPException(404, "요청 묶음을 찾을 수 없습니다.")
    if role == "request" and batch["requester_id"] != actor_id:
        raise HTTPException(404, "요청 묶음을 찾을 수 없습니다.")
    children = {item["id"]: item for item in batch["items"]}
    plans = []
    for selected in body.items:
        item = children.get(selected.request_id)
        if item is None:
            raise HTTPException(404, "묶음에 포함된 요청 항목을 찾을 수 없습니다.")
        if item["revision"] != selected.expected_revision:
            raise HTTPException(409, "요청이 다른 사용자에 의해 변경되었습니다. 최신 이력을 다시 불러오세요.")
        if role == "request" and item["requester_id"] != actor_id:
            raise HTTPException(404, "요청 항목을 찾을 수 없습니다.")
        plans.append(_prepare_action(repo, selected.request_id, item, body, selected.expected_revision,
                                     actor_id, role, now))
    repo.update_software_request_batch(batch_id, plans, actor_id, now)
