"""업무용 애플리케이션 분류와 조직 내 사용 승인 요청 API."""
from __future__ import annotations

from typing import Callable, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

from swinventory.server.accounts import Accounts
from swinventory.server.api.models import has_control
from swinventory.server.repo.base import ConflictError, InventoryRepository
from swinventory.server.timeutil import normalize_ts

_CATEGORIES = {"business_app", "os_package", "development_dependency", "needs_review"}
_STATUSES = {"submitted", "reviewing", "needs_changes", "approved", "rejected", "withdrawn"}


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

    @field_validator("host_ids")
    @classmethod
    def unique_hosts(cls, value: list[str]) -> list[str]:
        if not value or any(not item or len(item) > 128 or has_control(item) for item in value):
            raise ValueError("대상 호스트를 확인하세요.")
        if len(set(value)) != len(value):
            raise ValueError("대상 호스트가 중복되었습니다.")
        return value


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


def _bearer(authorization: str | None) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def _actor(accounts: Accounts, authorization: str | None, role: str) -> dict:
    principal = accounts.principal(_bearer(authorization))
    if (not principal or principal.get("kind") != "session" or not principal.get("user_id")
            or principal.get("user_role") != role):
        raise HTTPException(403, "개인 사용자 로그인 세션이 필요합니다.")
    return principal


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
    approval_role = caller_role
    approval_role.required_role = "request"  # 관리자는 상위 권한으로 허용되며 조회 역할은 차단된다.

    @router.get("/software-products", dependencies=[Depends(require_read)])
    def products(q: str = Query("", max_length=200), category: str | None = Query(None),
                 page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
        if category is not None and category not in _CATEGORIES:
            raise HTTPException(422, "분류값을 확인하세요.")
        total, items = repo.list_software_products(q.strip(), category, (page - 1) * page_size, page_size)
        return {"items": items, "total": total, "page": page, "page_size": page_size}

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
            kind, _, request_id = str(exc).partition(":")
            if kind == "overlapping request":
                existing = repo.get_software_request(int(request_id))
                raise HTTPException(409, {"kind": "duplicate_request", "request": existing}) from None
            if kind == "already approved":
                raise HTTPException(409, {"kind": "already_approved", "request_id": int(request_id)}) from None
            raise HTTPException(409, "요청이 동시에 변경되었습니다.") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @router.get("/software-requests", dependencies=[Depends(require_read)])
    def requests(role: str = Depends(approval_role), authorization: str | None = Header(None),
                 status: str | None = Query(None), q: str = Query("", max_length=200),
                 mine: bool = False, unassigned: bool = False, overdue: bool = False,
                 page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
        if role == "read":
            raise HTTPException(403, "요청 권한 또는 관리자 권한이 필요합니다.")
        if status is not None and status not in _STATUSES:
            raise HTTPException(422, "요청 상태를 확인하세요.")
        owner = None
        if role == "request" or mine:
            actor = _actor(accounts, authorization, "request" if role == "request" else "admin")
            owner = actor["user_id"]
        cutoff = normalize_ts(clock()) if overdue else None
        total, items = repo.list_software_requests(requester_id=owner, status=status, q=q.strip(),
            unassigned=unassigned, overdue_before=cutoff, offset=(page - 1) * page_size, limit=page_size)
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
        except ConflictError:
            raise HTTPException(409, "요청이 다른 사용자에 의해 변경되었습니다. 최신 이력을 다시 불러오세요.") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    return router


def _apply_action(repo: InventoryRepository, request_id: int, body: RequestAction,
                  actor_id: str, role: str, now: str) -> dict:
    item = repo.get_software_request(request_id)
    if item is None:
        raise HTTPException(404, "요청을 찾을 수 없습니다.")
    if item["revision"] != body.expected_revision:
        raise HTTPException(409, "요청이 다른 사용자에 의해 변경되었습니다. 최신 이력을 다시 불러오세요.")
    if role == "request" and item["requester_id"] != actor_id:
        raise HTTPException(404, "요청을 찾을 수 없습니다.")
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
        if not any(a["state"] == "active" and a["valid_until"] >= now for a in item["approvals"]):
            raise HTTPException(409, "현재 유효한 승인 범위가 없습니다.")
        values.update(decision_reason=reason)
        revoke = True
    else:
        raise HTTPException(422, "요청 작업을 확인하세요.")

    repo.update_software_request(request_id, body.expected_revision, values, actor_id, action, reason,
                                 detail, now, approvals=approvals, revoke_approvals=revoke)
    result = repo.get_software_request(request_id)
    for approval in result["approvals"]:
        approval["effective_state"] = ("revoked" if approval["state"] == "revoked" else
            "expired" if approval["valid_until"] < now else "active")
    return result
