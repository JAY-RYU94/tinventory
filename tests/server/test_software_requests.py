"""업무용 SW 분류와 조직 사용 승인 요청의 서버 권한·이력 계약."""
import pytest
from fastapi.testclient import TestClient

from swinventory.common.models import PackageRecord
from swinventory.server.app import ApiSettings, create_app
from tests.server.test_api import AD, ING, RD
from tests.server.conftest import make_snapshot

PASSWORD = "long-test-password-2026"
KEY = "software-request-test-key-" + "x" * 40


@pytest.fixture
def client(repo, clock):
    return TestClient(create_app(repo, ApiSettings(ingest_tokens=("ing-tok",), read_tokens=("read-tok",),
        admin_tokens=("adm-tok",)), clock=clock, env={"SWINV_JWT_SECRET": KEY}))


def _user(client, username: str, role: str) -> dict:
    response = client.post("/v1/users", headers=AD, json={"username": username, "password": PASSWORD, "role": role})
    assert response.status_code == 201, response.text
    return response.json()


def _login(client, username: str) -> dict:
    response = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def _seed(client):
    for host in ("host-a", "host-b"):
        response = client.post("/v1/ingest", headers=ING, json=make_snapshot(host_id=host,
            packages=[PackageRecord("dpkg", "CorpDesk", "1.2.3", "amd64"),
                      PackageRecord("dpkg", "libengine-dev", "2.0", "amd64")]).to_dict())
        assert response.status_code == 200, response.text


def _classify(client, admin_headers, name="CorpDesk", category="business_app"):
    response = client.put("/v1/software-products/classification", headers=admin_headers, json={
        "source": "dpkg", "name": name, "arch": "amd64", "category": category,
        "product_name": "CorpDesk", "publisher": "Example Corp", "evidence": "제품 소유자와 공급자 확인",
    })
    assert response.status_code == 200, response.text
    return response.json()


def test_read_only_and_unclassified_packages_cannot_request(client):
    _seed(client)
    requester = _user(client, "requester", "request")
    request_headers = _login(client, "requester")
    assert client.get("/v1/whoami", headers=request_headers).json() == {"role": "request"}
    assert client.get("/v1/software-products", headers=RD).status_code == 200
    assert client.get("/v1/software-products", headers=RD).json()["items"][0]["category"] == "needs_review"
    body = {"source": "dpkg", "name": "CorpDesk", "arch": "amd64", "version": "1.2.3",
            "purpose": "고객 문서 작성", "host_ids": ["host-a"]}
    assert client.post("/v1/software-requests", headers=RD, json=body).status_code == 403
    # 업무용으로 확인되지 않은 앱과 개발 의존성은 요청 API에서도 차단한다.
    scope = client.put(f"/v1/software-request-scopes/{requester['id']}", headers=AD,
                       json={"host_ids": ["host-a"]})
    assert scope.status_code == 403  # 정적 관리자 토큰에는 개인 감사 주체가 없으므로 권한 승격을 허용하지 않는다
    assert client.post("/v1/software-requests", headers=request_headers, json=body).status_code == 422


def test_request_scope_queue_revisions_decisions_and_approval_expiry(client):
    _seed(client)
    admin = _user(client, "sw-admin", "admin")
    requester = _user(client, "requester", "request")
    admin_headers = _login(client, "sw-admin")
    request_headers = _login(client, "requester")
    _classify(client, admin_headers)
    assert client.put(f"/v1/software-request-scopes/{requester['id']}", headers=admin_headers,
                      json={"host_ids": ["host-a"]}).status_code == 200

    body = {"source": "dpkg", "name": "CorpDesk", "arch": "amd64", "version": "1.2.3",
            "purpose": "고객 문서 작성", "host_ids": ["host-a"]}
    removed_field = {**body, "license_evidence": "예전 필드"}
    assert client.post("/v1/software-requests", headers=request_headers, json=removed_field).status_code == 422
    created = client.post("/v1/software-requests", headers=request_headers, json=body)
    assert created.status_code == 201, created.text
    item = created.json()
    assert "license_evidence" not in item
    assert item["request_no"].startswith("SW-") and item["status"] == "submitted"
    assert client.post("/v1/software-requests", headers=request_headers, json=body).status_code == 409
    assert client.get("/v1/software-requests", headers=RD).status_code == 403
    assert client.get(f"/v1/software-requests/{item['id']}", headers=RD).status_code == 403

    other = _user(client, "other-requester", "request")
    other_headers = _login(client, "other-requester")
    assert client.put(f"/v1/software-request-scopes/{other['id']}", headers=admin_headers,
                      json={"host_ids": ["host-b"]}).status_code == 200
    assert client.get(f"/v1/software-requests/{item['id']}", headers=other_headers).status_code == 404
    outside = {**body, "host_ids": ["host-b"]}
    assert client.post("/v1/software-requests", headers=request_headers, json=outside).status_code == 403

    due = "2026-11-06T12:00:00+09:00"
    assigned = client.post(f"/v1/software-requests/{item['id']}/actions", headers=admin_headers,
        json={"action": "assign", "expected_revision": 1, "assignee_id": admin["id"], "due_at": due})
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["status"] == "reviewing" and assigned.json()["revision"] == 2
    changed = client.post(f"/v1/software-requests/{item['id']}/actions", headers=admin_headers,
        json={"action": "request_changes", "expected_revision": 2, "reason": "사용 목적을 구체적으로 적어 주세요."})
    assert changed.status_code == 200 and changed.json()["status"] == "needs_changes"
    resubmitted = client.post(f"/v1/software-requests/{item['id']}/actions", headers=request_headers,
        json={"action": "resubmit", "expected_revision": 3, "purpose": "고객 문서 편집"})
    assert resubmitted.status_code == 200 and resubmitted.json()["id"] == item["id"]
    assert resubmitted.json()["revision"] == 4 and resubmitted.json()["status"] == "submitted"
    assert "license_evidence" not in resubmitted.json()
    assert len(resubmitted.json()["history"]) == 4
    # 오래된 편집 화면의 revision은 결정을 덮어쓰지 못한다.
    stale = client.post(f"/v1/software-requests/{item['id']}/actions", headers=admin_headers,
        json={"action": "assign", "expected_revision": 2, "assignee_id": admin["id"], "due_at": due})
    assert stale.status_code == 409

    assigned = client.post(f"/v1/software-requests/{item['id']}/actions", headers=admin_headers,
        json={"action": "assign", "expected_revision": 4, "assignee_id": admin["id"], "due_at": due})
    assert assigned.status_code == 200
    until = "2027-11-30T23:59:59+09:00"
    approved = client.post(f"/v1/software-requests/{item['id']}/actions", headers=admin_headers,
        json={"action": "approve", "expected_revision": 5, "reason": "업무상 필요를 확인했습니다.",
              "approval_until": until})
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert approved.json()["approvals"][0]["effective_state"] == "active"
    already = client.post("/v1/software-requests", headers=request_headers, json=body)
    assert already.status_code == 409 and already.json()["detail"] == "유효한 승인이 이미 있습니다."
    cancelled = client.post(f"/v1/software-requests/{item['id']}/actions", headers=admin_headers,
        json={"action": "revoke_approval", "expected_revision": 6, "reason": "계약 종료"})
    assert cancelled.status_code == 200
    assert cancelled.json()["approvals"][0]["effective_state"] == "revoked"


def test_scope_requires_admin_session_and_business_app_classification(client):
    _seed(client)
    admin = _user(client, "sw-admin", "admin")
    requester = _user(client, "requester", "request")
    admin_headers = _login(client, "sw-admin")
    request_headers = _login(client, "requester")
    _classify(client, admin_headers, name="libengine-dev", category="development_dependency")
    assert client.put(f"/v1/software-request-scopes/{requester['id']}", headers=AD,
                      json={"host_ids": ["host-a"]}).status_code == 403
    assert client.put(f"/v1/software-request-scopes/{requester['id']}", headers=admin_headers,
                      json={"host_ids": ["host-a"]}).status_code == 200
    body = {"source": "dpkg", "name": "libengine-dev", "arch": "amd64", "version": "2.0",
            "purpose": "업무용 개발도구 필요", "host_ids": ["host-a"]}
    response = client.post("/v1/software-requests", headers=request_headers, json=body)
    assert response.status_code == 422
    assert client.put(f"/v1/software-request-scopes/{requester['id']}", headers=admin_headers,
                      json={"host_ids": ["unregistered"]}).status_code == 422
