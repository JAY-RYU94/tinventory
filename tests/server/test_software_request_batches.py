"""호스트별 소프트웨어 요청 묶음과 원자적 개별·일괄 결정을 검증한다."""
import pytest
from fastapi.testclient import TestClient

from swinventory.common.models import PackageRecord
from swinventory.server.app import ApiSettings, create_app
from swinventory.server.repo.base import ConflictError
from tests.server.conftest import make_snapshot
from tests.server.test_api import AD, ING, RD

PASSWORD = "batch-test-password-long"
JWT_KEY = "software-batch-test-key-" + "z" * 40


@pytest.fixture
def client(repo, clock):
    return TestClient(create_app(repo, ApiSettings(ingest_tokens=("ing-tok",), read_tokens=("read-tok",),
        admin_tokens=("adm-tok",)), clock=clock, env={"SWINV_JWT_SECRET": JWT_KEY}))


def _user(client, username: str, role: str) -> dict:
    response = client.post("/v1/users", headers=AD,
        json={"username": username, "password": PASSWORD, "role": role})
    assert response.status_code == 201, response.text
    return response.json()


def _login(client, username: str) -> dict:
    response = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def _seed(client):
    for host_id in ("host-a", "host-b"):
        response = client.post("/v1/ingest", headers=ING, json=make_snapshot(host_id=host_id,
            hostname=f"{host_id}.example", packages=[
                PackageRecord("dpkg", "CorpDesk", "1.2.3", "amd64"),
                PackageRecord("dpkg", "CorpNotes", "4.5", "amd64"),
                PackageRecord("dpkg", "CorpWrite", "9.0", "amd64"),
                PackageRecord("dpkg", "CorpMail", "3.1", "amd64"),
                PackageRecord("dpkg", "libengine-dev", "2.0", "amd64"),
            ]).to_dict())
        assert response.status_code == 200, response.text


def _classify(client, admin, name: str, category: str = "business_app"):
    existing = client.get("/v1/software-products", headers=admin, params={"q": name}).json()["items"]
    current = next((row for row in existing if row["name"] == name and row["source"] == "dpkg"), None)
    values = {
        "source": "dpkg", "name": name, "arch": "amd64", "category": category,
        "product_name": name, "publisher": "Example", "evidence": "제품과 사용 범위를 확인했습니다.",
    }
    if current:
        values["expected_revision"] = current["revision"]
    response = client.put("/v1/software-products/classification", headers=admin, json=values)
    assert response.status_code == 200, response.text


def _batch_body(host_id="host-a", items=None):
    return {"host_id": host_id, "items": items or [
        {"source": "dpkg", "name": "CorpDesk", "arch": "amd64", "version": "1.2.3"},
        {"source": "dpkg", "name": "CorpNotes", "arch": "amd64", "version": "4.5"},
    ], "purpose": "고객 문서 작성과 내부 업무에 사용합니다.",
        "license_evidence": "계약서 LIC-2026-4와 사용권 범위를 확인했습니다."}


def _setup(client):
    _seed(client)
    admin_user = _user(client, "batch-admin", "admin")
    requester = _user(client, "batch-requester", "request")
    admin, request_headers = _login(client, "batch-admin"), _login(client, "batch-requester")
    for name in ("CorpDesk", "CorpNotes", "CorpWrite", "CorpMail"):
        _classify(client, admin, name)
    assert client.put(f"/v1/software-request-scopes/{requester['id']}", headers=admin,
        json={"host_ids": ["host-a"]}).status_code == 200
    return admin_user, requester, admin, request_headers


def test_batch_create_is_host_scoped_private_and_atomic_on_invalid_item(client):
    admin_user, requester, admin, request_headers = _setup(client)
    response = client.post("/v1/software-request-batches", headers=request_headers, json=_batch_body())
    assert response.status_code == 201, response.text
    batch = response.json()
    assert batch["batch_no"].startswith("SWB-")
    assert batch["host_id"] == "host-a" and batch["requester_id"] == requester["id"]
    assert batch["status"] == "submitted" and batch["status_counts"]["submitted"] == 2
    assert batch["pending_count"] == 2 and batch["terminal_count"] == 0
    assert len(batch["items"]) == 2
    for item in batch["items"]:
        assert item["host_ids"] == ["host-a"]
        assert item["purpose"] == batch["purpose"]
        assert item["license_evidence"] == batch["license_evidence"]
        assert item["current_installed"] is True
        assert item["approval_status"] == "not_active"
        assert item["security_impact"]["status"] == "not_assessed"

    # Invalid classification rejects the whole batch; its valid first child is not left behind.
    _classify(client, admin, "libengine-dev", category="development_dependency")
    invalid = _batch_body(items=[
        {"source": "dpkg", "name": "CorpWrite", "arch": "amd64", "version": "9.0"},
        {"source": "dpkg", "name": "libengine-dev", "arch": "amd64", "version": "2.0"},
    ])
    child_count_before = client.get("/v1/software-requests", headers=admin).json()["total"]
    denied = client.post("/v1/software-request-batches", headers=request_headers, json=invalid)
    assert denied.status_code == 422
    listed = client.get("/v1/software-request-batches", headers=admin)
    assert listed.status_code == 200 and listed.json()["total"] == 1
    assert client.get("/v1/software-requests", headers=admin).json()["total"] == child_count_before

    # Another requester's duplicate cannot disclose a private request id or rationale.
    other = _user(client, "other-batch-requester", "request")
    other_headers = _login(client, "other-batch-requester")
    assert client.put(f"/v1/software-request-scopes/{other['id']}", headers=admin,
        json={"host_ids": ["host-a"]}).status_code == 200
    duplicate = client.post("/v1/software-request-batches", headers=other_headers, json=_batch_body(items=[
        {"source": "dpkg", "name": "CorpDesk", "arch": "amd64", "version": "1.2.3"},
    ]))
    assert duplicate.status_code == 409
    assert batch["items"][0]["request_no"] not in duplicate.text
    assert "고객 문서 작성" not in duplicate.text

    assert client.get(f"/v1/software-request-batches/{batch['id']}", headers=request_headers).status_code == 200
    assert client.get(f"/v1/software-request-batches/{batch['id']}", headers=RD).status_code == 403
    assert client.get(f"/v1/software-request-batches/{batch['id']}", headers=_login(client, "other-batch-requester")).status_code == 404
    assert client.get(f"/v1/software-request-batches/{batch['id']}", headers=admin).json()["requester_id"] == requester["id"]
    summary = client.get("/v1/hosts/host-a/software-summary", headers=request_headers).json()
    desk = next(item for item in summary["items"] if item["name"] == "CorpDesk")
    assert desk["request_id"] == batch["items"][0]["id"] and desk["batch_id"] == batch["id"]
    read_summary = client.get("/v1/hosts/host-a/software-summary", headers=RD).json()
    read_desk = next(item for item in read_summary["items"] if item["name"] == "CorpDesk")
    assert "request_id" not in read_desk and "batch_id" not in read_desk and "request_status" not in read_desk
    # Host scope is exact; the same installed tuple outside the grant is rejected.
    outside = client.post("/v1/software-request-batches", headers=request_headers,
        json=_batch_body(host_id="host-b", items=[{"source": "dpkg", "name": "CorpWrite",
            "arch": "amd64", "version": "9.0"}]))
    assert outside.status_code == 403
    for changed in (
        {"source": "rpm", "name": "CorpWrite", "arch": "amd64", "version": "9.0"},
        {"source": "dpkg", "name": "CorpWrite", "arch": "arm64", "version": "9.0"},
        {"source": "dpkg", "name": "CorpWrite", "arch": "amd64", "version": "9.1"},
        {"source": "dpkg", "name": "CorpWrite", "arch": "amd64", "version": ""},
    ):
        rejected = client.post("/v1/software-request-batches", headers=request_headers,
            json=_batch_body(items=[changed]))
        assert rejected.status_code == 422
    short_purpose = _batch_body(items=[{"source": "dpkg", "name": "CorpWrite", "arch": "amd64", "version": "9.0"}])
    short_purpose["purpose"] = "x    "
    assert client.post("/v1/software-request-batches", headers=request_headers, json=short_purpose).status_code == 422
    # Request-role credentials must be a user's personal session, not an API token.
    assert client.post("/v1/software-request-batches", headers=ING, json=_batch_body()).status_code in {401, 403}
    assert client.post("/v1/software-request-batches", headers=AD, json=_batch_body()).status_code in {401, 403}


def test_batch_selected_actions_are_per_item_and_atomic(client):
    admin_user, requester, admin, request_headers = _setup(client)
    created = client.post("/v1/software-request-batches", headers=request_headers, json=_batch_body()).json()
    ids = [item["id"] for item in created["items"]]
    assigned = client.post(f"/v1/software-request-batches/{created['id']}/actions", headers=admin, json={
        "action": "assign", "items":[{"request_id": item["id"], "expected_revision": item["revision"]}
                                        for item in created["items"]],
        "assignee_id": admin_user["id"], "due_at": "2026-12-01T12:00:00Z",
    })
    assert assigned.status_code == 200, assigned.text
    assert all(item["status"] == "reviewing" and item["revision"] == 2 for item in assigned.json()["items"])
    token_action = client.post(f"/v1/software-request-batches/{created['id']}/actions", headers=AD, json={
        "action": "reject", "items": [{"request_id": ids[0], "expected_revision": 2}],
        "reason": "API token은 결정 세션이 아닙니다.",
    })
    assert token_action.status_code == 403

    # One stale selected revision rejects the complete multi-item mutation.
    stale = client.post(f"/v1/software-request-batches/{created['id']}/actions", headers=admin, json={
        "action": "approve", "reason": "업무와 사용권을 확인했습니다.", "approval_until": "2027-01-01T00:00:00Z",
        "items": [{"request_id": ids[0], "expected_revision": 2},
                  {"request_id": ids[1], "expected_revision": 1}],
    })
    assert stale.status_code == 409
    unchanged = client.get(f"/v1/software-request-batches/{created['id']}", headers=admin).json()
    assert all(item["status"] == "reviewing" and item["revision"] == 2 for item in unchanged["items"])
    assert all(item["approvals"] == [] for item in unchanged["items"])
    # A selected child from a different batch is rejected without changing either batch.
    other_batch = client.post("/v1/software-request-batches", headers=request_headers,
        json=_batch_body(items=[{"source": "dpkg", "name": "CorpWrite", "arch": "amd64", "version": "9.0"}])).json()
    foreign = client.post(f"/v1/software-request-batches/{created['id']}/actions", headers=admin, json={
        "action": "reject", "reason": "외부 항목 테스트", "items": [
            {"request_id": other_batch["items"][0]["id"], "expected_revision": 1}],
    })
    assert foreign.status_code == 404
    assert client.get(f"/v1/software-request-batches/{other_batch['id']}", headers=admin).json()["items"][0]["status"] == "submitted"

    # Different decisions remain possible within the same host batch.
    approved = client.post(f"/v1/software-request-batches/{created['id']}/actions", headers=admin, json={
        "action": "approve", "reason": "승인 대상의 필요와 사용권을 확인했습니다.",
        "approval_until": "2027-01-01T00:00:00Z",
        "items": [{"request_id": ids[0], "expected_revision": 2}],
    })
    assert approved.status_code == 200, approved.text
    rejected = client.post(f"/v1/software-request-batches/{created['id']}/actions", headers=admin, json={
        "action": "reject", "reason": "이 제품은 이번 업무 범위에서 제외합니다.",
        "items": [{"request_id": ids[1], "expected_revision": 2}],
    })
    assert rejected.status_code == 200, rejected.text
    batch = rejected.json()
    assert batch["status"] == "mixed" and batch["status_counts"]["approved"] == 1
    assert batch["status_counts"]["rejected"] == 1
    assert batch["pending_count"] == 0 and batch["terminal_count"] == 2
    by_name = {item["name"]: item for item in batch["items"]}
    assert by_name["CorpDesk"]["status"] == "approved"
    assert by_name["CorpDesk"]["approval_status"] == "active"
    assert by_name["CorpDesk"]["approvals"][0]["host_id"] == "host-a"
    assert all(approval["host_id"] == "host-a" for item in batch["items"] for approval in item["approvals"])
    assert by_name["CorpNotes"]["status"] == "rejected"
    assert by_name["CorpNotes"]["approval_status"] == "not_active"

    # A second batch bulk-approves all selected children; host-b stays untouched despite the same installs.
    all_batch = client.post("/v1/software-request-batches", headers=request_headers, json=_batch_body(items=[
        {"source": "dpkg", "name": "CorpNotes", "arch": "amd64", "version": "4.5"},
        {"source": "dpkg", "name": "CorpMail", "arch": "amd64", "version": "3.1"},
    ])).json()
    assigned_all = client.post(f"/v1/software-request-batches/{all_batch['id']}/actions", headers=admin, json={
        "action": "assign", "items": [{"request_id": item["id"], "expected_revision": 1}
                                          for item in all_batch["items"]],
        "assignee_id": admin_user["id"], "due_at": "2026-12-01T12:00:00Z",
    })
    assert assigned_all.status_code == 200
    approved_all = client.post(f"/v1/software-request-batches/{all_batch['id']}/actions", headers=admin, json={
        "action": "approve", "items": [{"request_id": item["id"], "expected_revision": 2}
                                           for item in all_batch["items"]],
        "reason": "전체 선택한 제품을 확인했습니다.", "approval_until": "2027-01-01T00:00:00Z",
    })
    assert approved_all.status_code == 200
    assert approved_all.json()["status_counts"]["approved"] == 2
    assert all([approval["host_id"] for approval in item["approvals"]] == ["host-a"]
               for item in approved_all.json()["items"])


def test_batch_approval_rechecks_exact_current_classification_and_installation(client, clock):
    admin_user, requester, admin, request_headers = _setup(client)
    created = client.post("/v1/software-request-batches", headers=request_headers, json=_batch_body(items=[
        {"source": "dpkg", "name": "CorpWrite", "arch": "amd64", "version": "9.0"},
    ])).json()
    child = created["items"][0]
    assigned = client.post(f"/v1/software-request-batches/{created['id']}/actions", headers=admin, json={
        "action": "assign", "items": [{"request_id": child["id"], "expected_revision": 1}],
        "assignee_id": admin_user["id"], "due_at": "2026-12-01T12:00:00Z",
    })
    assert assigned.status_code == 200

    # Reclassification after request creation invalidates approval, including through the legacy child URL.
    _classify(client, admin, "CorpWrite", category="development_dependency")
    action = {"action": "approve", "expected_revision": 2, "reason": "업무 범위 확인",
              "approval_until": "2027-01-01T00:00:00Z"}
    blocked = client.post(f"/v1/software-requests/{child['id']}/actions", headers=admin, json=action)
    assert blocked.status_code == 409
    still_open = client.get(f"/v1/software-request-batches/{created['id']}", headers=admin).json()["items"][0]
    assert still_open["status"] == "reviewing" and still_open["approvals"] == []

    # Restoring classification does not let a stale inventory row authorize approval after removal.
    _classify(client, admin, "CorpWrite")
    clock.advance(seconds=1)
    removed = client.post("/v1/ingest", headers=ING, json=make_snapshot(host_id="host-a", at=clock.now,
        hostname="host-a.example", packages=[PackageRecord("dpkg", "CorpDesk", "1.2.3", "amd64"),
            PackageRecord("dpkg", "CorpNotes", "4.5", "amd64"),
            PackageRecord("dpkg", "libengine-dev", "2.0", "amd64")]).to_dict())
    assert removed.status_code == 200
    blocked = client.post(f"/v1/software-requests/{child['id']}/actions", headers=admin, json=action)
    assert blocked.status_code == 409
    batch_item = client.get(f"/v1/software-request-batches/{created['id']}", headers=admin).json()["items"][0]
    assert batch_item["status"] == "reviewing" and batch_item["current_installed"] is False
    assert batch_item["approvals"] == []


def test_batch_queue_filters_aggregate_and_sort_before_pagination(client, repo):
    admin_user, requester, admin, request_headers = _setup(client)
    second_admin = _user(client, "second-batch-admin", "admin")
    second_admin_headers = _login(client, "second-batch-admin")
    host_batch = client.post("/v1/software-request-batches", headers=request_headers, json=_batch_body(items=[
        {"source": "dpkg", "name": "CorpDesk", "arch": "amd64", "version": "1.2.3"},
        {"source": "dpkg", "name": "CorpNotes", "arch": "amd64", "version": "4.5"},
    ])).json()
    changed = client.post(f"/v1/software-request-batches/{host_batch['id']}/actions", headers=admin, json={
        "action": "request_changes", "reason": "CorpDesk 사용 범위 근거를 보완해 주세요.",
        "items": [{"request_id": host_batch["items"][0]["id"], "expected_revision": 1}],
    })
    assert changed.status_code == 200
    first_assigned = client.post(f"/v1/software-request-batches/{host_batch['id']}/actions", headers=admin, json={
        "action": "assign", "assignee_id": admin_user["id"], "due_at": "2026-12-20T12:00:00Z",
        "items": [{"request_id": host_batch["items"][1]["id"], "expected_revision": 1}],
    })
    assert first_assigned.status_code == 200
    repo.upsert_nvd_vulnerabilities([{
        "cve_id": "CVE-2026-9911", "description": "CorpNotes sample impact", "published_at": None,
        "modified_at": None, "cvss_score": "9.8", "cvss_severity": "CRITICAL",
        "cvss_metrics": {}, "nvd_status": "Analyzed", "references": [], "configurations": [],
    }], fetched_at="2026-11-24T00:00:00Z")
    match = client.put("/v1/vulnerabilities/matches", headers=admin, json={
        "cve_id": "CVE-2026-9911", "source": "dpkg", "name": "CorpNotes", "arch": "amd64",
        "status": "affected_confirmed", "evidence": "공급자 보안 공지에서 영향을 확인했습니다.",
        "conditions": "정확 버전 4.5", "affected_versions": ["4.5"],
    })
    assert match.status_code == 200, match.text
    # 서로 다른 child가 각 필터를 따로 만족해도 같은 batch로 묶여 검색되면 안 된다.
    assert client.get("/v1/software-request-batches", headers=admin,
        params={"status": "needs_changes", "security_impact": "confirmed"}).json()["total"] == 0
    assert client.get("/v1/software-request-batches", headers=admin,
        params={"status": "reviewing", "security_impact": "confirmed"}).json()["total"] == 1
    batch_b = client.post("/v1/software-request-batches", headers=request_headers, json=_batch_body(items=[
        {"source": "dpkg", "name": "CorpWrite", "arch": "amd64", "version": "9.0"},
    ])).json()
    assert client.post(f"/v1/software-request-batches/{batch_b['id']}/actions", headers=admin, json={
        "action": "assign", "assignee_id": admin_user["id"], "due_at": "2026-12-20T12:00:00Z",
        "items": [{"request_id": batch_b["items"][0]["id"], "expected_revision": 1}],
    }).status_code == 200
    batch_c = client.post("/v1/software-request-batches", headers=request_headers, json=_batch_body(items=[
        {"source": "dpkg", "name": "CorpMail", "arch": "amd64", "version": "3.1"},
    ])).json()
    assert client.post(f"/v1/software-request-batches/{batch_c['id']}/actions", headers=second_admin_headers, json={
        "action": "assign", "assignee_id": second_admin["id"], "due_at": "2026-12-10T12:00:00Z",
        "items": [{"request_id": batch_c["items"][0]["id"], "expected_revision": 1}],
    }).status_code == 200

    page1 = client.get("/v1/software-request-batches", headers=admin,
        params={"sort": "due", "direction": "asc", "page": 1, "page_size": 1}).json()
    page2 = client.get("/v1/software-request-batches", headers=admin,
        params={"sort": "due", "direction": "asc", "page": 2, "page_size": 1}).json()
    page3 = client.get("/v1/software-request-batches", headers=admin,
        params={"sort": "due", "direction": "asc", "page": 3, "page_size": 1}).json()
    assert [page1["items"][0]["id"], page2["items"][0]["id"], page3["items"][0]["id"]] == [
        batch_c["id"], batch_b["id"], host_batch["id"]]
    assert page1["total"] == page2["total"] == page3["total"] == 3

    mine = client.get("/v1/software-request-batches", headers=admin,
        params={"scope": "assigned", "assigned_to_me": "true", "page_size": 50}).json()
    assert mine["total"] == 2
    assert {row["id"] for row in mine["items"]} == {batch_b["id"], host_batch["id"]}
    needs_changes = client.get("/v1/software-request-batches", headers=admin,
        params={"status": "needs_changes"}).json()
    assert needs_changes["total"] == 1
    aggregate = needs_changes["items"][0]
    assert aggregate["id"] == host_batch["id"] and aggregate["status"] == "mixed"
    assert aggregate["status_counts"]["needs_changes"] == 1
    assert aggregate["pending_count"] == 1 and aggregate["open_count"] == 2
    assert aggregate["terminal_count"] == 0 < aggregate["item_count"]


def test_batch_action_database_failure_rolls_back_prior_child_writes(client, repo):
    admin_user, requester, admin, request_headers = _setup(client)
    created = client.post("/v1/software-request-batches", headers=request_headers,
        json=_batch_body()).json()
    ids = [item["id"] for item in created["items"]]
    assigned = client.post(f"/v1/software-request-batches/{created['id']}/actions", headers=admin, json={
        "action": "assign", "assignee_id": admin_user["id"], "due_at": "2026-12-01T12:00:00Z",
        "items": [{"request_id": item_id, "expected_revision": 1} for item_id in ids],
    })
    assert assigned.status_code == 200, assigned.text
    before = {item_id: repo.get_software_request(item_id) for item_id in ids}
    items = {item["id"]: item for item in assigned.json()["items"]}
    valid = {
        "request_id": ids[0], "expected_revision": 2, "action": "reject",
        "values": {"status": "rejected"}, "reason": "범위 밖 제품입니다.", "detail": {},
        "approvals": [], "revoke_approvals": False,
    }
    install = items[ids[1]]
    invalid_approval = {
        "request_id": ids[1], "expected_revision": 2, "action": "approve",
        "values": {"status": "approved"}, "reason": "업무와 사용권을 확인했습니다.", "detail": {},
        "approvals": [{
            "request_id": ids[1], "source": install["source"], "name": install["name"],
            "arch": install["arch"], "version": install["version"], "host_id": "host-a",
            "state": "active", "valid_from": "2026-11-24T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z", "decided_by": "missing-user",
            "reason": "업무와 사용권을 확인했습니다.", "ended_at": None, "end_reason": "",
        }], "revoke_approvals": False,
    }
    with pytest.raises(ConflictError):
        repo.update_software_request_batch(created["id"], [valid, invalid_approval], admin_user["id"],
            "2026-11-24T00:00:00Z")
    after = {item_id: repo.get_software_request(item_id) for item_id in ids}
    for item_id in ids:
        assert after[item_id]["status"] == before[item_id]["status"] == "reviewing"
        assert after[item_id]["revision"] == before[item_id]["revision"] == 2
        assert after[item_id]["history"] == before[item_id]["history"]
        assert after[item_id]["approvals"] == before[item_id]["approvals"] == []
