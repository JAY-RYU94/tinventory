"""v4 UI read projections: exact product scope, role boundaries and full-list queue order."""
from fastapi.testclient import TestClient
from sqlalchemy import update

from swinventory.common.models import PackageRecord
from swinventory.server.app import ApiSettings, create_app
from swinventory.server.timeutil import normalize_ts
from swinventory.server.repo.schema import software_approvals
from tests.server.conftest import make_snapshot, hw
from tests.server.test_api import AD, ING, RD

PASSWORD = "v4-projection-test-password"
JWT_KEY = "v4-projection-test-key-" + "q" * 40


def _client(repo, clock):
    return TestClient(create_app(repo, ApiSettings(ingest_tokens=("ing-tok",), read_tokens=("read-tok",),
        admin_tokens=("adm-tok",)), clock=clock, env={"SWINV_JWT_SECRET": JWT_KEY}))


def _user(client, name: str, role: str) -> dict:
    response = client.post("/v1/users", headers=AD,
        json={"username": name, "password": PASSWORD, "role": role})
    assert response.status_code == 201, response.text
    return response.json()


def _login(client, name: str) -> dict:
    response = client.post("/v1/auth/login", json={"username": name, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def _nvd(cve_id: str, score: str = "7.5") -> dict:
    return {"cve_id": cve_id, "description": "projection test", "published_at": None,
        "modified_at": None, "cvss_score": score, "cvss_severity": "HIGH", "cvss_metrics": {},
        "nvd_status": "Analyzed", "references": [], "configurations": []}


def _match(repo, cve_id: str, source: str, name: str, arch: str, status: str, actor_id: str, at: str,
           versions: list[str] | None = None) -> None:
    repo.update_vulnerability_match(cve_id, source, name, arch, {
        "status": status, "evidence": "vendor advisory verified", "conditions": "",
        "affected_versions": versions or [],
    }, actor_id, at, None)


def _request_values(requester_id: str, name: str, version: str = "1") -> dict:
    return {"requester_id": requester_id, "source": "dpkg", "name": name, "arch": "amd64",
        "product_name": name, "version": version, "purpose": "업무 처리에 필요합니다.",
        "assignee_id": None, "due_at": None,
        "approval_until": None, "decision_reason": ""}


def test_exact_vulnerability_filters_counts_and_observed_installations(repo, clock):
    client = _client(repo, clock)
    packages = [PackageRecord("dpkg", "CorpDesk", "1.2.3", "amd64"),
        PackageRecord("dpkg", "CorpDesk", "1.2.4", "amd64"),
        PackageRecord("rpm", "CorpDesk", "1.2.3", "x86_64")]
    assert client.post("/v1/ingest", headers=ING,
        json=make_snapshot(host_id="host-a", packages=packages, sources=("dpkg", "rpm"),
                           hardware=hw(serial="SERIAL-A")).to_dict()).status_code == 200
    assert client.post("/v1/ingest", headers=ING,
        json=make_snapshot(host_id="host-b", packages=[packages[0]]).to_dict()).status_code == 200

    admin_user = _user(client, "projection-admin", "admin")
    admin = _login(client, "projection-admin")
    at = normalize_ts(clock())
    repo.upsert_nvd_vulnerabilities([_nvd("CVE-2026-7001"), _nvd("CVE-2026-7002")], at)
    _match(repo, "CVE-2026-7001", "dpkg", "CorpDesk", "amd64", "affected_confirmed",
           admin_user["id"], at, ["1.2.3"])
    _match(repo, "CVE-2026-7002", "rpm", "CorpDesk", "x86_64", "needs_review", admin_user["id"], at)

    exact_unmatched = client.get("/v1/vulnerabilities", headers=RD, params={"host": "host-a",
        "product_source": "dpkg", "product_name": "CorpDesk", "product_arch": "amd64",
        "product_version": "1.2.4"})
    assert exact_unmatched.status_code == 200, exact_unmatched.text
    assert exact_unmatched.json()["total"] == 1
    row = exact_unmatched.json()["items"][0]
    assert row["cve_id"] == "CVE-2026-7001"
    assert row["impact_status"] == "no_observed_match"
    assert row["confirmed_host_count"] == 0 and row["no_observed_match_host_count"] == 1

    exact_confirmed = client.get("/v1/vulnerabilities", headers=RD, params={"host": "host-a",
        "product_source": "dpkg", "product_name": "CorpDesk", "product_arch": "amd64",
        "product_version": "1.2.3"}).json()
    assert [row["cve_id"] for row in exact_confirmed["items"]] == ["CVE-2026-7001"]
    assert exact_confirmed["items"][0]["impact_status"] == "confirmed"
    assert exact_confirmed["items"][0]["confirmed_host_count"] == 1
    whole_inventory = client.get("/v1/vulnerabilities", headers=RD).json()
    cve_row = next(row for row in whole_inventory["items"] if row["cve_id"] == "CVE-2026-7001")
    assert cve_row["host_count"] == cve_row["confirmed_host_count"] == 2
    assert cve_row["no_observed_match_host_count"] == 1

    exact_rpm = client.get("/v1/vulnerabilities", headers=RD, params={"host": "host-a",
        "product_source": "rpm", "product_name": "CorpDesk", "product_arch": "x86_64",
        "product_version": "1.2.3"}).json()
    assert [row["cve_id"] for row in exact_rpm["items"]] == ["CVE-2026-7002"]
    assert exact_rpm["items"][0]["impact_status"] == "needs_review"
    assert exact_rpm["items"][0]["needs_review_host_count"] == 1

    repo.create_asset({"asset_no": "ASSET-A", "kind": "physical", "serial": "SERIAL-A",
        "hostname": "retired-name", "domain": "", "ip": "", "parent_asset_id": None,
        "host_id": None, "note": "", "primary_owner": "Mina", "secondary_owner": "Jin"}, at)
    detail = client.get("/v1/vulnerabilities/CVE-2026-7001", headers=RD).json()
    dpkg_match = next(row for row in detail["matches"] if row["source"] == "dpkg")
    assert [row["version"] for row in dpkg_match["installations"]] == ["1.2.3", "1.2.3"]
    observed = next(row for row in dpkg_match["observed_installations"] if row["version"] == "1.2.4")
    assert observed["impact_status"] == "no_observed_match"
    assert observed["asset_no"] == "ASSET-A"
    assert (observed["primary_owner"], observed["secondary_owner"]) == ("Mina", "Jin")
    assert observed["last_seen"] is not None


def test_host_software_summary_keeps_approval_request_and_classification_distinct(repo, clock):
    client = _client(repo, clock)
    openapi = client.get("/openapi.json").json()
    assert openapi["paths"]["/v1/hosts/{host_id}/software-summary"]["get"]["x-required-role"] == "read"
    assert openapi["paths"]["/v1/software-requests"]["get"]["x-required-role"] == "request"
    packages = [PackageRecord("dpkg", "CorpDesk", "1.2.3", "amd64"),
        PackageRecord("dpkg", "CorpDesk", "1.2.4", "amd64"),
        PackageRecord("rpm", "CorpDesk", "1.2.3", "x86_64"),
        PackageRecord("dpkg", "Unclassified", "5", "amd64")]
    for host_id in ("host-a", "host-b"):
        assert client.post("/v1/ingest", headers=ING,
            json=make_snapshot(host_id=host_id, packages=packages[:1]).to_dict()).status_code == 200
    clock.advance(seconds=1)
    assert client.post("/v1/ingest", headers=ING,
        json=make_snapshot(host_id="host-a", packages=packages, sources=("dpkg", "rpm"),
                           at=clock.now).to_dict()).status_code == 200

    admin_user = _user(client, "summary-admin", "admin")
    requester = _user(client, "summary-requester", "request")
    admin, request_headers = _login(client, "summary-admin"), _login(client, "summary-requester")
    for source, name, arch, category in (
        ("dpkg", "CorpDesk", "amd64", "business_app"),
        ("rpm", "CorpDesk", "x86_64", "development_dependency"),
    ):
        response = client.put("/v1/software-products/classification", headers=admin, json={
            "source": source, "name": name, "arch": arch, "category": category,
            "product_name": "CorpDesk", "publisher": "Example", "evidence": "분류 근거를 확인했습니다.",
        })
        assert response.status_code == 200, response.text
    assert client.put(f"/v1/software-request-scopes/{requester['id']}", headers=admin,
        json={"host_ids": ["host-a", "host-b"]}).status_code == 200

    body = {"source": "dpkg", "name": "CorpDesk", "arch": "amd64", "version": "1.2.3",
        "purpose": "고객 지원 업무를 처리합니다.", "host_ids": ["host-a"]}
    created = client.post("/v1/software-requests", headers=request_headers, json=body)
    assert created.status_code == 201, created.text
    assert "license_evidence" not in created.json()
    request_id = created.json()["id"]
    assigned = client.post(f"/v1/software-requests/{request_id}/actions", headers=admin, json={
        "action": "assign", "expected_revision": 1, "assignee_id": admin_user["id"],
        "due_at": "2026-11-20T00:00:00Z"})
    assert assigned.status_code == 200, assigned.text
    approved = client.post(f"/v1/software-requests/{request_id}/actions", headers=admin, json={
        "action": "approve", "expected_revision": 2, "reason": "업무상 필요를 확인했습니다.",
        "approval_until": "2026-12-01T00:00:00Z"})
    assert approved.status_code == 200, approved.text

    as_admin = client.get("/v1/hosts/host-a/software-summary", headers=admin).json()
    by_key = {(row["source"], row["name"], row["arch"], row["version"]): row for row in as_admin["items"]}
    exact = by_key[("dpkg", "CorpDesk", "amd64", "1.2.3")]
    assert exact["approval_status"] == "active" and exact["request_status"] == "approved"
    assert exact["request_no"].startswith("SW-")
    assert by_key[("dpkg", "CorpDesk", "amd64", "1.2.4")]["approval_status"] == "not_active"
    assert by_key[("rpm", "CorpDesk", "x86_64", "1.2.3")]["approval_status"] == "not_required"
    assert by_key[("dpkg", "Unclassified", "amd64", "5")]["approval_status"] == "classification_required"

    own = client.get("/v1/hosts/host-a/software-summary", headers=request_headers).json()
    own_exact = next(row for row in own["items"] if row["source"] == "dpkg" and row["version"] == "1.2.3")
    assert own_exact["request_status"] == "approved" and own_exact["request_no"] == exact["request_no"]
    other = _user(client, "summary-other", "request")
    other_headers = _login(client, "summary-other")
    other_view = client.get("/v1/hosts/host-a/software-summary", headers=other_headers).json()
    other_exact = next(row for row in other_view["items"] if row["source"] == "dpkg" and row["version"] == "1.2.3")
    assert other_exact["request_status"] is None and other_exact["request_no"] is None
    read_view = client.get("/v1/hosts/host-a/software-summary", headers=RD).json()
    read_exact = next(row for row in read_view["items"] if row["source"] == "dpkg" and row["version"] == "1.2.3")
    assert "request_status" not in read_exact and "request_no" not in read_exact

    # The approval date expires while the request remains approved.
    with repo._engine.begin() as connection:
        connection.execute(update(software_approvals).where(
            software_approvals.c.request_id == request_id).values(valid_until="2026-11-04T00:00:00.000000Z"))
    expired = client.get("/v1/hosts/host-a/software-summary", headers=admin).json()
    exp_exact = next(row for row in expired["items"] if row["source"] == "dpkg" and row["version"] == "1.2.3")
    assert exp_exact["approval_status"] == "not_active" and exp_exact["request_status"] == "approved"

    # A revoked approval is equally inactive even before its expiry date.
    body["host_ids"] = ["host-b"]
    second = client.post("/v1/software-requests", headers=request_headers, json=body)
    assert second.status_code == 201, second.text
    second_id = second.json()["id"]
    assigned = client.post(f"/v1/software-requests/{second_id}/actions", headers=admin, json={
        "action": "assign", "expected_revision": 1, "assignee_id": admin_user["id"],
        "due_at": "2026-11-20T00:00:00Z"})
    assert assigned.status_code == 200, assigned.text
    approved = client.post(f"/v1/software-requests/{second_id}/actions", headers=admin, json={
        "action": "approve", "expected_revision": 2, "reason": "업무상 필요를 확인했습니다.",
        "approval_until": "2026-12-01T00:00:00Z"})
    assert approved.status_code == 200, approved.text
    revoked = client.post(f"/v1/software-requests/{second_id}/actions", headers=admin, json={
        "action": "revoke_approval", "expected_revision": 3, "reason": "계약 종료"})
    assert revoked.status_code == 200, revoked.text
    host_b = client.get("/v1/hosts/host-b/software-summary", headers=admin).json()
    revoked_exact = next(row for row in host_b["items"] if row["version"] == "1.2.3")
    assert revoked_exact["approval_status"] == "not_active" and revoked_exact["request_status"] == "approved"


def test_request_queue_pending_first_filters_and_request_number_search(repo, clock):
    client = _client(repo, clock)
    packages = [PackageRecord("dpkg", f"queue-app-{index:02d}", "1", "amd64") for index in range(51)]
    assert client.post("/v1/ingest", headers=ING,
        json=make_snapshot(host_id="queue-host", packages=packages).to_dict()).status_code == 200
    requester = _user(client, "queue-requester", "request")
    admin_user = _user(client, "queue-admin", "admin")
    requester_headers = _login(client, "queue-requester")
    admin = _login(client, "queue-admin")
    at = normalize_ts(clock())

    # The only pending row is deliberately the oldest, after it 50 needs_changes rows are inserted.
    pending_id = repo.create_software_request(_request_values(requester["id"], "queue-app-00"),
        ["queue-host"], requester["id"], at)
    for index in range(1, 51):
        request_id = repo.create_software_request(_request_values(requester["id"], f"queue-app-{index:02d}"),
            ["queue-host"], requester["id"], at)
        repo.update_software_request(request_id, 1, {"status": "needs_changes", "decision_reason": "보완 필요"},
            admin_user["id"], "request_changes", "보완 필요", {}, at)

    first_page = client.get("/v1/software-requests", headers=requester_headers,
        params={"page": 1, "page_size": 50})
    assert first_page.status_code == 200, first_page.text
    assert first_page.json()["items"][0]["id"] == pending_id
    assert first_page.json()["items"][0]["security_impact"] == "not_assessed"
    assert client.get("/v1/software-requests", headers=requester_headers,
        params={"pending": "true", "security_impact": "not_assessed"}).json()["total"] == 1
    assert client.get("/v1/software-requests", headers=requester_headers,
        params={"scope": "pending", "status": "needs_changes"}).status_code == 422
    assert client.get("/v1/software-requests", headers=requester_headers,
        params={"security_impact": "made_up"}).status_code == 422
    searched = client.get("/v1/software-requests", headers=requester_headers,
        params={"q": f"SW-{pending_id:06d}"})
    assert searched.status_code == 200 and searched.json()["total"] == 1
    assert searched.json()["items"][0]["id"] == pending_id

    # A reviewing row assigned to this admin is selected by assignee, independently of requester identity.
    assigned_id = first_page.json()["items"][1]["id"]
    repo.update_software_request(assigned_id, 2, {"status": "reviewing", "assignee_id": admin_user["id"]},
        admin_user["id"], "assign", "", {}, at)
    assigned = client.get("/v1/software-requests", headers=admin, params={"assigned_to_me": "true"})
    assert assigned.status_code == 200 and [row["id"] for row in assigned.json()["items"]] == [assigned_id]
    assert client.get("/v1/software-requests", headers=admin,
        params={"assigned_to_me": "true", "mine": "true"}).status_code == 422
    sorted_queue = client.get("/v1/software-requests", headers=requester_headers,
        params={"sort": "product", "direction": "desc", "page_size": 50}).json()
    assert [row["id"] for row in sorted_queue["items"][:2]] == [assigned_id, pending_id]


def test_vulnerability_scores_sort_numerically_and_bad_legacy_score_is_null_last(repo, clock):
    client = _client(repo, clock)
    repo.upsert_nvd_vulnerabilities([
        _nvd("CVE-2026-7100", "9.8"), _nvd("CVE-2026-7101", "10.0"),
        _nvd("CVE-2026-7102", "legacy-invalid"),
    ], normalize_ts(clock()))
    response = client.get("/v1/vulnerabilities", headers=RD)
    assert response.status_code == 200, response.text
    assert [(row["cve_id"], row["cvss_score"]) for row in response.json()["items"]] == [
        ("CVE-2026-7101", "10.0"), ("CVE-2026-7100", "9.8"), ("CVE-2026-7102", "legacy-invalid")]
