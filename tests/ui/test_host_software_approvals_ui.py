"""호스트 단위 업무용 SW 묶음 요청 흐름을 실제 API와 Chrome으로 검증한다."""
from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import uvicorn
from fastapi.testclient import TestClient

from swinventory.common.models import KernelInfo, OsInfo, PackageRecord, Snapshot
from swinventory.server.app import ApiSettings, create_app
from swinventory.server.repo.sql import SqlInventoryRepository
from swinventory.server.services.ingest import IngestService

ADMIN_PASSWORD = "Host-Batch-Admin!2026"
REQUEST_PASSWORD = "Host-Batch-Request!2026"
HOST_ID = "d1" * 16
OUTSIDE_HOST_ID = "d2" * 16
UNREGISTERED_HOST_ID = "d3" * 16
ARTIFACT_DIR = Path(os.environ.get("SWINV_UI_ARTIFACT_DIR", Path(tempfile.gettempdir()) / "swinventory-ui-artifacts"))


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="function")
def host_batch_site(tmp_path):
    """요청·관리자 세션, 분류, 자산/미등록 호스트를 독립 SQLite에 준비한다."""
    root = tmp_path / "host-batches"
    root.mkdir()
    now = datetime(2026, 11, 24, 3, 0, tzinfo=timezone.utc)
    repo = SqlInventoryRepository.from_url(f"sqlite:///{root / 'host-batches.db'}")
    packages = [
        PackageRecord("dpkg", "corp-tool", "1.2.3", "amd64"),
        PackageRecord("dpkg", "inventory-agent", "4.5.6", "amd64"),
        PackageRecord("dpkg", "nginx", "1.24.0", "amd64"),
        PackageRecord("dpkg", "python3-demo", "2.4.1", "amd64"),
        PackageRecord("dpkg", "unclassified-demo", "0.9.0", "amd64"),
        PackageRecord("dpkg", "approved-demo", "3.0.0", "amd64"),
        PackageRecord("dpkg", "pending-demo", "2.0.0", "amd64"),
    ]
    for host_id, hostname, installed in (
        (HOST_ID, "batch-ui-01.corp.example", packages),
        (OUTSIDE_HOST_ID, "batch-ui-02.corp.example", packages[:2]),
        (UNREGISTERED_HOST_ID, "batch-ui-unregistered.corp.example", packages[:2]),
    ):
        snapshot = Snapshot(
            host_id=host_id,
            hostname=hostname,
            collected_at=now.isoformat(),
            agent_version="ui-test",
            os=OsInfo("debian", "Debian 12", "12"),
            kernel=KernelInfo("6.1.0", ("6.1.0",), False),
            packages=installed,
            interfaces=[], ports=[], hardware=None, containers=[], k8s=None,
            collected=["os", "kernel", "software.dpkg"], errors={},
        )
        IngestService(repo, clock=lambda: now).ingest(snapshot)

    env = {"SWINV_JWT_SECRET": "host-batch-ui-test-key-" + "x" * 40}
    settings = ApiSettings(admin_tokens=("host-batch-static-admin",))
    seed_app = create_app(repo, settings, clock=lambda: now, env=env, agent_dir=root)
    with TestClient(seed_app) as client:
        static_admin = {"Authorization": "Bearer host-batch-static-admin"}
        created_admin = client.post("/v1/users", headers=static_admin, json={
            "username": "host-batch-admin", "password": ADMIN_PASSWORD, "role": "admin",
        })
        assert created_admin.status_code == 201, created_admin.text
        created_requester = client.post("/v1/users", headers=static_admin, json={
            "username": "host-batch-requester", "password": REQUEST_PASSWORD, "role": "request",
        })
        assert created_requester.status_code == 201, created_requester.text
        created_reader = client.post("/v1/users", headers=static_admin, json={
            "username": "host-batch-reader", "password": "Host-Batch-Reader!2026", "role": "read",
        })
        assert created_reader.status_code == 201, created_reader.text
        admin_token = client.post("/v1/auth/login", json={
            "username": "host-batch-admin", "password": ADMIN_PASSWORD,
        }).json()["access_token"]
        request_token = client.post("/v1/auth/login", json={
            "username": "host-batch-requester", "password": REQUEST_PASSWORD,
        }).json()["access_token"]
        read_token = client.post("/v1/auth/login", json={
            "username": "host-batch-reader", "password": "Host-Batch-Reader!2026",
        }).json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        request_headers = {"Authorization": f"Bearer {request_token}"}
        for name, label, category in (
            ("corp-tool", "Corp Tool", "business_app"),
            ("inventory-agent", "Inventory Agent", "business_app"),
            ("nginx", "Nginx", "os_package"),
            ("python3-demo", "Python Demo", "development_dependency"),
            ("unclassified-demo", "Unclassified Demo", "needs_review"),
            ("approved-demo", "Approved Demo", "business_app"),
            ("pending-demo", "Pending Demo", "business_app"),
        ):
            classified = client.put("/v1/software-products/classification", headers=admin_headers, json={
                "source": "dpkg", "name": name, "arch": "amd64", "category": category,
                "product_name": label, "publisher": "Isolated UI fixture",
                "evidence": "격리된 브라우저 회귀 테스트용 분류입니다.",
            })
            assert classified.status_code == 200, classified.text

        asset = client.post("/v1/assets", headers=admin_headers, json={
            "asset_no": "BATCH-UI-01", "kind": "virtual", "hostname": "batch-ui-01.corp.example",
            "host_id": HOST_ID, "primary_owner": "테스트 정 담당자", "secondary_owner": "테스트 부 담당자",
        })
        assert asset.status_code == 201, asset.text
        scoped = client.put(f"/v1/software-request-scopes/{created_requester.json()['id']}",
                            headers=admin_headers, json={"host_ids": [HOST_ID, UNREGISTERED_HOST_ID]})
        assert scoped.status_code == 200, scoped.text

        # 비활성 행도 새 호스트별 요청 API와 승인 묶음에서 만든다.
        seeded_batch = client.post("/v1/software-request-batches", headers=request_headers, json={
            "host_id": HOST_ID,
            "items": [
                {"source": "dpkg", "name": "pending-demo", "arch": "amd64", "version": "2.0.0"},
                {"source": "dpkg", "name": "approved-demo", "arch": "amd64", "version": "3.0.0"},
            ],
            "purpose": "비활성 선택 행을 검증하기 위한 격리 테스트 요청입니다.",
            "license_evidence": "테스트 전용 가상 사용권 계약입니다.",
        })
        assert seeded_batch.status_code == 201, seeded_batch.text
        seeded_items = {item["name"]: item for item in seeded_batch.json()["items"]}
        approved_assignment = client.post(f"/v1/software-request-batches/{seeded_batch.json()['id']}/actions",
            headers=admin_headers, json={
                "action": "assign",
                "items": [{"request_id": seeded_items["approved-demo"]["id"], "expected_revision": 1}],
                "assignee_id": created_admin.json()["id"],
                "due_at": "2026-11-30T12:00:00+09:00",
            })
        assert approved_assignment.status_code == 200, approved_assignment.text
        approved_child = next(item for item in approved_assignment.json()["items"] if item["name"] == "approved-demo")
        approved = client.post(f"/v1/software-request-batches/{seeded_batch.json()['id']}/actions",
            headers=admin_headers, json={
                "action": "approve", "reason": "테스트용 승인",
                "approval_until": "2026-12-23T12:00:00+09:00",
                "items": [{"request_id": approved_child["id"], "expected_revision": approved_child["revision"]}],
            })
        assert approved.status_code == 200, approved.text

        # 서로 다른 영향 상태를 가진 두 선택 대상. 외부 피드 접속 없이 로컬 repo만 채운다.
        cve_id = "CVE-2026-54321"
        repo.upsert_nvd_vulnerabilities([{
            "cve_id": cve_id, "description": "Controlled batch UI fixture CVE.",
            "published_at": now.isoformat(), "modified_at": now.isoformat(),
            "cvss_score": "8.1", "cvss_severity": "HIGH", "cvss_metrics": {},
            "nvd_status": "Analyzed", "references": [], "configurations": [],
        }], now.isoformat())
        match = repo.update_vulnerability_match(cve_id, "dpkg", "corp-tool", "amd64", {
            "status": "affected_confirmed", "evidence": "격리 UI 테스트의 정확한 설치 버전과 CVE 연결",
            "conditions": "테스트 전용이며 운영 판정으로 사용하지 않음", "affected_versions": ["1.2.3"],
        }, created_admin.json()["id"], now.isoformat(), None)
        assert match["status"] == "affected_confirmed"

    app = create_app(repo, settings, clock=lambda: now, env=env, agent_dir=root)
    return {
        "app": app,
        "admin_token": admin_token,
        "request_token": request_token,
        "read_token": read_token,
        "admin_user_id": created_admin.json()["id"],
        "request_user_id": created_requester.json()["id"],
        "host_id": HOST_ID,
        "outside_host_id": OUTSIDE_HOST_ID,
        "unregistered_host_id": UNREGISTERED_HOST_ID,
        "seeded_batch_id": seeded_batch.json()["id"],
        "asset_id": asset.json()["id"],
        "repo": repo,
        "now": now,
    }


@pytest.fixture(scope="function")
def host_batch_server(host_batch_site):
    """Chrome용 loopback 서버는 브라우저 테스트에서만 실행한다."""
    app = host_batch_site["app"]
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        assert time.monotonic() < deadline, "격리된 API 서버가 시작되지 않았다"
        time.sleep(0.05)
    try:
        yield {**host_batch_site, "base": f"http://127.0.0.1:{port}"}
    finally:
        server.should_exit = True
        thread.join(10)


def _http_json(base: str, token: str, path: str, *, method: str = "GET", body: dict | None = None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(f"{base}{path}", data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
    })
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        payload = error.read()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = {"detail": payload.decode("utf-8", "replace")}
        return error.code, data


def test_batch_queue_api_is_available_to_requester(host_batch_site):
    """묶음 조회·생성의 호스트 권한과 범위 밖 거절을 실제 API로 확인한다."""
    with TestClient(host_batch_site["app"]) as client:
        response = client.get("/v1/software-request-batches", headers={
            "Authorization": f"Bearer {host_batch_site['request_token']}",
        })
        payload = response.json()
        assert response.status_code == 200, payload
        assert payload["total"] == 1
        assert len(payload["items"]) == 1
        assert payload["items"][0]["id"] == host_batch_site["seeded_batch_id"]
        assert payload["items"][0]["host_id"] == host_batch_site["host_id"]
        assert payload["items"][0]["item_count"] == 2
        assert client.get("/v1/software-request-batches", headers={
            "Authorization": f"Bearer {host_batch_site['read_token']}",
        }).status_code == 403

        created = client.post("/v1/software-request-batches", headers={
            "Authorization": f"Bearer {host_batch_site['request_token']}",
        }, json={
            "host_id": host_batch_site["host_id"],
            "items": [
                {"source": "dpkg", "name": "corp-tool", "arch": "amd64", "version": "1.2.3"},
                {"source": "dpkg", "name": "inventory-agent", "arch": "amd64", "version": "4.5.6"},
            ],
            "purpose": "호스트 관리 업무를 위해 두 제품이 필요합니다.",
            "license_evidence": "격리 UI fixture에서 승인 가능한 사용권을 준비했습니다.",
        })
        assert created.status_code == 201, created.text
        detail = created.json()
        assert detail["batch_no"] == f"SWB-{detail['id']:06d}"
        assert detail["host_id"] == host_batch_site["host_id"]
        assert {(item["name"], item["version"]) for item in detail["items"]} == {
            ("corp-tool", "1.2.3"), ("inventory-agent", "4.5.6"),
        }

        outside = client.post("/v1/software-request-batches", headers={
            "Authorization": f"Bearer {host_batch_site['request_token']}",
        }, json={
            "host_id": host_batch_site["outside_host_id"],
            "items": [{"source": "dpkg", "name": "corp-tool", "arch": "amd64", "version": "1.2.3"}],
            "purpose": "범위 밖 호스트로 요청이 우회되지 않는지 검증합니다.",
            "license_evidence": "테스트 전용 가상 사용권입니다.",
        })
        assert outside.status_code == 403, outside.text

        forbidden = client.post(f"/v1/software-request-batches/{detail['id']}/actions", headers={
            "Authorization": f"Bearer {host_batch_site['request_token']}",
        }, json={
            "action": "assign",
            "assignee_id": host_batch_site["admin_user_id"],
            "due_at": "2026-11-30T12:00:00+09:00",
            "items": [{"request_id": detail["items"][0]["id"], "expected_revision": 1}],
        })
        assert forbidden.status_code == 403, forbidden.text


def test_batch_admin_decisions_approve_only_the_selected_product_on_its_host(host_batch_site):
    """한 묶음 안의 선택별 판정과 승인 호스트 범위가 API 응답에 고정된다."""
    with TestClient(host_batch_site["app"]) as client:
        request_headers = {"Authorization": f"Bearer {host_batch_site['request_token']}"}
        admin_headers = {"Authorization": f"Bearer {host_batch_site['admin_token']}"}
        created = client.post("/v1/software-request-batches", headers=request_headers, json={
            "host_id": host_batch_site["host_id"],
            "items": [
                {"source": "dpkg", "name": "corp-tool", "arch": "amd64", "version": "1.2.3"},
                {"source": "dpkg", "name": "inventory-agent", "arch": "amd64", "version": "4.5.6"},
            ],
            "purpose": "호스트의 두 업무 앱을 사용해야 하는 사유입니다.",
            "license_evidence": "격리 테스트용 사용권 근거 문서입니다.",
        })
        assert created.status_code == 201, created.text
        batch = created.json()
        items = batch["items"]

        assigned = client.post(f"/v1/software-request-batches/{batch['id']}/actions", headers=admin_headers, json={
            "action": "assign",
            "items": [{"request_id": item["id"], "expected_revision": item["revision"]} for item in items],
            "assignee_id": host_batch_site["admin_user_id"],
            "due_at": "2026-11-30T12:00:00+09:00",
        })
        assert assigned.status_code == 200, assigned.text
        assert {item["status"] for item in assigned.json()["items"]} == {"reviewing"}

        by_name = {item["name"]: item for item in assigned.json()["items"]}
        approved = client.post(f"/v1/software-request-batches/{batch['id']}/actions", headers=admin_headers, json={
            "action": "approve", "reason": "선택 제품의 업무 필요와 사용권을 확인했습니다.",
            "approval_until": "2027-11-24T03:00:00Z",
            "items": [{"request_id": by_name["corp-tool"]["id"], "expected_revision": by_name["corp-tool"]["revision"]}],
        })
        assert approved.status_code == 200, approved.text
        by_name = {item["name"]: item for item in approved.json()["items"]}
        rejected = client.post(f"/v1/software-request-batches/{batch['id']}/actions", headers=admin_headers, json={
            "action": "reject", "reason": "이 항목은 이번 요청에서 제외합니다.",
            "items": [{"request_id": by_name["inventory-agent"]["id"], "expected_revision": by_name["inventory-agent"]["revision"]}],
        })
        assert rejected.status_code == 200, rejected.text
        result = rejected.json()
        assert result["status"] == "mixed"
        assert result["status_counts"]["approved"] == result["status_counts"]["rejected"] == 1
        assert result["terminal_count"] == result["item_count"] == 2
        by_name = {item["name"]: item for item in result["items"]}
        assert by_name["corp-tool"]["approval_status"] == "active"
        assert by_name["corp-tool"]["approvals"][0]["host_id"] == host_batch_site["host_id"]
        assert by_name["inventory-agent"]["approval_status"] == "not_active"
        assert by_name["inventory-agent"]["approvals"] == []


def test_host_batch_software_selection_and_review_flow_in_chrome(host_batch_server):
    """호스트별 선택·요청·관리자 혼합 판정을 실제 브라우저/API에서 검증한다."""
    pytest.importorskip("playwright.sync_api", reason="Playwright 가 설치되어 있지 않다")
    from playwright.sync_api import expect, sync_playwright

    chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if not chrome.exists():
        pytest.skip(f"Chrome 실행 파일이 없다: {chrome}")

    # 제품 UI와 실제 API를 같은 origin의 격리 SQLite fixture로 연결한다.
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=str(chrome), headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme="light")
        context.add_init_script(f"sessionStorage.setItem('swinv.token', {json.dumps(host_batch_server['request_token'])})")
        page = context.new_page()
        admin_context = None
        console_errors: list[str] = []
        page.on("pageerror", lambda error: console_errors.append(str(error)))
        try:
            page.goto(f"{host_batch_server['base']}/#/hosts/{host_batch_server['host_id']}?section=software")
            expect(page.get_by_role("heading", name="batch-ui-01.corp.example")).to_be_visible()
            section = page.locator('details[data-kind="software"]')
            expect(section).to_have_attribute("open", "")
            expect(page.locator(".software-table")).to_be_visible()

            # 업무 앱만 선택 가능하며 OS/개발 의존성, 미분류, 승인·진행 요청은 비활성이다.
            corp = page.get_by_role("checkbox", name="Corp Tool 1.2.3 선택", exact=True)
            agent = page.get_by_role("checkbox", name="Inventory Agent 4.5.6 선택", exact=True)
            nginx = page.get_by_role("checkbox", name="Nginx 1.24.0 선택", exact=True)
            python = page.get_by_role("checkbox", name="Python Demo 2.4.1 선택", exact=True)
            unclassified = page.get_by_role("checkbox", name="Unclassified Demo 0.9.0 선택", exact=True)
            approved = page.get_by_role("checkbox", name="Approved Demo 3.0.0 선택", exact=True)
            pending = page.get_by_role("checkbox", name="Pending Demo 2.0.0 선택", exact=True)
            for checkbox in (corp, agent):
                expect(checkbox).to_be_enabled()
            for checkbox in (nginx, python, unclassified, approved, pending):
                expect(checkbox).to_be_disabled()

            # 정렬 뒤에도 선택 identity가 전체 튜플과 함께 보존된다.
            page.get_by_role("button", name="소프트웨어 정렬", exact=True).click()
            corp.check()
            agent.check()
            expect(page.locator(".batch-selection-checkbox:checked")).to_have_count(2)
            selected_keys = {
                tuple(json.loads(value))
                for value in page.locator(".batch-selection-checkbox:checked").evaluate_all(
                    "nodes => nodes.map(node => node.dataset.softwareKey)"
                )
            }
            assert selected_keys == {
                ("dpkg", "corp-tool", "amd64", "1.2.3"),
                ("dpkg", "inventory-agent", "amd64", "4.5.6"),
            }

            # 검색 필터가 선택 항목 하나를 숨겨도 기존 선택과 카운터가 유지된다.
            search = page.get_by_role("searchbox", name="설치된 소프트웨어 검색", exact=True)
            search.fill("corp-tool")
            expect(page.locator(".batch-selection-count")).to_contain_text("선택 2개 · 현재 필터에서 숨김 1개")
            expect(page.locator(".batch-selection-checkbox:checked")).to_have_count(1)
            search.fill("")
            expect(page.locator(".batch-selection-checkbox:checked")).to_have_count(2)

            # 현재 표시 항목 선택은 자격을 갖춘 두 업무 앱만 선택한다.
            page.get_by_role("button", name="선택 해제", exact=True).click()
            page.get_by_role("button", name="현재 표시 가능한 항목 선택", exact=True).click()
            expect(page.locator(".batch-selection-checkbox:checked")).to_have_count(2)
            keys = {
                tuple(json.loads(value))
                for value in page.locator(".batch-selection-checkbox:checked").evaluate_all(
                    "nodes => nodes.map(node => node.dataset.softwareKey)"
                )
            }
            assert keys == {
                ("dpkg", "corp-tool", "amd64", "1.2.3"),
                ("dpkg", "inventory-agent", "amd64", "4.5.6"),
            }

            # 호스트 화면을 이동해 돌아오면 앞 호스트 선택이 남지 않는다.
            page.goto(f"{host_batch_server['base']}/#/hosts/{host_batch_server['outside_host_id']}?section=software")
            expect(page.locator(".batch-selection-checkbox")).to_have_count(0)
            page.goto(f"{host_batch_server['base']}/#/hosts/{host_batch_server['host_id']}?section=software")
            expect(page.locator(".batch-selection-count")).to_contain_text("선택 0개")
            expect(page.locator(".batch-selection-checkbox:checked")).to_have_count(0)
            page.get_by_role("button", name="현재 표시 가능한 항목 선택", exact=True).click()
            expect(page.locator(".batch-selection-checkbox:checked")).to_have_count(2)
            keys = {
                tuple(json.loads(value))
                for value in page.locator(".batch-selection-checkbox:checked").evaluate_all(
                    "nodes => nodes.map(node => node.dataset.softwareKey)"
                )
            }

            # 실제 자산·호스트 자료를 1440/1366/390 뷰포트에서 캡처한다.
            page.evaluate("document.querySelector('details[data-kind=software]').scrollIntoView()")
            ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-software.png"), animations="disabled")
            page.set_viewport_size({"width": 1366, "height": 768})
            page.wait_for_timeout(150)
            page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-software-1366.png"), animations="disabled")
            page.set_viewport_size({"width": 390, "height": 844})
            page.wait_for_timeout(150)
            overflow = page.evaluate("document.documentElement.scrollWidth > window.innerWidth")
            assert overflow is False, "호스트 상세 화면에서 390px 문서 가로 넘침이 발생했다"
            page.locator(".batch-selection-toolbar").scroll_into_view_if_needed()
            page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-software-390.png"), animations="disabled")
            page.set_viewport_size({"width": 1440, "height": 900})
            page.wait_for_timeout(150)

            page.get_by_role("button", name="선택한 SW 승인 요청", exact=True).click()
            dialog = page.locator("dialog.batch-request-dialog")
            expect(dialog).to_be_visible()
            expect(dialog.locator(".batch-request-summary li")).to_have_count(2)
            purpose = dialog.get_by_role("textbox", name="요청 사유", exact=True)
            license_evidence = dialog.get_by_role("textbox", name="사용권 근거", exact=True)
            expect(purpose).to_be_visible()
            assert purpose.evaluate("node => node.matches(':invalid')")
            dialog.get_by_role("button", name="승인 요청 제출", exact=True).click()
            expect(dialog).to_be_visible()
            purpose.fill("배치 호스트에서 두 업무 앱을 운영 업무에 사용합니다.")
            license_evidence.fill("가상 계약서 BATCH-UI-01을 확인했습니다.")
            page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-request.png"), animations="disabled")
            with page.expect_request(lambda request: request.method == "POST" and request.url.endswith("/v1/software-request-batches")) as request_info:
                dialog.get_by_role("button", name="승인 요청 제출", exact=True).click()
            submitted = request_info.value.post_data_json
            assert submitted["host_id"] == host_batch_server["host_id"]
            assert submitted["purpose"] == "배치 호스트에서 두 업무 앱을 운영 업무에 사용합니다."
            assert submitted["license_evidence"] == "가상 계약서 BATCH-UI-01을 확인했습니다."
            assert {tuple((row["source"], row["name"], row["arch"], row["version"])) for row in submitted["items"]} == keys
            expect(page).to_have_url(__import__("re").compile(r"#/sw-requests/batches/\d+"))

            batch_id = page.url.split("/batches/")[-1].split("?")[0]
            status, detail = _http_json(host_batch_server["base"], host_batch_server["request_token"],
                                        f"/v1/software-request-batches/{batch_id}")
            assert status == 200
            assert detail["host_id"] == host_batch_server["host_id"]
            assert detail["item_count"] == 2
            assert all(item["host_ids"] == [host_batch_server["host_id"]] for item in detail["items"])

            # 요청자는 저장된 묶음에서 실제 요청 호스트 화면으로 돌아간다.
            page.get_by_role("link", name="← 요청 묶음", exact=True).click()
            expect(page).to_have_url(__import__("re").compile(r"#/hosts/" + host_batch_server["host_id"]))
            expect(page.locator(".batch-selection-checkbox:checked")).to_have_count(0)

            # 범위 밖 호스트는 요청할 수 없지만, 자산 미등록이어도 허용 범위면 선택할 수 있다.
            page.goto(f"{host_batch_server['base']}/#/hosts/{host_batch_server['outside_host_id']}?section=software")
            expect(page.get_by_role("heading", name="batch-ui-02.corp.example")).to_be_visible()
            expect(page.get_by_text("이 호스트는 요청 권한 범위에 없습니다.", exact=False)).to_be_visible()
            expect(page.locator(".batch-selection-checkbox")).to_have_count(0)
            expect(page.get_by_role("button", name="선택한 SW 승인 요청", exact=True)).to_be_disabled()
            page.goto(f"{host_batch_server['base']}/#/hosts/{host_batch_server['unregistered_host_id']}?section=software")
            expect(page.get_by_role("heading", name="batch-ui-unregistered.corp.example")).to_be_visible()
            expect(page.locator(".batch-selection-checkbox:enabled")).to_have_count(2)
            expect(page.get_by_text("자산 대장에 없음", exact=True)).to_be_visible()

            # 별도 관리자 세션에서 큐→일괄 배정→SW별 승인/반려를 실제 화면과 HTTP로 검증한다.
            admin_context = browser.new_context(viewport={"width": 1440, "height": 900},
                                                color_scheme="light", timezone_id="Asia/Seoul")
            admin_context.add_init_script(
                f"sessionStorage.setItem('swinv.token', {json.dumps(host_batch_server['admin_token'])})")
            admin_page = admin_context.new_page()
            admin_page.on("pageerror", lambda error: console_errors.append(str(error)))
            admin_page.goto(f"{host_batch_server['base']}/#/sw-requests")
            expect(admin_page.get_by_role("heading", name="호스트별 승인 요청")).to_be_visible()
            status_filter = admin_page.get_by_label("요청 SW 상태 포함 필터", exact=True)
            security_filter = admin_page.get_by_label("요청 SW 보안 판정 포함 필터", exact=True)
            status_filter.select_option("submitted")
            expect(admin_page).to_have_url(__import__("re").compile(r"status=submitted"))
            security_filter.select_option("confirmed")
            expect(admin_page).to_have_url(__import__("re").compile(r"security_impact=confirmed"))
            queue_anchor = admin_page.locator(f'a[data-batch-id="{batch_id}"]').last
            expect(queue_anchor).to_be_visible()
            expect(admin_page.locator(".batch-queue-table tbody tr")).to_have_count(1)
            expect(admin_page.locator(".table-toolbar-result")).to_have_text("전체 1건")
            admin_page.get_by_role("button", name="요청 번호 정렬", exact=True).click()
            expect(admin_page).to_have_url(__import__("re").compile(r"sort=batch_no.*direction=asc"))
            queue_anchor.click()
            expect(admin_page.locator(".batch-detail-page")).to_be_visible()
            back_to_queue = admin_page.get_by_role("link", name="← 요청 묶음", exact=True)
            back_to_queue.click()
            expect(admin_page).to_have_url(__import__("re").compile(r"#/sw-requests.*status=submitted.*security_impact=confirmed.*sort=batch_no"))
            expect(admin_page.locator(".batch-queue-table tbody tr")).to_have_count(1)
            admin_page.get_by_role("button", name="초기화", exact=True).click()
            expect(admin_page.locator(".batch-queue-table tbody tr")).to_have_count(2)

            # 실제 제품 HTML을 1440/1366/390에서 캡처한다. 가로 넘침은 표 안에만 허용한다.
            ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
            admin_page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
            admin_page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-approvals-queue.png"),
                                 full_page=True, animations="disabled")
            admin_page.set_viewport_size({"width": 1366, "height": 768})
            admin_page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
            admin_page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-approvals-queue-1366.png"),
                                 full_page=True, animations="disabled")
            admin_page.set_viewport_size({"width": 390, "height": 844})
            admin_page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
            assert admin_page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "요청 큐가 390px 문서 폭을 넘었다"
            admin_page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-approvals-queue-390.png"),
                                 full_page=True, animations="disabled")
            admin_page.set_viewport_size({"width": 1440, "height": 900})
            admin_page.locator(f'a[data-batch-id="{batch_id}"]').last.click()
            expect(admin_page.locator(".batch-detail-page")).to_be_visible()
            expect(admin_page.locator(".batch-item-table tbody tr")).to_have_count(2)

            admin_page.locator("[data-batch-select-all]").click()
            expect(admin_page.locator(".batch-item-selection:checked")).to_have_count(2)
            bulk_assign = admin_page.locator('[data-batch-action="assign"][data-bulk="true"]')
            expect(bulk_assign).to_be_enabled()
            bulk_assign.click()
            assign_dialog = admin_page.locator("dialog.batch-action-dialog")
            expect(assign_dialog).to_be_visible()
            assign_dialog.get_by_label("담당 관리자", exact=True).select_option(str(host_batch_server["admin_user_id"]))
            assign_dialog.get_by_label("처리 기한", exact=True).fill("2026-11-30T12:00")
            with admin_page.expect_response(lambda response: response.request.method == "POST"
                    and response.url.endswith(f"/v1/software-request-batches/{batch_id}/actions")) as assign_response:
                assign_dialog.get_by_role("button", name="담당 배정", exact=True).click()
            assert assign_response.value.status == 200, assign_response.value.text()
            expect(assign_dialog).to_have_count(0)
            expect(admin_page.locator(".batch-item-selection:checked")).to_have_count(0)

            status, assigned = _http_json(host_batch_server["base"], host_batch_server["admin_token"],
                                          f"/v1/software-request-batches/{batch_id}")
            assert status == 200
            assert all(item["status"] == "reviewing" for item in assigned["items"])
            assert all(item["assignee_id"] == host_batch_server["admin_user_id"] for item in assigned["items"])
            assert all(item["due_at"] for item in assigned["items"])

            # 보완 요청을 거쳐 요청자 화면에서 사유·사용권 근거를 고친 뒤 다시 제출한다.
            admin_page.get_by_role("button", name="Corp Tool 보완 요청", exact=True).click()
            changes_dialog = admin_page.locator("dialog.batch-action-dialog")
            changes_dialog.get_by_label("보완 사유", exact=True).fill("사용 목적과 대상 업무를 구체화해 주세요.")
            with admin_page.expect_response(lambda response: response.request.method == "POST"
                    and response.url.endswith(f"/v1/software-request-batches/{batch_id}/actions")) as changes_response:
                changes_dialog.get_by_role("button", name="보완 요청", exact=True).click()
            assert changes_response.value.status == 200, changes_response.value.text()
            expect(changes_dialog).to_have_count(0)
            changed = _http_json(host_batch_server["base"], host_batch_server["admin_token"],
                                 f"/v1/software-request-batches/{batch_id}")[1]
            changed_child = next(item for item in changed["items"] if item["name"] == "corp-tool")
            assert changed_child["status"] == "needs_changes"
            assert changed_child["decision_reason"] == "사용 목적과 대상 업무를 구체화해 주세요."

            requester_context = browser.new_context(viewport={"width": 1440, "height": 900},
                                                     color_scheme="light", timezone_id="Asia/Seoul")
            requester_context.add_init_script(
                f"sessionStorage.setItem('swinv.token', {json.dumps(host_batch_server['request_token'])})")
            requester_page = requester_context.new_page()
            requester_page.goto(f"{host_batch_server['base']}/#/sw-requests/batches/{batch_id}")
            expect(requester_page.locator(".batch-detail-page")).to_be_visible()
            requester_page.get_by_role("button", name="Corp Tool 보완 후 재제출", exact=True).click()
            resubmit_dialog = requester_page.locator("dialog.batch-action-dialog")
            purpose_box = resubmit_dialog.get_by_label("요청 사유", exact=True)
            license_box = resubmit_dialog.get_by_label("사용권 근거", exact=True)
            purpose_box.fill("업무 배포 작업을 위해 Corp Tool을 호스트에 설치해 운영합니다.")
            license_box.fill("가상 계약 BATCH-UI-01에 명시된 내부 업무 사용권을 확인했습니다.")
            with requester_page.expect_response(lambda response: response.request.method == "POST"
                    and response.url.endswith(f"/v1/software-request-batches/{batch_id}/actions")) as resubmit_response:
                resubmit_dialog.get_by_role("button", name="보완 후 재제출", exact=True).click()
            assert resubmit_response.value.status == 200, resubmit_response.value.text()
            expect(resubmit_dialog).to_have_count(0)
            requester_context.close()
            resubmitted = _http_json(host_batch_server["base"], host_batch_server["request_token"],
                                     f"/v1/software-request-batches/{batch_id}")[1]
            resubmitted_child = next(item for item in resubmitted["items"] if item["name"] == "corp-tool")
            assert resubmitted_child["status"] == "submitted"
            assert resubmitted_child["purpose"] == "업무 배포 작업을 위해 Corp Tool을 호스트에 설치해 운영합니다."
            assert resubmitted_child["license_evidence"] == "가상 계약 BATCH-UI-01에 명시된 내부 업무 사용권을 확인했습니다."

            # 보완 후 재제출은 검토자가 다시 배정해야 한다.
            admin_page.goto(f"{host_batch_server['base']}/#/sw-requests/batches/{batch_id}")
            expect(admin_page.get_by_role("button", name="Corp Tool 담당 배정", exact=True)).to_be_visible()
            admin_page.get_by_role("button", name="Corp Tool 담당 배정", exact=True).click()
            reassign_dialog = admin_page.locator("dialog.batch-action-dialog")
            reassign_dialog.get_by_label("담당 관리자", exact=True).select_option(str(host_batch_server["admin_user_id"]))
            reassign_dialog.get_by_label("처리 기한", exact=True).fill("2026-11-30T12:00")
            with admin_page.expect_response(lambda response: response.request.method == "POST"
                    and response.url.endswith(f"/v1/software-request-batches/{batch_id}/actions")) as reassign_response:
                reassign_dialog.get_by_role("button", name="담당 배정", exact=True).click()
            assert reassign_response.value.status == 200, reassign_response.value.text()
            expect(reassign_dialog).to_have_count(0)

            # 상세 행의 단건 판정 버튼과 사유/유효기한 폼을 사용해 서로 다른 결론을 남긴다.
            admin_page.get_by_role("button", name="Corp Tool 승인", exact=True).click()
            approve_dialog = admin_page.locator("dialog.batch-action-dialog")
            approve_dialog.get_by_label("승인 사유", exact=True).fill("업무 필요와 사용권 근거를 확인했습니다.\n보안 검토도 마쳤습니다.")
            approve_dialog.get_by_label("승인 유효 기한", exact=True).fill("2026-12-23T12:00")
            with admin_page.expect_response(lambda response: response.request.method == "POST"
                    and response.url.endswith(f"/v1/software-request-batches/{batch_id}/actions")) as approve_response:
                approve_dialog.get_by_role("button", name="승인", exact=True).click()
            assert approve_response.value.status == 200, approve_response.value.text()
            expect(approve_dialog).to_have_count(0)

            admin_page.get_by_role("button", name="Inventory Agent 반려", exact=True).click()
            reject_dialog = admin_page.locator("dialog.batch-action-dialog")
            reject_dialog.get_by_label("반려 사유", exact=True).fill("이번 배포에서는 대체 도구를 사용합니다.")
            with admin_page.expect_response(lambda response: response.request.method == "POST"
                    and response.url.endswith(f"/v1/software-request-batches/{batch_id}/actions")) as reject_response:
                reject_dialog.get_by_role("button", name="반려", exact=True).click()
            assert reject_response.value.status == 200, reject_response.value.text()
            expect(reject_dialog).to_have_count(0)

            status, final_batch = _http_json(host_batch_server["base"], host_batch_server["admin_token"],
                                             f"/v1/software-request-batches/{batch_id}")
            assert status == 200
            assert final_batch["status"] == "mixed"
            assert final_batch["status_counts"]["approved"] == final_batch["status_counts"]["rejected"] == 1
            final_items = {item["name"]: item for item in final_batch["items"]}
            assert final_items["corp-tool"]["approval_status"] == "active"
            assert final_items["corp-tool"]["approvals"][0]["host_id"] == host_batch_server["host_id"]
            assert final_items["inventory-agent"]["approval_status"] == "not_active"
            assert final_items["inventory-agent"]["approvals"] == []
            expect(admin_page.locator(".batch-item-table tbody")).to_contain_text("승인")
            expect(admin_page.locator(".batch-item-table tbody")).to_contain_text("반려")

            # 상세 배치의 처리 정보/행 배치를 데스크톱과 모바일에서 확인한다.
            admin_page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
            admin_page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-approvals.png"),
                                 full_page=True, animations="disabled")
            admin_page.set_viewport_size({"width": 1366, "height": 768})
            admin_page.locator(".batch-item-grid").scroll_into_view_if_needed()
            admin_page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
            admin_page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-approvals-1366.png"),
                                 full_page=True, animations="disabled")
            admin_page.set_viewport_size({"width": 390, "height": 844})
            admin_page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
            assert admin_page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "묶음 상세가 390px 문서 폭을 넘었다"
            admin_page.locator(".batch-item-grid").scroll_into_view_if_needed()
            admin_page.screenshot(path=str(ARTIFACT_DIR / "product-v5-host-approvals-390.png"),
                                 full_page=True, animations="disabled")
            assert not console_errors, f"브라우저 예외: {console_errors}"
        finally:
            if admin_context is not None:
                admin_context.close()
            context.close()
            browser.close()
