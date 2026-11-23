"""실제 서비스 API와 Chrome에서 업무용 승인·CVE 화면을 검증한다."""
from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from datetime import timedelta
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

pytest.importorskip("playwright.sync_api", reason="Playwright 가 설치되어 있지 않다")
pytest.importorskip("uvicorn", reason="uvicorn 이 설치되어 있지 않다")
from playwright.sync_api import expect, sync_playwright  # noqa: E402

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if not Path(CHROME).exists():
    pytest.skip(f"Chrome 실행 파일이 없다: {CHROME}", allow_module_level=True)

import uvicorn  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from swinventory.common.models import KernelInfo, OsInfo, PackageRecord, Snapshot  # noqa: E402
from swinventory.server.app import ApiSettings, create_app  # noqa: E402
from swinventory.server.repo.sql import SqlInventoryRepository  # noqa: E402
from swinventory.server.services.ingest import IngestService  # noqa: E402

ADMIN_TOKEN = "security-ui-admin-token"
ADMIN_PASSWORD = "Security-UI-Admin!234"
REQUEST_PASSWORD = "Security-UI-Request!234"
HOST_ID = "ab" * 16
PRODUCT = "corp-tool"
CVE_ID = "CVE-2026-12345"
ARTIFACT_DIR = Path("/Users/jhjh54/.codex/visualizations/2026/11/22/01a205a3-cb51-7de2-b0db-36063be237fe/ux-audit/screenshots")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="function")
def app_site(tmp_path_factory):
    root = tmp_path_factory.mktemp("security-ui")
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    repo = SqlInventoryRepository.from_url(f"sqlite:///{root / 'security-ui.db'}")
    snapshot = Snapshot(host_id=HOST_ID, hostname="ui01.corp.example", collected_at=now.isoformat(),
        agent_version="test", os=OsInfo("debian", "Debian 12", "12"),
        kernel=KernelInfo("6.1.0", ("6.1.0",), False),
        packages=[PackageRecord("dpkg", PRODUCT, "1.2.3", "amd64")], interfaces=[], ports=[], hardware=None,
        containers=[], k8s=None, collected=["os", "kernel", "software.dpkg"], errors={})
    IngestService(repo, clock=lambda: now).ingest(snapshot)
    feed_env = {"SWINV_JWT_SECRET": "security-ui-test-key-" + "x" * 40}
    settings = ApiSettings(admin_tokens=(ADMIN_TOKEN,))
    setup_app = create_app(repo, settings, clock=lambda: now, env=feed_env, agent_dir=root)
    with TestClient(setup_app) as client:
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        created_admin = client.post("/v1/users", headers=headers,
            json={"username": "ui-admin", "password": ADMIN_PASSWORD, "role": "admin"})
        assert created_admin.status_code == 201, created_admin.text
        created_requester = client.post("/v1/users", headers=headers,
            json={"username": "ui-requester", "password": REQUEST_PASSWORD, "role": "request"})
        assert created_requester.status_code == 201, created_requester.text
        admin_session = client.post("/v1/auth/login", json={"username": "ui-admin", "password": ADMIN_PASSWORD}).json()["access_token"]
        request_session = client.post("/v1/auth/login", json={"username": "ui-requester", "password": REQUEST_PASSWORD}).json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_session}"}
        parent_asset = client.post("/v1/assets", headers=headers, json={"asset_no": "UI-PHYS-01", "kind": "physical", "hostname": "physical-ui"})
        assert parent_asset.status_code == 201, parent_asset.text
        vm_asset = client.post("/v1/assets", headers=headers, json={"asset_no": "UI-VM-01", "kind": "virtual", "hostname": "ui01.corp.example",
            "host_id": HOST_ID, "parent_asset_id": parent_asset.json()["id"], "note": "기존 비고"})
        assert vm_asset.status_code == 201, vm_asset.text
        classified = client.put("/v1/software-products/classification", headers=admin_headers, json={
            "source": "dpkg", "name": PRODUCT, "arch": "amd64", "category": "business_app",
            "product_name": "Corp Tool", "publisher": "Example Corp", "evidence": "내부 업무 담당자가 업무용 제품임을 확인함"})
        assert classified.status_code == 200, classified.text
        scoped = client.put(f"/v1/software-request-scopes/{created_requester.json()['id']}", headers=admin_headers,
                            json={"host_ids": [HOST_ID]})
        assert scoped.status_code == 200, scoped.text
        # 고립된 UI 검증용 CVE/KEV 샘플. 실제 피드 접속은 검증에 포함하지 않는다.
        repo.upsert_nvd_vulnerabilities([{
            "cve_id": CVE_ID, "description": "Controlled test CVE entry.", "published_at": now.isoformat(),
            "modified_at": now.isoformat(), "cvss_score": "8.1", "cvss_severity": "HIGH",
            "cvss_metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
            "nvd_status": "Analyzed", "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345", "source": "NVD"}],
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:example:corp-tool:*:*:*:*:*:*:*:*", "vulnerable": True}]}]}],
        }], now.isoformat())
        repo.replace_cisa_kev([{
            "cve_id": CVE_ID, "description": "Controlled test KEV entry.", "modified_at": now.isoformat(),
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345", "source": "NVD"}],
            "vendor": "Example Corp", "product": "Corp Tool", "vulnerability_name": "Controlled UI test vulnerability",
            "date_added": now.date().isoformat(), "due_date": "2026-12-31", "ransomware_use": "Unknown",
            "required_action": "Apply the vendor update.", "notes": "Isolated test record",
        }], "test-catalog-1", now.isoformat())
        repo.record_vulnerability_feed("cisa_kev", "ok", now.isoformat(), now.isoformat(), "", "test-catalog-1", 1)
        repo.record_vulnerability_feed("nvd", "ok", now.isoformat(), now.isoformat(), "", "test-window-1", 1)
        match = repo.update_vulnerability_match(CVE_ID, "dpkg", PRODUCT, "amd64", {
            "status": "affected_confirmed", "evidence": "격리 테스트의 정확한 설치 버전과 CVE 메타데이터 확인",
            "conditions": "테스트 전용이며 운영 판정으로 사용하지 않음", "affected_versions": ["1.2.3"],
        }, created_admin.json()["id"], now.isoformat(), None)
        assert match["status"] == "affected_confirmed"

    # ASGI lifespan 안의 MCP 세션 매니저는 단일 앱 인스턴스에서 한 번만 실행된다.
    # 시드 API가 닫힌 뒤 같은 공유 DB를 바라보는 별도 앱 인스턴스로 실제 브라우저 서버를 띄운다.
    app = create_app(repo, settings, clock=lambda: now, env=feed_env, agent_dir=root)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        assert time.monotonic() < deadline, "실제 UI 검증 서버가 시작되지 않았다"
        time.sleep(0.05)
    try:
        yield {"base": f"http://127.0.0.1:{port}", "request_token": request_session,
               "admin_token": admin_session, "admin_user_id": created_admin.json()["id"],
               "request_user_id": created_requester.json()["id"], "now": now, "repo": repo,
               "asset_id": vm_asset.json()["id"], "parent_asset_id": parent_asset.json()["id"]}
    finally:
        server.should_exit = True
        thread.join(10)


def _api_json(base: str, token: str, path: str, *, method: str = "GET", body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(f"{base}{path}", data=data, method=method,
                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _seed_v4_workflows(app_site):
    """두 개의 독립 요청과 네 분류 설치 항목을 실제 SQLite/API에 준비한다."""
    repo, now = app_site["repo"], app_site["now"]
    owners_host = "cd" * 16
    second_request_host = "ef" * 16
    packages = [
        PackageRecord("dpkg", PRODUCT, "1.2.3", "amd64"),
        PackageRecord("dpkg", "nginx", "1.24.0", "amd64"),
        PackageRecord("dpkg", "python3-demo", "2.4.1", "amd64"),
        PackageRecord("dpkg", "unclassified-v4", "0.1.0", "amd64"),
    ]
    for host_id, hostname, installed in (
        (owners_host, "ui-v4.corp.example", packages),
        (second_request_host, "ui-v4-secondary.corp.example", [packages[0]]),
    ):
        snapshot = Snapshot(host_id=host_id, hostname=hostname, collected_at=now.isoformat(),
            agent_version="test", os=OsInfo("debian", "Debian 12", "12"),
            kernel=KernelInfo("6.1.0", ("6.1.0",), False), packages=installed,
            interfaces=[], ports=[], hardware=None, containers=[], k8s=None,
            collected=["os", "kernel", "software.dpkg"], errors={})
        IngestService(repo, clock=lambda: now).ingest(snapshot)

    admin_headers = app_site["admin_token"]
    requester_headers = app_site["request_token"]
    for name, label, category in (
        ("nginx", "Nginx", "os_package"),
        ("python3-demo", "Python Demo", "development_dependency"),
    ):
        _api_json(app_site["base"], admin_headers, "/v1/software-products/classification", method="PUT", body={
            "source": "dpkg", "name": name, "arch": "amd64", "category": category,
            "product_name": label, "publisher": "Test fixture", "evidence": "격리된 UI 테스트용 분류 근거입니다.",
        })
    asset = _api_json(app_site["base"], admin_headers, "/v1/assets", method="POST", body={
        "asset_no": "UI-V4-ASSET", "kind": "virtual", "hostname": "ui-v4.corp.example",
        "host_id": owners_host, "primary_owner": "정 담당자", "secondary_owner": "부 담당자",
    })
    requester = app_site["request_user_id"]
    _api_json(app_site["base"], admin_headers, f"/v1/software-request-scopes/{requester}", method="PUT",
              body={"host_ids": [owners_host, second_request_host]})
    requests = []
    for host_id in (owners_host, second_request_host):
        item = _api_json(app_site["base"], requester_headers, "/v1/software-requests", method="POST", body={
            "source": "dpkg", "name": PRODUCT, "arch": "amd64", "version": "1.2.3",
            "purpose": "격리 UI 테스트에서 필터를 검증합니다.",
            "license_evidence": "가상 테스트 계약 범위이며 운영 데이터가 아닙니다.", "host_ids": [host_id],
        })
        requests.append(item)
    assigned = _api_json(app_site["base"], admin_headers,
        f"/v1/software-requests/{requests[0]['id']}/actions", method="POST", body={
            "action": "assign", "expected_revision": requests[0]["revision"],
            "assignee_id": app_site["admin_user_id"],
            "due_at": (now + timedelta(days=5)).isoformat(),
        })
    return {"asset_id": asset["id"], "host_id": owners_host, "request_ids": [r["id"] for r in requests],
            "assigned_request": assigned["id"]}


def test_v4_workflow_filters_and_cve_scope_in_chrome(app_site):
    """V4 승인·자산SW·CVE 탐색이 실제 API와 좁은 화면에서 상태를 보존한다."""
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    seeded = _seed_v4_workflows(app_site)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=CHROME, headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme="light", timezone_id="Asia/Seoul")
        context.add_init_script(f"sessionStorage.setItem('swinv.token', {json.dumps(app_site['admin_token'])})")
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda err: errors.append(str(err)))

        def capture(name: str):
            # Resize 후 paint가 끝난 안정된 frame에서 캡처한다. 셸 요소가 실제로 하나씩만 있는지도 함께 확인한다.
            page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
            assert page.locator("#top").count() == 1
            assert page.locator("#workspace-bar").count() == 1
            page.screenshot(path=str(ARTIFACT_DIR / name), full_page=True, animations="disabled")
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), f"viewport overflow at {name}"

        def capture_widths(stem: str):
            for width, height, suffix in ((1440, 900, ""), (1366, 768, "-1366"), (390, 844, "-390")):
                page.set_viewport_size({"width": width, "height": height})
                capture(f"product-v4-{stem}{suffix}.png")
            page.set_viewport_size({"width": 1440, "height": 900})

        # 승인 목록: 기본 검토 대기, 상태/보안/담당 범위, 서버 정렬, 상세 복귀를 점검한다.
        page.goto(f"{app_site['base']}/#/sw-requests")
        expect(page.get_by_role("heading", name="SW 사용 승인 요청")).to_be_visible()
        expect(page.locator(".approval-grid .data-grid thead th")).to_have_count(9)
        result = page.locator(".table-toolbar-result")
        expect(result).to_have_text("전체 2건")
        status = page.get_by_label("요청 상태 필터")
        security = page.get_by_label("보안 영향 판정 필터")
        expect(status.locator("option").first).to_have_text("모든 상태")
        expect(security.locator("option").first).to_have_text("모든 보안 판정")
        expect(page.locator(".approval-grid tbody tr")).to_have_count(2)
        original_hash = page.evaluate("location.hash")
        page.locator(".skip-link").focus()
        page.keyboard.press("Enter")
        expect(page.locator("#app")).to_be_focused()
        assert page.evaluate("location.hash") == original_hash
        page.evaluate("document.activeElement.blur()")
        capture_widths("approvals")

        status.select_option("reviewing")
        expect(result).to_have_text("전체 1건")
        expect(page.locator(".approval-grid tbody tr")).to_have_count(1)
        expect(page).to_have_url(re.compile(r"scope=all.*status=reviewing|status=reviewing.*scope=all"))
        security.select_option("not_affected")
        expect(result).to_have_text("전체 0건")
        security.select_option("confirmed")
        expect(result).to_have_text("전체 1건")
        page.get_by_role("button", name="초기화").click()
        expect(result).to_have_text("전체 2건")
        expect(status).to_have_value("")
        expect(security).to_have_value("")
        expect(page).to_have_url(re.compile(r"scope=all"))

        page.get_by_role("link", name="내 검토").click()
        expect(result).to_have_text("전체 1건")
        sort_button = page.get_by_role("button", name=re.compile(r"요청 상태 정렬"))
        sort_button.click()
        expect(page.locator(".approval-grid th").nth(2)).to_have_attribute("aria-sort", "ascending")
        expect(page).to_have_url(re.compile(r"sort=status.*direction=asc|direction=asc.*sort=status"))
        page.get_by_role("link", name="전체", exact=True).click()
        expect(page).to_have_url(re.compile(r"scope=all"))
        status = page.get_by_label("요청 상태 필터")
        expect(page.locator(".approval-grid tbody tr")).to_have_count(2)
        status.select_option("submitted")
        expect(page).to_have_url(re.compile(r"status=submitted"))
        expect(result).to_have_text("전체 1건")
        expect(page.locator(".approval-grid tbody tr")).to_have_count(1)
        list_hash = page.evaluate("location.hash")
        page.locator(".approval-grid tbody tr a.workflow-primary-link").first.click()
        expect(page.get_by_role("heading", name=re.compile(r"SW-\d+"))).to_be_visible()
        page.get_by_role("link", name="← 요청함").click()
        expect(page).to_have_url(re.compile(re.escape(list_hash) + r"$"))
        expect(result).to_have_text("전체 1건")

        # 자산 설치 소프트웨어: 분류/승인/영향 상태와 URL을 함께 유지한다.
        software_hash = f"#/assets/{seeded['asset_id']}?tab=software"
        page.goto(f"{app_site['base']}/{software_hash}")
        expect(page.locator(".asset-context-strip")).to_contain_text("정 담당자")
        expect(page.locator(".asset-context-strip")).to_contain_text("부 담당자")
        expect(page.locator(".software-grid .data-grid thead th")).to_have_count(7)
        software_count = page.locator(".table-toolbar-result")
        expect(software_count).to_have_text("4개 표시 · 전체 4개")
        capture_widths("software")

        category_tabs = page.locator(".view-tabs[aria-label='설치 소프트웨어 분류']")
        category_tabs.locator("[data-category='os_package']").click()
        expect(software_count).to_have_text("1개 표시 · 전체 4개")
        expect(page.locator(".software-table tbody tr")).to_have_count(1)
        expect(page).to_have_url(re.compile(r"software_category=os_package"))
        category_tabs.locator("[data-category='development_dependency']").click()
        expect(software_count).to_have_text("1개 표시 · 전체 4개")
        category_tabs.locator("[data-category='needs_review']").click()
        expect(software_count).to_have_text("1개 표시 · 전체 4개")
        category_tabs.locator("[data-category='business_app']").click()
        expect(software_count).to_have_text("1개 표시 · 전체 4개")
        page.get_by_label("사용 승인 필터").select_option("active")
        expect(software_count).to_have_text("0개 표시 · 전체 4개")
        page.get_by_label("사용 승인 필터").select_option("not_active")
        expect(software_count).to_have_text("1개 표시 · 전체 4개")
        page.get_by_label("취약점 영향 필터").select_option("not_affected")
        expect(software_count).to_have_text("0개 표시 · 전체 4개")
        page.get_by_label("취약점 영향 필터").select_option("confirmed")
        expect(software_count).to_have_text("1개 표시 · 전체 4개")
        expect(page).to_have_url(re.compile(r"software_category=business_app.*software_approval=not_active.*software_impact=confirmed"))
        page.get_by_role("button", name="초기화").click()
        expect(software_count).to_have_text("4개 표시 · 전체 4개")
        expect(page).to_have_url(re.compile(r"tab=software"))

        # 정확한 제품/버전 필터 → CVE 호스트 집계 → 설치행 근거 → 범위 보존 복귀.
        page.get_by_label("취약점 영향 필터").select_option("confirmed")
        impact_link = page.get_by_role("link", name="영향 확인, 연결된 CVE 1건")
        expect(impact_link).to_be_visible()
        impact_link.click()
        expect(page.get_by_role("heading", name="취약점 영향 조회")).to_be_visible()
        cve_list_hash = page.evaluate("location.hash")
        assert "host=" + seeded["host_id"] in cve_list_hash
        assert "product_source=dpkg" in cve_list_hash and "product_name=corp-tool" in cve_list_hash
        assert "product_arch=amd64" in cve_list_hash and "product_version=1.2.3" in cve_list_hash
        expect(page.locator(".table-toolbar-result")).to_have_text("전체 1건")
        expect(page.get_by_role("link", name=CVE_ID)).to_be_visible()
        capture_widths("cve-list")
        page.get_by_role("link", name="1대", exact=True).click()
        expect(page.get_by_role("heading", name=CVE_ID)).to_be_visible()
        install_section = page.locator("section.panel").filter(has_text="설치 호스트 영향 판정 (1)")
        expect(install_section.locator("tbody tr")).to_have_count(1)
        install_row = install_section.locator("tbody tr").first
        expect(install_row).to_contain_text(f"{PRODUCT} · 1.2.3")
        evidence = "격리 테스트의 정확한 설치 버전과 CVE 메타데이터 확인"
        evidence_details = install_row.locator("details")
        if evidence_details.count():
            evidence_details.first.locator("summary").click()
            expect(evidence_details.first).to_contain_text(evidence)
        else:
            expect(install_row).to_contain_text(evidence)
        capture_widths("cve")
        page.get_by_role("link", name="← 취약점 목록").click()
        expect(page).to_have_url(re.compile(re.escape(cve_list_hash) + r"$"))
        expect(page.locator(".table-toolbar-result")).to_have_text("전체 1건")
        assert not errors, "브라우저 오류: " + "; ".join(errors)
        context.close(); browser.close()


def test_business_request_and_cve_screens_in_chrome(app_site, tmp_path):
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=CHROME, headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme="light", timezone_id="Asia/Seoul")
        context.add_init_script(f"sessionStorage.setItem('swinv.token', {json.dumps(app_site['request_token'])})")
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda err: errors.append(str(err)))
        page.goto(f"{app_site['base']}/#/business-apps")
        expect(page.get_by_role("heading", name="업무용 앱")).to_be_visible()
        expect(page.get_by_role("link", name="Corp Tool")).to_be_visible()
        page.screenshot(path=str(ARTIFACT_DIR / "business-apps-live-desktop.png"), full_page=True)
        page.get_by_role("button", name="사용 승인 요청").click()
        expect(page.get_by_role("dialog", name="업무용 앱 사용 승인 요청")).to_be_visible()
        page.get_by_role("checkbox", name=f"ui01.corp.example ({HOST_ID})").check()
        page.get_by_label("업무 목적").fill("내부 고객관리 업무에서 사용하는 제품입니다.")
        page.get_by_label("사용권 근거").fill("조직의 공급자 계약 문서와 정식 라이선스 내역을 확인했습니다.")
        page.get_by_role("button", name="승인 요청 제출").click()
        expect(page.get_by_role("heading", name="SW-000001")).to_be_visible()
        expect(page.get_by_role("button", name="요청 철회")).to_be_visible()
        expect(page.get_by_text("[object HTMLTimeElement]", exact=True)).to_have_count(0)
        page.screenshot(path=str(ARTIFACT_DIR / "software-request-submitted-live-desktop.png"), full_page=True)

        admin_context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme="light", timezone_id="Asia/Seoul")
        admin_context.add_init_script(f"sessionStorage.setItem('swinv.token', {json.dumps(app_site['admin_token'])})")
        admin_page = admin_context.new_page()
        admin_page.goto(f"{app_site['base']}/#/sw-requests/1")
        expect(admin_page.get_by_role("heading", name="SW-000001")).to_be_visible()
        admin_page.get_by_role("button", name="담당 배정").click()
        assign_dialog = admin_page.get_by_role("dialog", name="담당 배정")
        assign_dialog.get_by_label("담당자").select_option(app_site["admin_user_id"])
        assign_dialog.get_by_label("처리 기한").fill("2026-11-26T12:00")
        assign_dialog.get_by_role("button", name="담당 배정").click()
        expect(admin_page.locator(".action-bar > .badge")).to_have_text("검토 중")
        admin_page.get_by_role("button", name="보완 요청").click()
        changes_dialog = admin_page.get_by_role("dialog", name="보완 요청")
        changes_dialog.get_by_label("보완 사유").fill("사용권 적용 범위와 업무 부서 확인을 추가해 주세요.")
        changes_dialog.get_by_role("button", name="보완 요청").click()
        expect(changes_dialog).to_have_count(0)
        expect(admin_page.locator(".action-bar > .badge")).to_have_text("보완 요청")

        page.goto(f"{app_site['base']}/#/sw-requests/1")
        expect(page.get_by_role("button", name="같은 요청 번호로 재제출")).to_be_visible()
        page.get_by_role("button", name="같은 요청 번호로 재제출").click()
        resubmit_dialog = page.get_by_role("dialog", name="보완 후 재제출")
        resubmit_dialog.get_by_label("업무 목적").fill("보완: 내부 고객관리 업무에 필요한 제품입니다.")
        resubmit_dialog.get_by_label("사용권 근거").fill("보완: 공급자 계약과 조직 내 사용권 범위를 확인했습니다.")
        resubmit_dialog.get_by_role("button", name="보완 후 재제출").click()
        expect(resubmit_dialog).to_have_count(0)
        expect(page.get_by_role("heading", name="SW-000001")).to_be_visible()
        expect(page.locator(".action-bar > .badge")).to_have_text("접수")

        admin_page.reload()
        expect(admin_page.locator(".action-bar > .badge")).to_have_text("접수")
        admin_page.get_by_role("button", name="담당 재배정").click()
        assign_dialog = admin_page.get_by_role("dialog", name="담당 재배정")
        assign_dialog.get_by_label("담당자").select_option(app_site["admin_user_id"])
        assign_dialog.get_by_label("처리 기한").fill("2026-11-27T12:00")
        assign_dialog.get_by_role("button", name="담당 재배정").click()
        expect(assign_dialog).to_have_count(0)
        expect(admin_page.locator(".action-bar > .badge")).to_have_text("검토 중")
        expect(admin_page.get_by_role("button", name="승인", exact=True)).to_be_visible()
        admin_page.get_by_role("button", name="승인", exact=True).click()
        approve_dialog = admin_page.get_by_role("dialog", name="승인")
        approve_dialog.get_by_label("승인 사유").fill("정식 사용권과 업무 목적을 확인했습니다.")
        approve_dialog.get_by_label("승인 유효 기한").fill("2026-12-23T12:00")
        approve_dialog.get_by_role("button", name="승인").click()
        expect(approve_dialog).to_have_count(0)
        expect(admin_page.locator(".action-bar > .badge")).to_have_text("승인")
        expect(admin_page.get_by_text("active", exact=True)).to_be_visible()
        expect(admin_page.get_by_text("[object HTMLTimeElement]", exact=True)).to_have_count(0)
        admin_page.screenshot(path=str(ARTIFACT_DIR / "software-request-live-desktop.png"), full_page=True)

        page.goto(f"{app_site['base']}/#/cves")
        expect(page.get_by_role("heading", name="취약점 영향 조회")).to_be_visible()
        expect(page.get_by_role("link", name=CVE_ID)).to_be_visible()
        page.get_by_role("link", name=CVE_ID).click()
        expect(page.get_by_role("heading", name=CVE_ID)).to_be_visible()
        expect(page.get_by_text("영향 확인").first).to_be_visible()
        expect(page.get_by_role("link", name="ui01.corp.example")).to_be_visible()
        expect(page.get_by_text("[object HTMLTimeElement]", exact=True)).to_have_count(0)
        page.screenshot(path=str(ARTIFACT_DIR / "cve-impact-live-desktop.png"), full_page=True)

        admin_page.goto(f"{app_site['base']}/#/assets/{app_site['asset_id']}")
        expect(admin_page.get_by_role("heading", name="자산 UI-VM-01")).to_be_visible()
        expect(admin_page.get_by_text("기존 비고", exact=True)).to_be_visible()
        admin_page.screenshot(path=str(ARTIFACT_DIR / "asset-detail-live-desktop.png"), full_page=True)

        # 조회 전용 세션에서도 비활성화된 VM 상위 자산 값은 표시되어야 한다.
        page.goto(f"{app_site['base']}/#/assets/{app_site['asset_id']}/edit")
        parent_select = page.get_by_label("상위 호스트")
        expect(parent_select).to_be_disabled()
        expect(parent_select).to_have_value(str(app_site["parent_asset_id"]))
        page.goto(f"{app_site['base']}/#/assets/{app_site['asset_id']}?tab=software")
        expect(page.locator(".software-table tbody tr")).to_have_count(1)
        freshness = page.locator(".asset-collection-details")
        expect(freshness).to_be_visible()
        freshness.locator("summary").click()
        expect(freshness).to_contain_text("software.dpkg")
        expect(freshness).to_contain_text("마지막 성공")
        page.screenshot(path=str(ARTIFACT_DIR / "asset-software-freshness-live-desktop.png"), full_page=True)

        # 다른 필드의 서버 변경은 보존하고, 같은 필드의 충돌만 사용자가 선택한다.
        admin_page.get_by_role("link", name="자산 정보 편집").click()
        admin_page.get_by_label("비고").fill("로컬 비고 수정")
        external = admin_page.evaluate("""async ({id, token, parentId, hostId}) => {
          const response = await fetch(`/v1/assets/${id}`, {method: "PUT", headers: {"Content-Type": "application/json", Authorization: `Bearer ${token}`},
            body: JSON.stringify({asset_no: "UI-VM-01", kind: "virtual", hostname: "server-side-host", parent_asset_id: parentId,
              host_id: hostId, note: "기존 비고", serial: "", domain: "", ip: ""})});
          return response.status;
        }""", {"id": app_site["asset_id"], "token": app_site["admin_token"], "parentId": app_site["parent_asset_id"], "hostId": HOST_ID})
        assert external == 200
        admin_page.get_by_role("button", name="저장").click()
        dialog = admin_page.get_by_role("dialog", name="자산이 다른 사용자에 의해 변경됨")
        expect(dialog.get_by_text("최신값 유지", exact=True)).to_be_visible()
        expect(dialog.get_by_text("내 입력 유지", exact=True)).to_be_visible()
        dialog.get_by_role("button", name="선택한 값으로 저장").click()
        expect(dialog).to_have_count(0)
        expect(admin_page.locator(".kv dd").filter(has_text="server-side-host")).to_be_visible()
        expect(admin_page.locator(".kv dd").filter(has_text="로컬 비고 수정")).to_be_visible()
        admin_page.screenshot(path=str(ARTIFACT_DIR / "asset-detail-live-desktop.png"), full_page=True)

        admin_page.get_by_role("link", name="자산 정보 편집").click()
        admin_page.get_by_label("비고").fill("내 비고 선택")
        external = admin_page.evaluate("""async ({id, token, parentId, hostId}) => {
          const response = await fetch(`/v1/assets/${id}`, {method: "PUT", headers: {"Content-Type": "application/json", Authorization: `Bearer ${token}`},
            body: JSON.stringify({asset_no: "UI-VM-01", kind: "virtual", hostname: "server-side-host", parent_asset_id: parentId,
              host_id: hostId, note: "최신 비고 선택", serial: "", domain: "", ip: ""})});
          return response.status;
        }""", {"id": app_site["asset_id"], "token": app_site["admin_token"], "parentId": app_site["parent_asset_id"], "hostId": HOST_ID})
        assert external == 200
        admin_page.get_by_role("button", name="저장").click()
        dialog = admin_page.get_by_role("dialog", name="자산이 다른 사용자에 의해 변경됨")
        dialog.get_by_label("비고 충돌 해결").select_option("mine")
        dialog.get_by_role("button", name="선택한 값으로 저장").click()
        expect(dialog).to_have_count(0)
        expect(admin_page.locator(".kv dd").filter(has_text="내 비고 선택")).to_be_visible()

        admin_page.set_viewport_size({"width": 390, "height": 844})
        admin_page.evaluate("window.scrollTo(0, 0)")
        assert admin_page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        admin_page.set_viewport_size({"width": 1440, "height": 900})
        admin_page.goto(f"{app_site['base']}/#/assets/{app_site['asset_id']}/edit")
        admin_page.get_by_label("관리 IP").fill("not-an-ip")
        admin_page.get_by_role("button", name="저장").click()
        ip_field = admin_page.get_by_label("관리 IP")
        expect(ip_field).to_have_attribute("aria-invalid", "true")
        error_id = ip_field.get_attribute("aria-describedby").split()[-1]
        expect(admin_page.locator(f"#{error_id}")).to_contain_text("IP 주소 형식")
        admin_page.screenshot(path=str(ARTIFACT_DIR / "asset-edit-validation-live-desktop.png"), full_page=True)

        assert errors == [], errors
        admin_context.close()
        context.close()
        browser.close()
