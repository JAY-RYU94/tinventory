"""실제 서비스 API와 Chrome에서 업무용 승인·CVE 화면을 검증한다."""
from __future__ import annotations

import json
import os
import re
import socket
import tempfile
import threading
import time
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
ARTIFACT_DIR = Path(os.environ.get("SWINV_UI_ARTIFACT_DIR", Path(tempfile.gettempdir()) / "swinventory-ui-artifacts"))


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
    """자산 담당자와 분류·CVE 설치 항목을 격리 SQLite/API에 준비한다."""
    repo, now = app_site["repo"], app_site["now"]
    owners_host = "cd" * 16
    packages = [
        PackageRecord("dpkg", PRODUCT, "1.2.3", "amd64"),
        PackageRecord("dpkg", "nginx", "1.24.0", "amd64"),
        PackageRecord("dpkg", "python3-demo", "2.4.1", "amd64"),
        PackageRecord("dpkg", "unclassified-v4", "0.1.0", "amd64"),
    ]
    for host_id, hostname, installed in ((owners_host, "ui-v4.corp.example", packages),):
        snapshot = Snapshot(host_id=host_id, hostname=hostname, collected_at=now.isoformat(),
            agent_version="test", os=OsInfo("debian", "Debian 12", "12"),
            kernel=KernelInfo("6.1.0", ("6.1.0",), False), packages=installed,
            interfaces=[], ports=[], hardware=None, containers=[], k8s=None,
            collected=["os", "kernel", "software.dpkg"], errors={})
        IngestService(repo, clock=lambda: now).ingest(snapshot)

    admin_headers = app_site["admin_token"]
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
    return {"asset_id": asset["id"], "host_id": owners_host}


def test_asset_software_filters_and_cve_scope_in_chrome(app_site):
    """자산 설치 SW 필터와 정확한 제품 범위의 CVE 탐색을 실제 API로 검증한다."""
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

        # 자산 본문 건너뛰기는 해시 라우트를 바꾸지 않고 main에 초점을 둔다.
        software_hash = f"#/assets/{seeded['asset_id']}?tab=software"
        page.goto(f"{app_site['base']}/{software_hash}")
        expect(page.locator(".software-table")).to_be_visible()
        original_hash = page.evaluate("location.hash")
        page.locator(".skip-link").focus()
        page.keyboard.press("Enter")
        expect(page.locator("#app")).to_be_focused()
        assert page.evaluate("location.hash") == original_hash
        page.evaluate("document.activeElement.blur()")
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


def test_business_apps_cve_and_asset_edits_in_chrome(app_site):
    """분류·CVE 화면과 자산 권한·충돌 처리를 실제 세션으로 확인한다."""
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

        # 제품의 요청 진입점은 요청 가능 호스트를 보여 주고, 선택 후 호스트 설치표로 이동한다.
        page.get_by_role("button", name="사용 승인 요청", exact=True).click()
        chooser = page.get_by_role("dialog", name="호스트별 사용 승인 요청")
        expect(chooser).to_be_visible()
        chooser.get_by_role("link", name="ui01.corp.example", exact=True).click()
        expect(page).to_have_url(re.compile(r"#/hosts/" + re.escape(HOST_ID) + r"\?section=software"))
        expect(page.get_by_role("checkbox", name="Corp Tool 1.2.3 선택", exact=True)).to_be_enabled()
        page.goto(f"{app_site['base']}/#/cves")
        expect(page.get_by_role("heading", name="취약점 영향 조회")).to_be_visible()
        expect(page.get_by_role("link", name=CVE_ID)).to_be_visible()
        page.get_by_role("link", name=CVE_ID).click()
        expect(page.get_by_role("heading", name=CVE_ID)).to_be_visible()
        expect(page.get_by_text("영향 확인").first).to_be_visible()
        expect(page.get_by_role("link", name="ui01.corp.example")).to_be_visible()
        expect(page.get_by_text("[object HTMLTimeElement]", exact=True)).to_have_count(0)
        page.screenshot(path=str(ARTIFACT_DIR / "cve-impact-live-desktop.png"), full_page=True)

        admin_context = browser.new_context(viewport={"width": 1440, "height": 900}, color_scheme="light", timezone_id="Asia/Seoul")
        admin_context.add_init_script(f"sessionStorage.setItem('swinv.token', {json.dumps(app_site['admin_token'])})")
        admin_page = admin_context.new_page()
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
