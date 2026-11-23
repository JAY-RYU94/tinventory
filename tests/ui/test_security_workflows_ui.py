"""실제 서비스 API와 Chrome에서 업무용 승인·CVE 화면을 검증한다."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path

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


@pytest.fixture(scope="module")
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
               "admin_token": admin_session, "admin_user_id": created_admin.json()["id"], "repo": repo,
               "asset_id": vm_asset.json()["id"], "parent_asset_id": parent_asset.json()["id"]}
    finally:
        server.should_exit = True
        thread.join(10)


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
        expect(page.get_by_role("heading", name="설치 항목 1행")).to_be_visible()
        expect(page.get_by_text("software.dpkg", exact=True)).to_be_visible()
        expect(page.get_by_text("마지막 성공", exact=True)).to_be_visible()
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
