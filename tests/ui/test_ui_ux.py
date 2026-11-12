"""화면(UX) 개선 검증 — 실제 서버(uvicorn 스레드)를 띄우고 Chrome(Playwright)으로 **브라우저에서 측정**한다.

소스 문자열을 훑는 테스트는 구현을 베껴도 통과하므로, 여기서는 렌더된 결과(레이아웃·색·포커스·요청 URL)만 단언한다.
CSP(`script-src 'self'`, 인라인 스타일 금지)를 끄지 않는다 — 위반은 콘솔 오류로 드러나 '콘솔 오류 없음' 단언이 잡는다.
문자열 `wait_for_function` 은 CSP 가 막으므로 선언적 대기(`expect`)만 쓴다.

`all(...)` 은 빈 목록에 항상 참이다 — 측정 대상이 실제로 있었는지(검사한 요소 수)를 먼저 단언한다.
playwright 나 Chrome 이 없으면 모듈 전체를 건너뛴다.
"""
from __future__ import annotations

import importlib.util
import itertools
import json
import re
import socket
import threading
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

pytest.importorskip("playwright.sync_api", reason="playwright 가 설치되어 있지 않다")
pytest.importorskip("uvicorn", reason="uvicorn 이 설치되어 있지 않다")
from playwright.sync_api import expect, sync_playwright  # noqa: E402

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
if not Path(CHROME).exists():
    pytest.skip(f"Chrome 실행 파일이 없다: {CHROME}", allow_module_level=True)

import uvicorn  # noqa: E402

from swinventory.common.models import KernelInfo, OsInfo, PackageRecord, Snapshot  # noqa: E402
from swinventory.server import app as server_app  # noqa: E402
from swinventory.server.app import ApiSettings, create_app  # noqa: E402
from swinventory.server.repo.sql import SqlInventoryRepository  # noqa: E402
from swinventory.server.services.ingest import IngestService  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB = Path(server_app.WEB_DIR)   # 서버가 서빙하는 정적 파일 디렉터리 — 소스 단언도 같은 곳을 읽는다
ADMIN_ONLY = "관리자 토큰으로 로그인해야 합니다"
CLUSTER_A = "a1" * 32
BIG_HOST = "b" * 32
RD, ADM, ING = "rd", "adm", "ing"

# 한 화면씩(해시 라우트) — 상세 화면은 site 에서 만든 id 로 채운다
STATIC_ROUTES = [
    "#/overview", "#/kernels", "#/software", "#/software/openssl", "#/hosts", "#/assets", "#/assets/new", "#/containers",
    "#/containers/images", "#/containers/list", "#/events", "#/network", "#/network/ports", "#/network/ports/tcp/22",
    "#/reports", "#/reports/facts", "#/enroll", "#/settings",
]


# --------------------------------------------------------------------------- 서버·브라우저 준비

def _load_seed():
    spec = importlib.util.spec_from_file_location("seed_demo_for_ui", REPO_ROOT / "scripts" / "seed_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(app) -> tuple[uvicorn.Server, threading.Thread, str]:
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not server.started:
        assert time.time() < deadline, "서버가 시작되지 않았다"
        time.sleep(0.05)
    return server, thread, f"http://127.0.0.1:{port}"


def call(base: str, path: str, token: str = ADM, method: str = "GET", body=None):
    req = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as res:
        raw = res.read()
    return json.loads(raw) if raw else None


@contextmanager
def host_tags(base: str, host_id: str, tags: dict[str, str] | None):
    """호스트 태그를 잠시 바꾸고(관리자 API) 끝나면 원래대로 돌린다 — 모듈 단위로 공유하는 시드를 뒤의 테스트도 본다. tags 가 None 이면 아무것도 하지 않는다."""
    if tags is None:
        yield
        return
    before = call(base, f"/v1/hosts/{host_id}")["tags"]
    call(base, f"/v1/hosts/{host_id}/tags", method="PUT", body=tags)
    try:
        yield
    finally:
        call(base, f"/v1/hosts/{host_id}/tags", method="PUT", body=before)


@dataclass
class Site:
    base: str
    base_with_agents: str
    unknown_kind_host: str      # 자산 미등록 + 장비 정보 없음(구분을 알 수 없음)
    unregistered_vm_host: str   # 자산 미등록 + VM 으로 감지
    mismatch_asset: int         # 대장과 수집값이 어긋난 자산(P-1099)
    linked_asset: int
    report_id: int

    def route(self, name: str) -> str:
        return {"host_detail": f"#/hosts/{self.unknown_kind_host}", "cluster": f"#/containers/clusters/{CLUSTER_A}",
                "asset_edit": f"#/assets/{self.mismatch_asset}", "report": f"#/reports/{self.report_id}",
                "big_host": f"#/hosts/{BIG_HOST}"}[name]


def _add_big_host(repo, now: datetime) -> None:
    """패키지 450개 호스트 — 200행 상한·'더 보기'·버전 정렬(2.2.x < 2.10.x)을 시험하려면 행이 많아야 한다."""
    pkgs = [PackageRecord("dpkg", f"pkg-{i:03d}", f"2.{i % 12}.{i % 5}", "amd64") for i in range(450)]
    snap = Snapshot(host_id=BIG_HOST, hostname="big01.corp.example", collected_at=now.isoformat(), agent_version="0.1.0",
                    os=OsInfo("debian", "Ubuntu 22.04.4 LTS", "22.04"), kernel=KernelInfo("5.15.0-100-generic", ("5.15.0-100-generic",), False),
                    packages=pkgs, interfaces=[], ports=[], hardware=None, containers=[], k8s=None,
                    collected=["os", "kernel", "software.dpkg"], errors={})
    IngestService(repo, clock=lambda: now).ingest(snap)


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    root = tmp_path_factory.mktemp("ui")
    url = f"sqlite:///{root / 'ui.db'}"
    now = datetime.now(timezone.utc)
    _load_seed().seed(url, now)
    repo = SqlInventoryRepository.from_url(url)
    _add_big_host(repo, now)
    repo.add_report(now.isoformat(), "test-model", "# 제목\n\n| 열 | 값 |\n|---|---|\n| a | 1 |\n\n- 항목", {"hosts": 1}, 10, 20)
    settings = ApiSettings(ingest_tokens=(ING,), read_tokens=(RD,), admin_tokens=(ADM,))
    empty_agents = root / "agents-empty"
    empty_agents.mkdir()
    full_agents = root / "agents-full"
    full_agents.mkdir()
    for name in ("swinventory-agent.pyz", "install.sh", "swinventory-agent-win-x64.exe", "install.ps1"):
        (full_agents / name).write_bytes(b"x" * 64)
    s1, t1, base = _serve(create_app(repo, settings, env={}, agent_dir=empty_agents))
    s2, t2, base2 = _serve(create_app(repo, settings, env={}, agent_dir=full_agents))

    unreg = call(base, "/v1/assets?status=unregistered")
    unknown = next(r for r in unreg if r["kind"] == "unknown" and r["host_id"] != BIG_HOST)
    vm = next(r for r in unreg if r["kind"] == "virtual")
    assets = call(base, "/v1/assets")
    mismatch = next(r for r in assets if r["asset"] and r["flags"])["asset"]["id"]
    linked = next(r for r in assets if r["asset"] and r["status"] == "linked" and not r["flags"])["asset"]["id"]
    reports = call(base, "/v1/reports")
    yield Site(base, base2, unknown["host_id"], vm["host_id"], mismatch, linked, reports[0]["id"])
    for s in (s1, s2):
        s.should_exit = True
    for t in (t1, t2):
        t.join(10)


EVENT_HOST = "ee" * 16
EARLY_AT, LATE_AT = "2026-11-05T14:00:00+00:00", "2026-11-05T16:00:00+00:00"    # 서울 11-05 23:00 · 11-06 01:00 — 로컬 자정(11-05T15:00Z)이 둘 사이에 있다


@pytest.fixture(scope="module")
def events_base(tmp_path_factory):
    """변경 이력이 정해진 순간(UTC)에 찍힌 별도 서버. '이후' 날짜가 로컬 자정으로 해석되는지를 시각이 정해진 데이터로 본다(공용 시드의 이벤트는 '지금' 기준이라 못 쓴다)."""
    root = tmp_path_factory.mktemp("events")
    repo = SqlInventoryRepository.from_url(f"sqlite:///{root / 'ev.db'}")
    ingest = IngestService(repo, clock=lambda: datetime(2026, 11, 6, tzinfo=timezone.utc))

    def snap(at: str, names: list[str]) -> Snapshot:
        return Snapshot(host_id=EVENT_HOST, hostname="tz01.corp.example", collected_at=at, agent_version="0.1.0",
                        os=OsInfo("debian", "Ubuntu 22.04.4 LTS", "22.04"), kernel=KernelInfo("5.15.0-100-generic", ("5.15.0-100-generic",), False),
                        packages=[PackageRecord("dpkg", n, "1.0", "amd64") for n in names], interfaces=[], ports=[], hardware=None, containers=[], k8s=None,
                        collected=["os", "kernel", "software.dpkg"], errors={})

    ingest.ingest(snap("2026-11-05T10:00:00+00:00", []))                    # 첫 스냅샷은 기준선 — 이벤트 없음
    ingest.ingest(snap(EARLY_AT, ["early-pkg"]))                            # 이벤트: early-pkg 설치
    ingest.ingest(snap(LATE_AT, ["early-pkg", "late-pkg"]))                 # 이벤트: late-pkg 설치
    agents = root / "agents"
    agents.mkdir()
    server, thread, base = _serve(create_app(repo, ApiSettings(ingest_tokens=(ING,), read_tokens=(RD,), admin_tokens=(ADM,)), env={}, agent_dir=agents))
    yield base
    server.should_exit = True
    thread.join(10)


@pytest.fixture(scope="module")
def chrome():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=CHROME, headless=True)
        yield browser
        browser.close()


@pytest.fixture
def make_page(chrome):
    contexts = []

    def make(token: str | None = ADM, width: int = 1360, height: int = 900, scheme: str = "light", timezone_id: str | None = None):
        # timezone_id: 시각 표시·날짜 입력이 브라우저 시간대에 기대는 시험은 기계의 시간대에 맡기지 않고 고정한다(None 이면 기본값)
        ctx = chrome.new_context(viewport={"width": width, "height": height}, color_scheme=scheme, accept_downloads=True, timezone_id=timezone_id)
        if token:
            ctx.add_init_script(f"try {{ sessionStorage.setItem('swinv.token', {json.dumps(token)}); }} catch (e) {{}}")
        page = ctx.new_page()
        page.problems = []   # 콘솔 오류·미처리 예외(CSP 위반 포함)
        page.on("console", lambda m: page.problems.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)
        page.on("pageerror", lambda e: page.problems.append(f"pageerror: {e}"))
        contexts.append(ctx)
        return page

    yield make
    for ctx in contexts:
        ctx.close()


_seq = itertools.count(1)
READY = "#app table, #app .empty, #app .error, #app form, #app .panel, #app .cards, #app pre"


def settle(page) -> None:
    """화면이 그려졌다는 신호(제목 + 표/빈 상태/오류/폼/패널) — 고정 대기 없이 선언적으로 기다린다."""
    expect(page.locator("#app h1").first).to_be_visible()
    expect(page.locator(READY).first).to_be_visible()


def open_route(page, base: str, route: str, *, expand_inventory: bool = True) -> None:
    """매번 새 문서로 연다(?v=N) — 해시만 바꾸면 이전 화면이 남아 '그려졌다' 신호가 거짓이 된다."""
    page.goto(f"{base}/?v={next(_seq)}{route}")
    settle(page)
    if expand_inventory:
        expand_groups(page)


def expand_groups(page):
    """기존 표 동작 검사는 사용자가 요약을 펼친 후 진행한다."""
    for details in page.locator("details.server-group, details.inventory-section").all():
        if details.get_attribute("open") is None:
            details.locator(":scope > summary").click()
    for body in page.locator(".server-group-body").all():
        expect(body.locator("table, .empty, .error").first).to_be_visible()


def all_routes(site: Site) -> list[str]:
    return STATIC_ROUTES + [site.route("host_detail"), site.route("big_host"), site.route("asset_edit"), site.route("cluster"), site.route("report"),
                            "#/containers/images/nginx"]


def csv_query(page, button: str = "CSV 내보내기") -> dict[str, list[str]]:
    """CSV 버튼을 눌러 실제로 나가는 요청의 쿼리를 읽는다."""
    with page.expect_request(lambda r: "format=csv" in r.url) as info:
        page.get_by_role("button", name=button).click()
    return parse_qs(urlparse(info.value.url).query)


def hash_query(page) -> dict[str, list[str]]:
    frag = page.evaluate("() => location.hash")
    return parse_qs(frag.split("?", 1)[1]) if "?" in frag else {}


# --------------------------------------------------------------------------- A. 역할·로그인

def test_login_distinguishes_invalid_ingest_only_and_unreachable(site, make_page):
    page = make_page(token=None)
    page.goto(site.base + "/")
    box = page.get_by_label("토큰")
    expect(box).to_be_visible()
    expect(box).to_have_attribute("placeholder", "조회 토큰 또는 관리자 토큰")

    def attempt(token: str) -> None:
        page.get_by_label("토큰").fill(token)
        page.get_by_role("button", name="로그인").click()

    attempt("wrong-token")
    expect(page.get_by_role("alert")).to_have_text("토큰이 올바르지 않습니다.")
    attempt("틀린-토큰")      # 한글은 헤더에 못 실린다 — fetch 예외를 '서버 연결 실패'로 오해하면 안 된다
    expect(page.get_by_role("alert")).to_have_text("토큰이 올바르지 않습니다.")
    attempt(ING)
    expect(page.get_by_role("alert")).to_have_text("이 토큰으로는 조회할 수 없습니다(수집 전용).")
    page.route("**/v1/whoami", lambda route: route.abort())           # 네트워크 단절
    attempt(RD)
    expect(page.get_by_role("alert")).to_have_text("서버에 연결할 수 없습니다(잠시 후 다시 시도).")
    page.unroute("**/v1/whoami")
    page.route("**/v1/whoami", lambda route: route.fulfill(status=503, body="down"))     # 5xx
    attempt(RD)
    expect(page.get_by_role("alert")).to_have_text("서버에 연결할 수 없습니다(잠시 후 다시 시도).")


@pytest.mark.parametrize("token, label", [(ADM, "관리자"), (RD, "조회 전용")])
def test_role_badge_shows_after_login_and_after_reload(site, make_page, token, label):
    page = make_page(token=None)
    page.goto(site.base + "/")
    page.get_by_label("토큰").fill(token)
    page.get_by_role("button", name="로그인").click()
    expect(page.locator("#role")).to_have_text(label)
    expect(page.locator("#app h1").first).to_be_visible()
    page.reload()                                                         # 저장된 토큰으로 다시 열어도 whoami 로 역할을 안다
    expect(page.locator("#role")).to_have_text(label)
    assert page.problems == []


# 조회 전용 토큰이면 비활성 + 이유(툴팁), 관리자면 활성인 컨트롤 전부 — (화면, 컨트롤을 찾는 방법)
def _controls(site: Site):
    btn = lambda name: (lambda p: p.get_by_role("button", name=name, exact=True))  # noqa: E731
    return [
        (site.route("host_detail"), "호스트 삭제", btn("호스트 삭제")),
        (site.route("host_detail"), "태그 저장", lambda p: p.locator(".panel", has=p.get_by_label("태그 (key=value, 한 줄에 하나)")).get_by_role("button", name="저장")),
        (site.route("host_detail"), "자산으로 등록", btn("자산으로 등록")),
        ("#/assets", "자산 추가", btn("자산 추가")),
        ("#/assets/new", "신규 저장", btn("저장")),
        (site.route("asset_edit"), "자산 저장", btn("저장")),
        (site.route("asset_edit"), "자산 삭제", btn("삭제")),
        (site.route("asset_edit"), "수집값 적용", lambda p: p.get_by_role("button", name=re.compile("수집값 적용")).first),
        (site.route("cluster"), "클러스터 이름 저장", btn("저장")),
        ("#/reports", "리포트 생성", btn("AI 리포트 생성")),
        (site.route("report"), "리포트 삭제", btn("삭제")),
        ("#/settings", "하한선 저장", lambda p: p.get_by_role("button", name="저장", exact=True).first),
        ("#/settings", "규칙 추가", btn("+ 규칙 추가")),
        ("#/enroll", "토큰 포함", lambda p: p.get_by_label("토큰 포함(관리자)")),
    ]


def test_read_token_sees_admin_controls_disabled_with_reason_and_admin_sees_them_enabled(site, make_page):
    checked = 0
    for token, enabled in ((RD, False), (ADM, True)):
        page = make_page(token=token)
        for route, name, find in _controls(site):
            if name == "수집값 적용" and enabled:
                continue    # 이미 같은 값이면 관리자에게도 꺼져 있을 수 있다(아래에서 따로 본다)
            open_route(page, site.base, route)
            control = find(page)
            expect(control, f"{token}:{route}:{name}").to_be_visible()
            if enabled:
                expect(control, f"{token}:{route}:{name}").to_be_enabled()
            else:
                expect(control, f"{token}:{route}:{name}").to_be_disabled()
                expect(control, f"{token}:{route}:{name}").to_have_attribute("title", ADMIN_ONLY)
            checked += 1
        assert page.problems == [], (token, page.problems)      # 조회 전용 토큰으로도 403 콘솔 오류가 나지 않는다(AI 설정은 요청하지 않는다)
    assert checked >= 2 * len(_controls(site)) - 1


def test_read_token_inputs_are_blocked_so_nobody_fills_a_form_for_a_403(site, make_page):
    page = make_page(token=RD)
    open_route(page, site.base, "#/assets/new")
    for label in ("자산번호 *", "구분 *", "시리얼", "호스트명", "관리 IP", "비고"):
        expect(page.get_by_label(label)).to_be_disabled()
    expect(page.get_by_text(ADMIN_ONLY).first).to_be_visible()                           # 이유가 눈에 보이는 문장으로도 있다
    open_route(page, site.base, "#/assets?status=unregistered")
    expect(page.get_by_role("link", name="등록", exact=True)).to_have_count(0)           # 만들 수 없는 사람에게 '등록' 링크를 주지 않는다
    expect(page.locator("td span[aria-disabled='true']", has_text="등록").first).to_have_attribute("title", ADMIN_ONLY)
    open_route(page, site.base, "#/assets?status=linked")
    expect(page.get_by_role("link", name="편집", exact=True)).to_have_count(0)           # 읽기 전용이니 '편집' 대신 '보기'
    expect(page.get_by_role("link", name="보기", exact=True).first).to_be_visible()
    open_route(page, site.base, site.route("host_detail"))
    expect(page.get_by_label("태그 (key=value, 한 줄에 하나)")).to_have_js_property("readOnly", True)
    open_route(page, site.base, "#/settings")
    expect(page.get_by_text("AI 연결 설정을 보려면 " + ADMIN_ONLY)).to_be_visible()
    for sel in page.locator(".rule select, .rule input").all():
        expect(sel).to_be_disabled()


def test_every_403_is_the_same_single_message(site, make_page):
    """서버가 403 을 주는 모든 쓰기 경로가 같은 한 문장(상수)으로 안내한다."""
    page = make_page(token=ADM)
    page.route("**/v1/hosts/*/tags", lambda r: r.fulfill(status=403, json={"detail": "insufficient role"}))
    open_route(page, site.base, site.route("host_detail"))
    page.locator(".panel", has=page.get_by_label("태그 (key=value, 한 줄에 하나)")).get_by_role("button", name="저장").click()
    expect(page.get_by_role("alert").filter(has_text=ADMIN_ONLY)).to_be_visible()

    page.route("**/v1/k8s/clusters/*/name", lambda r: r.fulfill(status=403, json={"detail": "insufficient role"}))
    open_route(page, site.base, site.route("cluster"))
    page.get_by_role("button", name="저장", exact=True).click()
    expect(page.get_by_role("alert").filter(has_text=ADMIN_ONLY)).to_be_visible()

    page.route("**/v1/settings/kernel-policy", lambda r: r.fulfill(status=403, json={"detail": "x"}) if r.request.method == "PUT" else r.continue_())
    open_route(page, site.base, "#/settings")
    page.get_by_role("button", name="저장", exact=True).first.click()
    expect(page.get_by_role("alert").filter(has_text=ADMIN_ONLY)).to_be_visible()

    page.route("**/v1/assets/*", lambda r: r.fulfill(status=403, json={"detail": "x"}) if r.request.method == "PUT" else r.continue_())
    open_route(page, site.base, site.route("asset_edit"))
    page.get_by_role("button", name="저장", exact=True).click()
    expect(page.get_by_role("alert").filter(has_text=ADMIN_ONLY)).to_be_visible()


def test_source_has_the_admin_message_exactly_once_and_no_old_variants():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert js.count(f'"{ADMIN_ONLY}"') == 1, "관리자 안내 문구는 상수 하나로만 정의한다"
    for old in ("관리자(admin) 토큰", "토큰이 필요합니다"):
        assert old not in js, old


# --------------------------------------------------------------------------- B. 모바일(390px)

def test_no_horizontal_overflow_at_390_on_every_route(site, make_page):
    page = make_page(width=390, height=844)
    offenders, checked = [], 0
    for route in all_routes(site):
        open_route(page, site.base, route)
        width = page.evaluate("() => [document.documentElement.scrollWidth, document.documentElement.clientWidth, document.body.scrollWidth]")
        checked += 1
        if max(width) > 390:
            offenders.append((route, width))
    assert checked == len(all_routes(site)) and checked > 20
    assert offenders == [], offenders
    assert page.problems == []


def test_mobile_header_nav_is_one_scrollable_row_and_logout_stays_reachable(site, make_page):
    page = make_page(width=390, height=844)
    open_route(page, site.base, "#/overview")
    nav = page.locator("#nav")
    box = nav.evaluate("""(el) => { const links = [...el.querySelectorAll('a')].map((a) => a.getBoundingClientRect());
        return { scrollW: el.scrollWidth, clientW: el.clientWidth, overflowX: getComputedStyle(el).overflowX,
                 tops: [...new Set(links.map((r) => Math.round(r.top)))], maxH: Math.max(...links.map((r) => r.height)) }; }""")
    assert box["scrollW"] > box["clientW"] and box["overflowX"] in ("auto", "scroll"), box     # 넘치는 메뉴는 가로로 스크롤
    assert len(box["tops"]) == 1, box                                                          # 한 줄(줄바꿈으로 쌓이지 않음)
    assert box["maxH"] < 60, box                                                               # 글자가 세로로 쌓이면 링크 높이가 커진다
    logout = page.get_by_role("button", name="로그아웃").bounding_box()
    assert logout and 0 <= logout["x"] and logout["x"] + logout["width"] <= 390, logout
    page.get_by_role("button", name="로그아웃").click()
    expect(page.get_by_label("토큰")).to_be_visible()


def test_mobile_layouts_collapse_and_tables_scroll_inside_their_container(site, make_page):
    page = make_page(width=390, height=844, token=ADM)
    # 폼·규칙·kv·등록 격자는 한 열
    open_route(page, site.base, "#/assets/new")
    cols = page.locator("form.form").evaluate("el => getComputedStyle(el).gridTemplateColumns.split(' ').length")
    assert cols == 1, cols
    open_route(page, site.base, "#/settings")
    page.get_by_role("button", name="+ 규칙 추가").click()
    assert page.locator(".rule").first.evaluate("el => getComputedStyle(el).gridTemplateColumns.split(' ').length") == 1
    open_route(page, site.base, site.route("host_detail"))
    assert page.locator("dl.kv").first.evaluate("el => getComputedStyle(el).gridTemplateColumns.split(' ').length") == 1
    assert page.locator(".grid2").first.evaluate("el => getComputedStyle(el).gridTemplateColumns.split(' ').length") == 1
    page.goto(f"{site.base_with_agents}/?v={next(_seq)}#/enroll")
    expect(page.locator(".enroll-grid")).to_be_visible()
    assert page.locator(".enroll-grid").evaluate("el => getComputedStyle(el).gridTemplateColumns.split(' ').length") == 1
    # 표는 칸이 찌그러지지 않고 .scroll 안에서 가로로 스크롤된다
    open_route(page, site.base, "#/hosts")
    scroll = page.locator(".scroll").first
    metrics = scroll.evaluate("el => ({sw: el.scrollWidth, cw: el.clientWidth, tw: el.querySelector('table').offsetWidth, ox: getComputedStyle(el).overflowX})")
    assert metrics["tw"] >= 560 and metrics["sw"] > metrics["cw"] and metrics["ox"] in ("auto", "scroll"), metrics
    narrow = scroll.evaluate("el => Math.min(...[...el.querySelectorAll('thead th')].map((t) => t.getBoundingClientRect().width))")
    assert narrow >= 40, narrow
    cols = scroll.locator("thead th").count()
    assert page.locator(".scroll table").first.evaluate("el => getComputedStyle(el).minWidth") == f"{cols * 104}px"   # 열 수에 비례한 바닥
    open_route(page, site.base, "#/software?q=open")                 # 서버의 패키지 표는 열 수에 맞는 최소 폭을 유지한다
    expect(page.locator(".scroll table").first).to_be_visible()
    assert page.locator(".scroll table").first.evaluate("el => getComputedStyle(el).minWidth") == "416px"
    assert page.locator(".scroll").first.evaluate("el => el.scrollWidth > el.clientWidth")


# --------------------------------------------------------------------------- C. 표

def test_mono_cells_never_break_inside_a_token(site, make_page):
    for width in (1360, 390):
        page = make_page(width=width, height=900)
        open_route(page, site.base, "#/hosts")
        cells = page.locator("td.mono")
        assert cells.count() > 20
        style = cells.first.evaluate("el => ({wb: getComputedStyle(el).wordBreak, ow: getComputedStyle(el).overflowWrap})")
        assert style["wb"] != "break-all" and style["ow"] == "break-word", (width, style)
        # IP 칸(두 번째 mono 열): 토큰 하나가 한 줄에 그려져야 한다
        lines = page.locator("td.mono").evaluate_all("""(tds) => tds.map((td) => {
            const ip = (td.textContent.match(/\\d+\\.\\d+\\.\\d+\\.\\d+/) || [])[0]; if (!ip) return null;
            const walker = document.createTreeWalker(td, NodeFilter.SHOW_TEXT); let node, hit = null;
            while ((node = walker.nextNode())) { const i = node.textContent.indexOf(ip); if (i >= 0) { hit = [node, i]; break; } }
            if (!hit) return null;
            const range = document.createRange(); range.setStart(hit[0], hit[1]); range.setEnd(hit[0], hit[1] + ip.length);
            return new Set([...range.getClientRects()].map((r) => Math.round(r.top))).size; }).filter((n) => n !== null)""")
        assert len(lines) >= 20 and set(lines) == {1}, (width, lines)


def test_h1_mono_keeps_the_heading_size(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/software/openssl")
    size = page.locator("h1.mono").evaluate("el => parseFloat(getComputedStyle(el).fontSize)")
    assert size >= 18, size
    assert page.locator("td.mono").first.evaluate("el => parseFloat(getComputedStyle(el).fontSize)") <= 14   # 표 안 mono 는 작게 유지


def test_sortable_headers_sort_stably_and_expose_aria_sort(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/hosts")
    names = lambda: page.locator("tbody tr td:nth-child(2)").all_inner_texts()   # noqa: E731 — 호스트 열
    original = names()
    assert len(original) == 29                                                   # 시드 28 + 큰 호스트
    header = page.locator("thead th", has_text="호스트").first
    header.get_by_role("button").click()
    expect(header).to_have_attribute("aria-sort", "ascending")
    asc = names()
    assert asc == sorted(original, key=lambda s: s.casefold()), asc[:4]             # 이름순(대소문자 무시)
    assert asc != original
    header.get_by_role("button").click()
    expect(header).to_have_attribute("aria-sort", "descending")
    assert names() == list(reversed(asc))
    header.get_by_role("button").click()
    expect(header).not_to_have_attribute("aria-sort", re.compile("."))
    assert names() == original                                                   # 세 번째 클릭은 원래 순서로

    # 안정 정렬: 같은 값(상태)끼리는 오름·내림 어느 쪽에서도 원래 순서를 지킨다(내림차순을 '오름차순 뒤집기'로 만들면 동률이 뒤집힌다)
    status = page.locator("thead th", has_text="상태").first
    for direction in ("ascending", "descending"):
        status.get_by_role("button").click()
        expect(status).to_have_attribute("aria-sort", direction)
        rows = page.locator("tbody tr").evaluate_all("trs => trs.map((tr) => [tr.children[0].textContent.trim(), tr.children[1].textContent.trim()])")
        same = [h for s, h in rows if s == "정상"]
        assert len(same) >= 20 and same == [h for h in original if h in set(same)], (direction, "같은 키의 원래 순서가 바뀌었다")


def test_blank_values_sort_last_in_both_directions_and_count_columns_start_descending(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/hosts")
    domain_col = page.locator("thead th", has_text="도메인").first
    cells = lambda: page.locator("tbody tr td:nth-child(5)").all_inner_texts()   # noqa: E731 — 도메인(상태·호스트·자산번호·구분 다음)
    assert "-" in cells() and "corp.example" in cells()                          # 비어 있는 칸(장비 정보가 없는 호스트)이 실제로 있다
    for direction in ("ascending", "descending"):
        domain_col.get_by_role("button").click()
        expect(domain_col).to_have_attribute("aria-sort", direction)
        values = cells()
        assert values[-1] == "-" and values.count("-") >= 1, (direction, values[-3:])     # 빈 값은 방향과 상관없이 맨 뒤
        first_blank = values.index("-")
        assert set(values[first_blank:]) == {"-"}, (direction, values)
    # 개수 열의 첫 클릭은 내림차순이다.
    open_route(page, site.base, "#/containers/images")
    count_col = page.locator("thead th").filter(has_text=re.compile("^호스트")).first
    count_col.get_by_role("button").click()
    expect(count_col).to_have_attribute("aria-sort", "descending")
    counts = [int(c) for c in page.locator("tbody tr td:nth-child(2)").all_inner_texts()]
    assert counts == sorted(counts, reverse=True) and len(set(counts)) > 1, counts


def test_version_columns_sort_by_number_tokens(site, make_page):
    page = make_page()
    open_route(page, site.base, site.route("big_host"))
    section = page.locator(".table-wrap", has=page.locator("th", has_text="아키텍처"))
    header = section.locator("thead th", has_text="버전")
    key = lambda v: tuple(int(x) for x in v.split("."))   # noqa: E731
    everything = [f"2.{i % 12}.{i % 5}" for i in range(450)]
    # 오름차순: 앞 200행은 2.0.x … 2.5.x 라 사전순과 같아 보이므로, 구분은 내림차순에서 한다
    header.get_by_role("button").click()
    expect(header).to_have_attribute("aria-sort", "ascending")
    asc = section.locator("tbody tr td:nth-child(2)").all_inner_texts()
    assert [key(v) for v in asc] == [key(v) for v in sorted(everything, key=key)[:200]]
    header.get_by_role("button").click()
    expect(header).to_have_attribute("aria-sort", "descending")
    desc = section.locator("tbody tr td:nth-child(2)").all_inner_texts()
    assert [key(v) for v in desc] == [key(v) for v in sorted(everything, key=key, reverse=True)[:200]]
    assert desc[0].startswith("2.11."), desc[:3]                    # 사전순 내림차순이면 2.9.x 로 시작한다
    # 안정 정렬: 같은 버전은 원래(패키지명) 순서
    names = section.locator("tbody tr td:nth-child(1)").all_inner_texts()
    same = [n for n, v in zip(names, desc) if v == desc[0]]
    assert same == sorted(same), same


def test_tables_render_200_rows_then_show_more(site, make_page):
    page = make_page()
    open_route(page, site.base, site.route("big_host"))
    section = page.locator(".table-wrap", has=page.locator("th", has_text="아키텍처"))
    rows = section.locator("tbody tr")
    expect(rows).to_have_count(200)
    more = section.get_by_role("button", name=re.compile("개 더 보기"))
    expect(more).to_have_text("200개 더 보기")
    expect(section.get_by_role("status")).to_have_text("전체 450개 중 200개 표시")
    more.click()
    expect(rows).to_have_count(400)
    expect(more).to_have_text("50개 더 보기")
    more.click()
    expect(rows).to_have_count(450)
    expect(more).to_be_hidden()
    # 28행 표에는 '더 보기'도 '전체 N개 중' 안내도 없다(hidden 속성이 display:flex 에 눌리지 않아야 한다)
    open_route(page, site.base, "#/hosts")
    expect(page.get_by_role("button", name=re.compile("개 더 보기"))).to_have_count(0)
    expect(page.locator(".table-wrap .more")).to_be_hidden()


def test_long_table_header_really_sticks_while_the_container_scrolls(site, make_page):
    for route in ("#/hosts", site.route("big_host")):
        page = make_page(height=900)
        open_route(page, site.base, route)
        box = page.locator(".scroll.tall").last
        expect(box, f"{route}: 긴 표(.tall)가 없다").to_be_visible()
        assert box.evaluate("el => el.scrollHeight > el.clientHeight"), f"{route}: 컨테이너 안에서 세로로 스크롤되지 않는다"
        before = box.evaluate("el => el.querySelector('thead th').getBoundingClientRect().top - el.getBoundingClientRect().top")
        scrolled = box.evaluate("el => { el.scrollTop = 400; return el.scrollTop; }")
        assert scrolled > 100, scrolled
        after = box.evaluate("el => el.querySelector('thead th').getBoundingClientRect().top - el.getBoundingClientRect().top")
        assert abs(after - before) <= 2 and 0 <= after <= 3, (route, before, after)         # 스크롤해도 머리글이 컨테이너 위쪽에 붙어 있다
        first_row = box.evaluate("el => el.querySelector('tbody tr').getBoundingClientRect().top - el.getBoundingClientRect().top")
        assert first_row < 0, "본문은 실제로 스크롤됐어야 한다"


@pytest.mark.parametrize("width, inner_scroll", [(390, False), (640, False), (641, True), (1360, True)])
def test_long_table_scrolls_with_the_page_on_phones_and_inside_its_box_on_desktop(site, make_page, width, inner_scroll):
    """휴대폰(≤640px)에서는 표 안쪽 세로 스크롤이 페이지 스크롤과 겹쳐 손가락이 표 안에 갇힌다 — 높이 제한을 풀고 페이지와 함께 스크롤한다
    (대신 이 폭에서는 머리글 고정이 없다). 데스크톱은 머리글 고정을 위해 75vh 로 제한한 채 그대로다(위 시험이 고정을 확인한다). 경계(640/641)도 본다."""
    page = make_page(width=width, height=900)
    open_route(page, site.base, "#/hosts")
    box = page.locator(".scroll.tall")
    expect(box).to_have_count(1)                                          # 28행 > 10행이라 긴 표다
    m = box.evaluate("""el => ({ maxHeight: getComputedStyle(el).maxHeight, inner: el.scrollHeight > el.clientHeight + 1,
                                 vh: window.innerHeight, pageH: document.documentElement.scrollHeight })""")
    if inner_scroll:
        assert m["maxHeight"] == f"{m['vh'] * 0.75:g}px" and m["inner"], m     # 75vh 로 제한 → 표 안에서 세로 스크롤
    else:
        assert m["maxHeight"] == "none" and not m["inner"], m                  # 제한 없음 → 표 안쪽 세로 스크롤 없음
        assert m["pageH"] > m["vh"], m                                         # 대신 페이지가 길어져 페이지 스크롤로 본다


# 칸 하나가 글자 단위로 찌그러져 행이 4~5줄이 되던 결함(호스트 표 — 390px 에서 79~122px, 1360px 에서 65~80px)의 회귀 가드.
# 원인: 자산번호 칸을 통째로 nowrap 으로 둬 '구분 불일치 IP 불일치' 배지까지 한 줄로 묶여 열이 200px 가 되고, auto 레이아웃이 OS 칸을 66px(min-content)로 줄여
# 'Rocky Linux 9.4 (Blue Onyx)' 가 3~5줄로 쌓였다. 태그 칩도 좁은 칸에서 한 줄에 하나씩 쌓였다.
ROW_METRICS_JS = """() => {
  const td = document.querySelector('#app tbody td');
  const cs = getComputedStyle(td);
  const box = document.querySelector('#app .scroll');
  const flagged = [...document.querySelectorAll('#app td.asset')].find((c) => c.querySelectorAll('.badge').length >= 2);
  return {
    lineHeight: parseFloat(cs.lineHeight),
    gutter: parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom) + parseFloat(cs.borderBottomWidth),     // 행의 세로 여백: 칸 위아래 패딩 + 아래 선
    fits: box.scrollWidth <= box.clientWidth,
    flagged: flagged ? { cell: getComputedStyle(flagged).whiteSpace, link: getComputedStyle(flagged.querySelector('a')).whiteSpace } : null,
    rows: [...document.querySelectorAll('#app tbody tr')].map((tr) => ({ host: tr.children[1].textContent.trim(), height: tr.getBoundingClientRect().height })),
  };
}"""


@pytest.mark.parametrize("width", [390, 1360])
@pytest.mark.parametrize("tags", [None, {"env": "pre-prod", "team": "web-platform"}], ids=["seed", "hyphenated-tags"])
def test_hosts_table_rows_never_need_more_than_two_text_lines(site, make_page, width, tags):
    """모든 행의 높이가 '두 줄'을 넘지 않는다 — 한도는 렌더된 줄 높이·칸 여백에서 계산한다(고정 픽셀 없음).
    시드에는 대장과 수집값이 어긋나 배지가 둘 붙는 자산(P-1099)이 있고, 'hyphenated-tags' 는 그 호스트에 하이픈이 있는 긴 태그 값을 얹은 최악 조합이다."""
    mismatched_host = call(site.base, f"/v1/assets/{site.mismatch_asset}")["host_id"]
    with host_tags(site.base, mismatched_host, tags):
        page = make_page(width=width, height=900)
        open_route(page, site.base, "#/hosts")
        m = page.evaluate(ROW_METRICS_JS)
    rows = m["rows"]
    assert len(rows) >= 28, len(rows)
    # 측정 대상에 원인 조건이 실제로 있었다: 배지가 둘 이상 붙은 자산번호 칸. 칸은 줄바꿈이 되고(normal) 링크만 끊기지 않는다(nowrap)
    assert m["flagged"] == {"cell": "normal", "link": "nowrap"}, m["flagged"]
    assert isinstance(m["lineHeight"], (int, float)) and m["lineHeight"] > 0, m["lineHeight"]    # 'normal' 이면 NaN 이라 아래 비교가 모두 거짓이 되어 빈 단언이 된다
    two_lines = m["gutter"] + 2 * m["lineHeight"]
    limit = two_lines + m["lineHeight"] / 2          # 인라인 배지·칩 상자가 줄을 조금 키우므로 반 줄의 여유. 세 줄(+1줄)은 넘는다
    tall = sorted(((r["host"], r["height"]) for r in rows if r["height"] > limit), key=lambda t: -t[1])
    assert tall == [], f"{width}px: 두 줄({two_lines}px) 한도 {limit}px 를 넘는 행 {len(tall)}개 — 가장 큰 것 {tall[:3]}"
    if width >= 1360:
        assert m["fits"], "데스크톱 폭에서 호스트 표가 가로로 넘친다 — 열 최소 너비가 너무 크다"


# --------------------------------------------------------------------------- D. 필터 ↔ CSV ↔ URL

def test_csv_buttons_export_exactly_what_the_screen_filters(site, make_page):
    page = make_page(timezone_id="Asia/Seoul")      # '이후' 날짜는 브라우저 로컬 자정 → UTC 시각으로 나간다(아래 변경 이력 단언)

    # 호스트: 상태 + 검색 + 태그(team=infra 도 받는다)
    open_route(page, site.base, "#/hosts")
    page.get_by_label("상태 필터").select_option("error")
    expect(page.locator("#app h1")).to_have_text("호스트 (2)")                       # 시드의 수집 오류 호스트 2대
    page.get_by_label("호스트 검색").fill("db")
    expect(page.locator("#app h1")).not_to_have_text("호스트 (2)")
    q = csv_query(page)
    assert q == {"status": ["error"], "q": ["db"], "format": ["csv"]}, q
    assert hash_query(page) == {"status": ["error"], "q": ["db"]}                      # 주소에도 같은 조건
    page.get_by_label("태그 필터").fill("team=infra")
    page.get_by_label("태그 필터").press("Tab")
    expect(page.locator("#app h1")).to_be_visible()
    assert hash_query(page)["tag"] == ["team:infra"]
    q = csv_query(page)
    assert q["tag"] == ["team:infra"] and q["status"] == ["error"] and q["q"] == ["db"], q

    # 커널: 실행 중 커널 + 재부팅 + 검색
    open_route(page, site.base, "#/kernels?reboot=1&q=web")
    expect(page.get_by_label("호스트 검색")).to_have_value("web")
    expect(page.get_by_label("재부팅 필요만")).to_be_checked()
    q = csv_query(page)
    assert q == {"reboot_required": ["true"], "q": ["web"], "format": ["csv"]}, q

    # 자산: 상태(불일치) + 구분 + 검색
    open_route(page, site.base, "#/assets?status=mismatch&kind=physical")
    page.get_by_label("자산 검색").fill("P-1")
    q = csv_query(page)
    assert q == {"status": ["mismatch"], "kind": ["physical"], "q": ["P-1"], "format": ["csv"]}, q

    # 컨테이너: 이미지 + 클러스터 + 상태 선택 + 검색
    open_route(page, site.base, f"#/containers/list?image=nginx:1.25&cluster={CLUSTER_A}&active=1")
    page.get_by_label("컨테이너 검색").fill("web")
    q = csv_query(page)
    assert q == {"image": ["nginx:1.25"], "cluster": [CLUSTER_A], "active": ["1"], "q": ["web"], "format": ["csv"]}, q

    # IP: 충돌만 + 검색 — 주소(URL)에 남고 새로 고쳐도 유지된다
    open_route(page, site.base, "#/network")
    page.get_by_label("IP·MAC 검색").fill("10.20")
    page.get_by_label("충돌만").check()
    expect(page.get_by_text("IP 충돌", exact=False).first).to_be_visible()
    q = csv_query(page)
    assert q == {"q": ["10.20"], "conflicts": ["true"], "format": ["csv"]}, q
    assert hash_query(page) == {"q": ["10.20"], "conflicts": ["1"]}
    page.reload()
    settle(page)
    expect(page.get_by_label("충돌만")).to_be_checked()
    expect(page.get_by_label("IP·MAC 검색")).to_have_value("10.20")
    expand_groups(page)
    rows = page.locator("tbody tr")
    assert rows.count() >= 2
    assert all("충돌" in t for t in rows.locator("td:last-child").all_inner_texts())    # 충돌 행만 남았다

    # 포트: 프로토콜 + 주의 포트만 + 검색
    open_route(page, site.base, "#/network/ports?proto=tcp&notable=1")
    page.get_by_label("포트·서비스 검색").fill("22")
    q = csv_query(page)
    assert q["proto"] == ["tcp"] and q["notable"] == ["true"] and q["q"] == ["22"] and q["format"] == ["csv"], q

    # 변경 이력: 유형 + 이후 + 건수. 서울의 2020-01-01 00:00 은 2019-12-31T15:00Z — 시간대 없는 값을 보내면 서버가 UTC 로 읽어 9시간 어긋난다
    open_route(page, site.base, "#/events?type=kernel_changed&since=2020-01-01&limit=500")
    q = csv_query(page)
    assert q == {"limit": ["500"], "type": ["kernel_changed"], "since": ["2019-12-31T15:00:00Z"], "format": ["csv"]}, q
    assert page.problems == []


def test_hosts_has_a_csv_button_and_it_downloads_the_filtered_rows(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/hosts?status=error")
    expect(page.locator("tbody tr")).to_have_count(2)                                  # 화면: 수집 오류 호스트 2대
    with page.expect_download() as dl:
        page.get_by_role("button", name="CSV 내보내기").click()
    text = Path(dl.value.path()).read_text(encoding="utf-8-sig")
    lines = text.strip().splitlines()
    assert lines[0] == "hostname,host_id,asset_no,kind,domain,ips,os_name,running,kernel_compliant,reboot_required,status,last_seen,tags"
    assert len(lines) == 3 and all(line.split(",")[10] == "error" for line in lines[1:]), lines     # 화면과 같은 2대
    assert dl.value.suggested_filename == "hosts.csv"


# --------------------------------------------------------------------------- E. 드릴다운

def test_version_bar_click_filters_the_host_list_and_chip_removes_it(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/software/openssl")
    total = page.locator("tbody tr").count()
    bar = page.get_by_role("button", name=re.compile("^3\\.0\\.2 ")).first
    bar_count = int(bar.locator(".n").inner_text())
    assert 0 < bar_count < total
    bar.click()
    expect(page.get_by_role("heading", name=f"설치 호스트 ({bar_count})")).to_be_visible()
    expand_groups(page)
    expect(page.get_by_role("button", name=re.compile("^3\\.0\\.2 ")).first).to_have_attribute("aria-pressed", "true")
    assert hash_query(page) == {"version": ["3.0.2"]}
    rows = page.locator("tbody tr")
    expect(rows).to_have_count(bar_count)
    assert set(page.locator("tbody tr td:nth-child(4)").all_inner_texts()) == {"3.0.2"}    # 버전 열(호스트·자산번호·구분 다음)은 모두 3.0.2
    expect(page.get_by_role("heading", name=f"설치 호스트 ({bar_count})")).to_be_visible()
    # 분포는 필터와 무관하게 전체가 남는다
    assert page.locator(".bars .bar").count() >= 3
    q = csv_query(page)
    assert q["version"] == ["3.0.2"] and q["format"] == ["csv"], q
    # 칩 = 적용 중 필터, 눌러서 해제
    chip = page.locator(".chip", has_text="버전 = 3.0.2")
    expect(chip).to_be_visible()
    chip.get_by_role("button", name=re.compile("필터 해제")).click()
    expect(chip).to_have_count(0)
    expand_groups(page)
    expect(page.locator("tbody tr")).to_have_count(total)
    assert hash_query(page) == {}

    # '이 버전 미만'
    page.get_by_label("이 버전 미만").fill("3.0.11")
    page.get_by_label("이 버전 미만").press("Enter")
    expect(page.locator(".chip", has_text=page.get_by_label("이 버전 미만").input_value() + " 미만")).to_be_visible()
    expand_groups(page)
    assert hash_query(page) == {"below": ["3.0.11"]}
    expect(page.locator(".chip", has_text="3.0.11 미만")).to_be_visible()
    versions = set(page.locator("tbody tr td:nth-child(4)").all_inner_texts())
    assert versions == {"3.0.2"}, versions                                              # 3.0.2 < 3.0.11 (사전순이면 3.0.13·3.0.2 가 뒤섞인다)
    assert csv_query(page)["below"] == ["3.0.11"]
    page.get_by_label("이 버전 미만").fill("0.1")                      # 일치하는 호스트가 없으면 404 가 아니라 빈 상태
    page.get_by_label("이 버전 미만").press("Enter")
    expect(page.locator(".chip", has_text=page.get_by_label("이 버전 미만").input_value() + " 미만")).to_be_visible()
    expand_groups(page)
    expect(page.get_by_text("조건에 맞는 서버 데이터가 없습니다.")).to_be_visible()
    expect(page.get_by_role("heading", name="설치 호스트 (0)")).to_be_visible()
    assert page.locator(".bars .bar").count() >= 3                    # 분포는 그대로
    assert page.problems == []


def test_image_tag_links_and_cluster_scope_carry_through(site, make_page):
    page = make_page()
    # 이미지 목록의 태그 배지 → 그 이미지:태그의 컨테이너 목록
    open_route(page, site.base, "#/containers/images")
    tag = page.get_by_role("link", name=re.compile("^1\\.25 ×")).first
    expect(tag).to_have_attribute("href", re.compile(r"#/containers/list\?image=nginx%3A1\.25&active=1"))
    tag.click()
    settle(page)
    expand_groups(page)
    expect(page.locator(".chip", has_text="이미지: nginx:1.25")).to_be_visible()
    images = page.locator("tbody tr td:nth-child(7)").all_inner_texts()               # 이미지 열(호스트·자산번호·구분·클러스터·파드·컨테이너 다음)
    assert images and all("nginx:1.25" in i for i in images), images
    page.locator(".chip", has_text="이미지:").get_by_role("button").click()
    assert hash_query(page) == {"active": ["1"]}

    # 클러스터 상세 → 이미지 링크가 클러스터를 싣고, 이미지 상세는 범위를 보여 주고 해제할 수 있다
    open_route(page, site.base, site.route("cluster"))
    repo_link = page.get_by_role("link", name="nginx", exact=True).first
    expect(repo_link).to_have_attribute("href", re.compile(f"#/containers/images/nginx\\?cluster={CLUSTER_A}"))
    tag_in_cluster = page.get_by_role("link", name=re.compile("^1\\.2[56] ×")).first
    expect(tag_in_cluster).to_have_attribute("href", re.compile(f"cluster={CLUSTER_A}"))
    repo_link.click()
    settle(page)
    expand_groups(page)
    chip = page.locator(".chip", has_text="클러스터: a1a1a1a1")
    expect(chip).to_be_visible()
    scoped = page.locator("tbody tr").count()
    scoped_hosts = set(page.locator("tbody tr td:nth-child(1)").all_inner_texts())
    # 태그 막대(진짜 버튼) → 컨테이너 목록(이미지:태그 + 클러스터)
    page.locator(".bars button.bar").first.click()
    expect(page.locator(".chip", has_text="클러스터: a1a1a1a1")).to_be_visible()
    assert hash_query(page)["cluster"] == [CLUSTER_A] and hash_query(page)["image"][0].startswith("nginx:")
    page.go_back()
    expect(chip).to_be_visible()
    chip.get_by_role("button", name=re.compile("필터 해제")).click()
    expect(chip).to_have_count(0)
    expand_groups(page)
    expect(page.locator(".chip")).to_have_count(0)
    assert hash_query(page) == {}
    assert page.locator("tbody tr").count() > scoped and len(scoped_hosts) >= 1          # 범위를 해제하면 다른 클러스터·도커 서버도 보인다
    assert page.problems == []


def test_cluster_scope_without_a_match_shows_a_clear_way_out(site, make_page):
    page = make_page()
    open_route(page, site.base, f"#/containers/images/redis?cluster={'b2' * 32}")
    expect(page.get_by_text("이 클러스터에는 이 이미지를 쓰는 컨테이너가 없습니다")).to_be_visible()
    page.locator(".chip").get_by_role("button").click()
    expect(page.locator(".chip")).to_have_count(0)


# --------------------------------------------------------------------------- F. 접근성

NAME_CHECK_JS = """() => {
  const bad = [];
  const nameOf = (el) => {
    const aria = (el.getAttribute('aria-label') || '').trim(); if (aria) return aria;
    const by = el.getAttribute('aria-labelledby');
    if (by) { const t = by.split(/\\s+/).map((id) => (document.getElementById(id) || {}).textContent || '').join(' ').trim(); if (t) return t; }
    if (el.labels && el.labels.length) { const t = [...el.labels].map((l) => l.textContent).join(' ').trim(); if (t) return t; }
    return '';
  };
  let inputs = 0;
  for (const el of document.querySelectorAll('input, select, textarea')) {
    if (el.type === 'hidden') continue;
    inputs += 1;
    if (!nameOf(el)) bad.push(el.outerHTML.slice(0, 140));
  }
  let buttons = 0;
  for (const el of document.querySelectorAll('button, a[href]')) {
    buttons += 1;
    if (!((el.getAttribute('aria-label') || el.textContent || '').trim())) bad.push(el.outerHTML.slice(0, 140));
  }
  const levels = [...document.querySelectorAll('#app h1, #app h2, #app h3, #app h4')].map((h) => Number(h.tagName[1]));
  const skips = levels.filter((l, i) => i > 0 && l > levels[i - 1] + 1);
  return { bad, inputs, buttons, skips };
}"""


def test_every_input_select_textarea_and_button_has_an_accessible_name(site, make_page):
    page = make_page()
    total_inputs = 0
    for route in all_routes(site):
        open_route(page, site.base, route)
        res = page.evaluate(NAME_CHECK_JS)
        total_inputs += res["inputs"]
        assert res["bad"] == [], (route, res["bad"])
        assert res["skips"] == [], (route, "제목 단계를 건너뛴다", res["skips"])
    assert total_inputs > 25
    # 나중에 생기는 컨트롤도 이름이 있어야 한다: 설정의 규칙 행, 자산 폼의 비교표
    open_route(page, site.base, "#/settings")
    before = page.evaluate(NAME_CHECK_JS)["inputs"]
    page.get_by_role("button", name="+ 규칙 추가").click()
    expect(page.locator(".rule")).to_have_count(1)
    res = page.evaluate(NAME_CHECK_JS)
    assert res["bad"] == [] and res["inputs"] == before + 2, (before, res)       # 새 규칙 행의 select·input 두 개도 이름이 있다
    open_route(page, site.base, site.route("host_detail"))
    page.get_by_role("button", name="자산으로 등록").click()
    expect(page.get_by_label("자산번호 *")).to_be_visible()
    assert page.evaluate(NAME_CHECK_JS)["bad"] == []
    # 서버 등록(에이전트 파일 있음)·이벤트 호스트 선택도
    page.goto(f"{site.base_with_agents}/?v={next(_seq)}#/enroll")
    expect(page.locator(".enroll-grid")).to_be_visible()
    res = page.evaluate(NAME_CHECK_JS)
    assert res["bad"] == [] and res["skips"] == [], res
    assert page.problems == []


def test_bars_are_real_buttons_operable_by_keyboard(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/kernels")
    bars = page.locator(".bars .bar")
    count = bars.count()
    assert count >= 2
    kinds = bars.evaluate_all("els => els.map((e) => [e.tagName, e.type, e.tabIndex])")
    assert all(k == ["BUTTON", "button", 0] for k in kinds), kinds
    bars.nth(1).focus()
    expect(bars.nth(1)).to_be_focused()
    page.keyboard.press("Tab")
    expect(bars.nth(2) if count > 2 else page.locator(":focus")).to_be_focused()        # Tab 으로 다음 막대로 이동
    bars.nth(1).focus()
    version = bars.nth(1).locator(".name").inner_text()
    page.keyboard.press("Enter")
    assert hash_query(page) == {"running": [version]}
    expect(page.get_by_label("실행 중 커널")).to_have_value(version)
    expect(page.locator(".bars .bar.active")).to_have_count(1)
    # 덜 중요한 곳: 개요의 커널 분포·이미지 태그 분포도 버튼
    open_route(page, site.base, "#/overview")
    assert page.locator(".bars .bar").evaluate_all("els => els.every((e) => e.tagName === 'BUTTON')")
    assert page.locator("div.bar.clickable, .bar[onclick]").count() == 0


def test_nav_marks_the_current_page_and_each_route_sets_title_and_moves_focus(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/settings")                  # 첫 링크(개요)가 '다른 화면으로의 이동'이 되도록
    expect(page.get_by_role("navigation", name="주 메뉴")).to_be_visible()
    screens = [("개요", "overview"), ("커널", "kernels"), ("소프트웨어", "software"), ("호스트", "hosts"), ("자산", "assets"), ("컨테이너", "containers"),
               ("네트워크", "network"), ("변경 이력", "events"), ("AI 리포트", "reports"), ("서버 등록", "enroll"), ("설정", "settings")]
    for label, route in screens:
        page.get_by_role("navigation", name="주 메뉴").get_by_role("link", name=label, exact=True).click()
        expect(page).to_have_title(f"{label} · swinventory")
        current = page.locator("#nav a[aria-current]")
        expect(current).to_have_count(1)
        expect(current).to_have_attribute("href", f"#/{route}")
        expect(current).to_have_attribute("aria-current", "page")
        expect(page.locator("#app h1").first).to_be_focused()                       # 화면을 옮기면 초점이 제목으로
        assert page.evaluate("() => document.activeElement.getAttribute('tabindex')") == "-1"
    # 상세 화면은 대상 이름을 제목에 싣는다
    open_route(page, site.base, "#/software/openssl")
    expect(page).to_have_title("openssl · 소프트웨어 · swinventory")
    open_route(page, site.base, site.route("host_detail"))
    assert re.fullmatch(r".+ · 호스트 · swinventory", page.title()), page.title()
    assert page.problems == []


def test_changing_a_filter_select_keeps_focus_on_the_select_instead_of_jumping_to_the_heading(site, make_page):
    """필터 select 를 바꾸면 주소(query)가 바뀌어 화면이 통째로 다시 그려진다. 그때 초점이 제목(h1)으로 튕겨 가면 키보드 사용자는 다음 값을 고를 수 없다 —
    새로 그려진 같은 select 에 초점이 남아야 한다."""
    page = make_page()
    open_route(page, site.base, "#/hosts")
    total = len(call(site.base, "/v1/hosts"))
    for value, count in (("error", 2), ("", total), ("error", 2)):
        select = page.get_by_label("상태 필터")
        select.focus()
        # 초점이 select 에 있는 채로 값이 바뀐다(키보드 조작과 같다 — 헤드리스 Chrome(macOS)은 select 팝업을 키보드로 열 수 없어 Playwright 로 값을 고른다)
        select.select_option(value)
        expect(page.locator("#app h1")).to_have_text(f"호스트 ({count})")        # 다시 그려졌다
        expect(page.get_by_label("상태 필터")).to_have_value(value)
        expect(page.get_by_label("상태 필터")).to_be_focused()                    # 새 select 에 초점이 남는다
        expect(page.locator("#app h1")).not_to_be_focused()
    assert page.problems == []


def test_rapid_successive_filter_changes_still_end_with_focus_on_the_select(site, make_page):
    """키를 누르고 있으면 change 가 연달아 나서 앞의 그리기가 끝나기 전에 다음 그리기가 시작된다(그 사이에 select 는 이미 DOM 에서 빠져 초점이 body 에 있다).
    그래도 마지막에 새 select 에 초점이 있어야 한다."""
    page = make_page()
    open_route(page, site.base, "#/hosts")
    ok_count = len(call(site.base, "/v1/hosts?status=ok"))
    page.get_by_label("상태 필터").focus()
    page.evaluate("() => { location.hash = '#/hosts?status=error'; location.hash = '#/hosts?status=ok'; }")     # hashchange 두 번이 이어서 도착한다
    expect(page.locator("#app h1")).to_have_text(f"호스트 ({ok_count})")
    expect(page.get_by_label("상태 필터")).to_have_value("ok")
    expect(page.get_by_label("상태 필터")).to_be_focused()


def press_and_wait_for_rerender(page, control, key: str) -> None:
    """키를 누르고, 그 컨트롤이 다시 그려질 때까지(옛 요소가 DOM 에서 빠질 때까지) 기다린다. 눌린 직후의 옛 요소는 '체크됨·초점 있음'이라
    기다리지 않으면 다시 그리기 전에 단언이 먼저 통과하고, 다음 키가 사라지는 중인 화면(초점이 body)에 들어가 간헐적으로 실패한다."""
    control.evaluate("el => { el.dataset.beforeRender = '1'; }")
    page.keyboard.press(key)
    expect(page.locator("[data-before-render]")).to_have_count(0)


def test_keyboard_only_filters_keep_focus_on_the_text_input_and_the_checkbox(site, make_page):
    """키보드만으로 하는 필터(텍스트 + Enter, 체크박스 + Space)도 다시 그린 뒤 같은 컨트롤에서 계속 조작할 수 있다."""
    page = make_page()
    open_route(page, site.base, "#/hosts")
    tag = page.get_by_label("태그 필터")
    tag.focus()
    page.keyboard.type("team=infra")
    page.keyboard.press("Enter")                                                   # change → 주소(query) 갱신 → 다시 그리기
    expect(page).to_have_url(re.compile(r"tag=team%3Ainfra"))
    expect(page.get_by_label("태그 필터")).to_have_value("team:infra")
    expect(page.get_by_label("태그 필터")).to_be_focused()

    open_route(page, site.base, "#/kernels")
    page.get_by_label("재부팅 필요만").focus()
    press_and_wait_for_rerender(page, page.get_by_label("재부팅 필요만"), "Space")
    expect(page).to_have_url(re.compile(r"reboot=1"))
    expect(page.get_by_label("재부팅 필요만")).to_be_checked()
    expect(page.get_by_label("재부팅 필요만")).to_be_focused()                       # 새로 그려진 체크박스에 초점이 있다
    press_and_wait_for_rerender(page, page.get_by_label("재부팅 필요만"), "Space")      # 그 체크박스를 이어서 조작한다
    expect(page.get_by_label("재부팅 필요만")).not_to_be_checked()
    expect(page.get_by_label("재부팅 필요만")).to_be_focused()
    assert hash_query(page) == {}
    assert page.problems == []


def test_removing_a_filter_chip_sends_focus_to_the_heading_instead_of_losing_it(site, make_page):
    """눌렀던 컨트롤이 다시 그린 화면에 없으면(칩이 사라짐) 초점은 문서 처음(body)으로 떨어지지 않고 제목으로 간다."""
    page = make_page()
    open_route(page, site.base, "#/containers/list?image=nginx:1.25&active=1")
    expect(page.locator(".chip", has_text="이미지:")).to_be_visible()
    page.locator(".chip", has_text="이미지:").get_by_role("button").focus()
    page.keyboard.press("Enter")
    expect(page.locator(".chip")).to_have_count(0)
    expect(page.locator("#app h1").first).to_be_focused()


def test_only_a_screen_change_moves_focus_to_the_heading(site, make_page):
    """h1 로 초점을 보내는 것은 화면(경로)이 바뀔 때만이다. 같은 화면의 주소 query 만 바뀌면(메뉴의 '호스트'를 다시 누름) 누른 메뉴 링크에 초점이 남는다."""
    page = make_page()
    open_route(page, site.base, "#/hosts")
    select = page.get_by_label("상태 필터")
    select.focus()
    select.select_option("error")                                                  # 같은 화면을 다시 그리고 초점은 select 에 돌아온다(그 기록은 이 시점에 쓰이고 사라진다)
    expect(page.locator("#app h1")).to_have_text("호스트 (2)")
    expect(page.get_by_label("상태 필터")).to_be_focused()
    nav = page.get_by_role("navigation", name="주 메뉴")
    hosts_link = nav.get_by_role("link", name="호스트", exact=True)
    hosts_link.focus()
    page.keyboard.press("Enter")
    expect(page).to_have_url(re.compile(r"#/hosts$"))
    expect(page.locator("#app h1")).to_have_text(re.compile(r"호스트 \(\d{2,}\)"))      # 필터가 풀려 다시 그려졌다
    expect(hosts_link).to_be_focused()                                             # 같은 화면 — 제목으로도, 방금 만지던 select 로도 가져가지 않는다
    nav.get_by_role("link", name="커널", exact=True).focus()
    page.keyboard.press("Enter")                                                   # 다른 화면 — 제목으로
    expect(page.locator("#app h1").first).to_have_text("커널 버전")
    expect(page.locator("#app h1").first).to_be_focused()
    # 같은 경로 모양이라도 대상이 다른 상세 화면(호스트 A → 호스트 B)은 다른 화면이다
    open_route(page, site.base, site.route("host_detail"))
    page.evaluate("(id) => { location.hash = `#/hosts/${id}`; }", site.route("big_host").rsplit("/", 1)[1])
    expect(page.locator("#app h1").first).to_contain_text("big01.corp.example")
    expect(page.locator("#app h1").first).to_be_focused()
    assert page.problems == []


def test_returning_from_an_error_screen_to_the_previous_screen_still_counts_as_a_new_screen(site, make_page):
    """오류 화면은 어느 화면도 아니다. 호스트 → (변경 이력 불러오기 실패) → 호스트로 돌아오면 같은 경로라고 건너뛰지 않고 제목으로 초점이 가야 한다."""
    page = make_page()
    open_route(page, site.base, "#/hosts")
    page.route("**/v1/events*", lambda r: r.abort())
    nav = page.get_by_role("navigation", name="주 메뉴")
    nav.get_by_role("link", name="변경 이력", exact=True).click()
    expect(page.get_by_role("alert")).to_contain_text("불러오지 못했습니다")
    page.unroute("**/v1/events*")
    nav.get_by_role("link", name="호스트", exact=True).click()
    expect(page.locator("#app h1").first).to_have_text(re.compile(r"호스트 \("))
    expect(page.locator("#app h1").first).to_be_focused()


def test_after_logging_in_again_the_heading_gets_focus_even_for_the_screen_left_before_logout(site, make_page):
    """로그아웃 전에 보던 화면과 같은 화면으로 다시 로그인해도 '새 화면'이다 — 제목으로 초점이 가야 하고 로그인 단추 자리에서 사라지면 안 된다."""
    page = make_page()
    open_route(page, site.base, "#/hosts")
    page.get_by_role("button", name="로그아웃").click()
    page.get_by_label("토큰").fill(ADM)
    page.get_by_role("button", name="로그인").click()
    expect(page.locator("#app h1").first).to_have_text(re.compile(r"호스트 \("))
    expect(page.locator("#app h1").first).to_be_focused()


def test_result_messages_are_live_regions(site, make_page):
    page = make_page()
    open_route(page, site.base, site.route("host_detail"))
    tags = page.get_by_label("태그 (key=value, 한 줄에 하나)")
    original = tags.input_value()
    save = page.locator(".panel", has=tags).get_by_role("button", name="저장")
    tags.fill("형식이틀림")
    save.click()
    expect(page.get_by_role("alert").filter(has_text="형식 오류")).to_be_visible()      # 오류는 role=alert
    tags.fill(original)
    save.click()
    expect(page.get_by_role("status").filter(has_text="저장했습니다.")).to_be_visible()  # 성공은 role=status
    open_route(page, site.base, "#/settings")
    page.get_by_role("button", name="저장", exact=True).first.click()
    expect(page.get_by_role("status").filter(has_text="저장했습니다")).to_be_visible()
    assert page.problems == []


def test_enroll_copy_feedback_is_announced_and_polling_errors_surface_after_three_failures(site, make_page):
    page = make_page()
    page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=site.base_with_agents)
    state = {"hosts_calls": 0}

    def hosts(route):                       # 처음 두 번(화면을 연 시점의 목록·첫 폴링)은 통과시키고 이후 폴링은 실패시킨다
        state["hosts_calls"] += 1
        if state["hosts_calls"] <= 2:
            route.continue_()
        else:
            route.fulfill(status=500, json={"detail": "boom"})

    def tick(calls: int) -> None:
        """폴링 주기(5초) 하나를 흘리고 그 요청이 처리될 때까지 기다린다."""
        page.clock.run_for(5_000)
        deadline = time.time() + 5
        while state["hosts_calls"] < calls:
            assert time.time() < deadline, state
            page.wait_for_timeout(20)
        page.wait_for_timeout(100)          # 응답을 받아 화면에 반영할 시간

    page.route("**/v1/hosts", hosts)
    page.clock.install()
    page.goto(f"{site.base_with_agents}/?v={next(_seq)}#/enroll")
    expect(page.locator(".enroll-grid")).to_be_visible()
    expect(page.get_by_text("등록 대기 중")).to_be_visible()
    assert state["hosts_calls"] == 2        # 화면을 열 때 + 첫 폴링
    page.clock.pause_at((page.evaluate("() => Date.now()") + 500) / 1000)     # 이후엔 run_for 로만 시간이 흐른다(파이썬 API 의 숫자 시각은 초 단위)
    # 복사 결과는 role=status 영역에 적힌다
    page.get_by_role("button", name="복사").first.click()
    expect(page.get_by_role("status").filter(has_text=re.compile("복사"))).to_be_visible()
    # 폴링 실패: 2회까지는 조용하고 3회 연속이면 알린다. 대기 중 제목은 오류 중에도 남는다
    tick(3)
    tick(4)
    expect(page.get_by_role("alert").filter(has_text="연속 실패")).to_have_count(0)
    expect(page.get_by_text("등록 대기 중")).to_be_visible()
    tick(5)
    expect(page.get_by_role("alert").filter(has_text="3회 연속 실패")).to_be_visible()
    expect(page.get_by_text("등록 대기 중")).to_be_visible()


def test_enroll_without_agent_files_hides_the_waiting_panel_and_says_why(site, make_page):
    page = make_page()
    polls = []
    page.on("request", lambda r: polls.append(r.url) if r.url.endswith("/v1/hosts") else None)
    page.clock.install()
    open_route(page, site.base, "#/enroll")
    expect(page.get_by_role("alert").filter(has_text="배포용 에이전트 파일이 하나도 없어")).to_be_visible()
    expect(page.get_by_text("등록 대기 중")).to_have_count(0)
    expect(page.locator(".enroll-grid")).to_have_count(0)
    page.clock.run_for(16_000)                          # 폴링 주기(5초) 세 번을 흘려도
    page.wait_for_timeout(100)
    assert len(polls) == 1, polls                       # 화면을 열 때 한 번뿐 — 폴링이 시작되지 않았다
    levels = page.evaluate("() => [...document.querySelectorAll('#app h1, #app h2, #app h3')].map((h) => h.tagName)")
    assert "H3" not in levels


def test_enroll_card_headings_are_h2_not_h3(site, make_page):
    page = make_page()
    page.goto(f"{site.base_with_agents}/?v={next(_seq)}#/enroll")
    expect(page.locator(".enroll-grid")).to_be_visible()
    assert page.locator(".enroll-grid h3").count() == 0
    assert page.locator(".enroll-grid h2").count() == 2


# --------------------------------------------------------------------------- G. 대비(WCAG AA)

CONTRAST_JS = """() => {
  const parse = (c) => { const m = c.match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number);
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
  const lin = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  const lum = (c) => 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const bgOf = (el) => { const stack = [];
    for (let n = el; n; n = n.parentElement) { const c = parse(getComputedStyle(n).backgroundColor); if (c && c.a > 0) { stack.push(c); if (c.a === 1) break; } }
    let base = { r: 255, g: 255, b: 255, a: 1 }; for (const c of stack.reverse()) base = over(c, base); return base; };
  const ratio = (f, b) => { const x = lum(over(f, b)), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  const seen = { 'badge.ok': 0, 'badge.warn': 0, 'badge.err': 0, badge: 0, notice: 0, th: 0, primary: 0, link: 0, muted: 0, placeholder: 0, error: 0 };
  const bad = [];
  const kindOf = (el) => el.matches('.badge.ok') ? 'badge.ok' : el.matches('.badge.warn') ? 'badge.warn' : el.matches('.badge.err') ? 'badge.err'
    : el.matches('.badge') ? 'badge' : el.closest('.notice') ? 'notice' : el.closest('th') ? 'th' : el.matches('button.primary') ? 'primary'
    : el.closest('.error') ? 'error' : el.matches('a') ? 'link' : el.matches('.muted, .hint') ? 'muted' : null;
  for (const el of document.querySelectorAll('body *')) {
    if (['SCRIPT', 'STYLE', 'OPTION', 'OPTGROUP'].includes(el.tagName)) continue;
    if (el.closest(':disabled') || el.closest('[hidden]')) continue;       // 비활성 컨트롤은 대비 요구에서 제외(WCAG 1.4.3)
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    const direct = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (!direct) continue;
    const fg = parse(cs.color); if (!fg) continue;
    const bg = bgOf(el); const r = ratio(fg, bg);
    const kind = kindOf(el); if (kind) seen[kind] += 1;
    if (r < 4.5) bad.push({ text: el.textContent.trim().slice(0, 30), cls: el.className, ratio: Math.round(r * 100) / 100, fg: cs.color, bg: `rgb(${bg.r|0},${bg.g|0},${bg.b|0})` });
  }
  for (const el of document.querySelectorAll('input[placeholder], textarea[placeholder]')) {
    if (el.disabled) continue;
    const fg = parse(getComputedStyle(el, '::placeholder').color); if (!fg) continue;
    const r = ratio(fg, bgOf(el)); seen.placeholder += 1;
    if (r < 4.5) bad.push({ text: 'placeholder:' + el.placeholder, ratio: Math.round(r * 100) / 100 });
  }
  return { bad, seen };
}"""


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_wcag_aa_contrast_on_every_text_in_both_color_schemes(site, make_page, scheme):
    page = make_page(scheme=scheme, token=ADM)
    totals: dict[str, int] = {}
    for route in all_routes(site) + ["#/assets?status=mismatch", "#/kernels?compliant=false"]:
        open_route(page, site.base, route)
        res = page.evaluate(CONTRAST_JS)
        assert res["bad"] == [], (scheme, route, res["bad"])
        for k, v in res["seen"].items():
            totals[k] = totals.get(k, 0) + v
    # 로그인 화면(주 버튼)도
    page2 = make_page(scheme=scheme, token=None)
    page2.goto(site.base + "/")
    expect(page2.get_by_role("button", name="로그인")).to_be_visible()
    res = page2.evaluate(CONTRAST_JS)
    assert res["bad"] == [], (scheme, "login", res["bad"])
    totals["primary"] = totals.get("primary", 0) + res["seen"]["primary"]
    # 측정 대상이 실제로 있었어야 한다(빈 목록에 대한 all() 은 항상 참)
    for kind in ("badge.ok", "badge.warn", "badge.err", "badge", "notice", "th", "primary", "link", "muted", "placeholder"):
        assert totals.get(kind, 0) > 0, (scheme, kind, totals)
    assert page.problems == []


def test_dark_primary_button_uses_a_dark_foreground_on_the_light_accent(site, make_page):
    page = make_page(scheme="dark")
    open_route(page, site.base, "#/assets")
    btn = page.get_by_role("button", name="자산 추가")
    fg = btn.evaluate("el => getComputedStyle(el).color")
    bg = btn.evaluate("el => getComputedStyle(el).backgroundColor")
    assert fg != "rgb(255, 255, 255)", (fg, bg)                    # 흰 글자(2.47:1)로 돌아가면 실패


# --------------------------------------------------------------------------- H. 자산 불일치 해소

def test_mismatch_filter_and_banner_link(site, make_page):
    total = len(call(site.base, "/v1/assets"))
    mismatched = len(call(site.base, "/v1/assets?status=mismatch"))
    assert 0 < mismatched < total
    page = make_page()
    open_route(page, site.base, "#/assets")
    expect(page.locator("tbody tr")).to_have_count(total)
    page.get_by_role("link", name="불일치 자산만 보기").click()
    expect(page.get_by_label("상태 필터")).to_have_value("mismatch")
    rows = page.locator("tbody tr")
    expect(rows).to_have_count(mismatched)
    assert all("불일치" in t for t in rows.locator("td:nth-child(8)").all_inner_texts()), "불일치 필터인데 일치하는 행이 섞였다"
    page.get_by_label("상태 필터").select_option("")
    expect(page.locator("tbody tr")).to_have_count(total)
    page.get_by_label("상태 필터").select_option("mismatch")
    expect(page.locator("tbody tr")).to_have_count(mismatched)


def test_asset_form_compares_ledger_and_collected_values_and_applies_without_saving(site, make_page):
    page = make_page()
    open_route(page, site.base, site.route("asset_edit"))               # P-1099: 대장=물리·IP 10.99.99.99, 수집=VM
    table = page.locator(".cmp-table")
    expect(table).to_be_visible()
    assert table.locator("thead th").all_inner_texts() == ["항목", "대장 값", "수집 값", "판정", "작업"]
    assert table.locator("tbody tr th").all_inner_texts() == ["구분", "시리얼", "호스트명", "도메인", "IP"]
    kind_row = table.locator("tbody tr", has=page.locator("th", has_text="구분"))
    expect(kind_row.locator("td").nth(0)).to_contain_text("물리")
    expect(kind_row.locator("td").nth(1)).to_contain_text("VM")
    expect(kind_row.locator("td").nth(2)).to_contain_text("다름")
    kind_row.get_by_role("button", name=re.compile("수집값 적용")).click()
    expect(page.get_by_label("구분 *")).to_have_value("virtual")
    expect(kind_row.locator("td").nth(2)).to_contain_text("일치")
    expect(kind_row.locator("td").nth(0)).to_contain_text("(저장 전)")                  # 저장 전이라는 표시
    ip_row = table.locator("tbody tr", has=page.locator("th", has_text="IP"))
    ip_row.get_by_role("button", name=re.compile("수집값 적용")).first.click()
    expect(page.get_by_label("관리 IP")).not_to_have_value("10.99.99.99")
    expect(ip_row.locator("td").nth(2)).to_contain_text("일치")
    # 저장하지 않았으므로 서버 값은 그대로다
    saved = call(site.base, f"/v1/assets/{site.mismatch_asset}")
    assert saved["asset"]["kind"] == "physical" and saved["asset"]["ip"] == "10.99.99.99"
    assert page.problems == []


def test_register_from_host_requires_an_explicit_kind_validates_inline_and_returns_to_the_host(site, make_page):
    page = make_page()
    host = site.unknown_kind_host
    created = []
    page.on("request", lambda r: created.append(r.url) if r.method == "POST" and r.url.endswith("/v1/assets") else None)
    open_route(page, site.base, f"#/hosts/{host}")
    page.get_by_role("button", name="자산으로 등록").click()
    expect(page.get_by_label("자산번호 *")).to_be_visible()
    expect(page.get_by_label("자산번호 *")).to_have_attribute("required", "")          # 필수 입력(보조기기에도 알린다)
    expect(page.get_by_label("자산번호 *")).to_have_attribute("aria-required", "true")
    assert hash_query(page)["return"] == [f"#/hosts/{host}"]                          # 돌아갈 곳이 주소에 실린다
    expect(page.get_by_label("구분 *")).to_have_value("")                             # 구분을 모르면 '물리'를 미리 고르지 않는다
    expect(page.get_by_text("수집된 구분을 알 수 없어")).to_be_visible()
    expect(page.get_by_label("호스트명")).not_to_have_value("")                       # 나머지는 수집값으로 채운다
    # 비어 있는 채로 저장 → 요청 없이 그 자리에서 오류
    page.get_by_role("button", name="저장", exact=True).click()
    expect(page.get_by_text("자산번호를 입력하세요.")).to_be_visible()
    expect(page.get_by_text("구분(물리/VM)을 선택하세요.")).to_be_visible()
    expect(page.get_by_label("자산번호 *")).to_be_focused()
    expect(page.get_by_label("자산번호 *")).to_have_attribute("aria-invalid", "true")
    assert created == []
    # 채우면 오류가 사라지고, 더블 클릭해도 한 번만 만든다
    page.get_by_label("자산번호 *").fill("UX-TEST-0001")
    expect(page.get_by_text("자산번호를 입력하세요.")).to_be_hidden()
    page.get_by_label("구분 *").select_option("physical")
    try:
        page.get_by_role("button", name="저장", exact=True).dblclick()
        expect(page).to_have_url(re.compile(re.escape(f"#/hosts/{host}") + "$"))       # 저장 뒤 온 곳(호스트 상세)으로
        expect(page.locator("#app h1").first).to_be_visible()
        assert len(created) == 1, created
        expect(page.locator(".panel", has_text="자산번호")).to_contain_text("UX-TEST-0001")
    finally:
        for row in call(site.base, "/v1/assets"):
            if row["asset"] and row["asset"]["asset_no"] == "UX-TEST-0001":
                call(site.base, f"/v1/assets/{row['asset']['id']}", method="DELETE")
    assert page.problems == []


def test_asset_edit_returns_to_the_list_it_came_from(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/assets?status=mismatch")
    page.get_by_role("link", name="편집").first.click()
    expect(page.get_by_role("button", name="저장", exact=True)).to_be_visible()
    expect(page.get_by_role("link", name="← 돌아가기")).to_be_visible()
    page.get_by_role("link", name="← 돌아가기").click()
    expect(page.get_by_label("상태 필터")).to_have_value("mismatch")
    # 검색어를 입력하면 주소는 곧바로 바뀌지만 표는 응답이 와야 다시 그려진다 — 그 사이에 눌러도 return 은 '누른 순간'의 화면이어야 한다
    open_route(page, site.base, "#/assets")
    held = []
    page.route("**/v1/assets?q=*", lambda r: held.append(r))              # 검색 응답을 붙들어 둔다(옛 표가 그대로 보이는 구간)
    page.get_by_label("자산 검색").fill("P-1099")
    expect(page).to_have_url(re.compile("q=P-1099"))
    deadline = time.time() + 5
    while not held:
        assert time.time() < deadline, "검색 요청이 나가지 않았다"
        page.wait_for_timeout(20)
    page.get_by_role("link", name="편집").first.click()                    # 아직 옛 표의 링크다
    assert hash_query(page)["return"] == ["#/assets?q=P-1099"], hash_query(page)
    for r in held:
        r.abort()
    page.unroute("**/v1/assets?q=*")
    expect(page.get_by_role("link", name="← 돌아가기")).to_be_visible()
    page.get_by_role("link", name="← 돌아가기").click()
    expect(page.get_by_label("자산 검색")).to_have_value("P-1099")
    expect(page.locator("tbody tr")).to_have_count(1)
    # 같은 자산 링크가 호스트 목록에서는 호스트 목록으로 돌려보낸다
    open_route(page, site.base, "#/hosts?status=error")
    page.locator("tbody tr").first.get_by_role("link", name=re.compile(r"^[VP]-\d+")).click()
    expect(page.get_by_role("button", name="저장", exact=True)).to_be_visible()
    expect(page.get_by_role("link", name="← 돌아가기")).to_be_visible()
    page.get_by_role("link", name="← 돌아가기").click()
    expect(page.get_by_label("상태 필터")).to_have_value("error")


# --------------------------------------------------------------------------- I. 그 밖의 것

def test_kernels_policy_filters_are_disabled_with_a_link_when_no_policy_exists(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/kernels")
    select = page.get_by_label("하한선 준수 여부")
    expect(select.get_by_role("option", name="하한선 미달만")).to_be_disabled()
    expect(select.get_by_role("option", name="하한선 준수만")).to_be_disabled()
    link = page.get_by_role("link", name="설정에서 지정")
    expect(link).to_have_attribute("href", "#/settings")
    call(site.base, "/v1/settings/kernel-policy", method="PUT", body={"rules": [{"os_family": "debian", "min_kernel": "5.15.0-100"}]})
    try:
        open_route(page, site.base, "#/kernels")
        expect(page.get_by_label("하한선 준수 여부").get_by_role("option", name="하한선 미달만")).to_be_enabled()
        expect(page.get_by_role("link", name="설정에서 지정")).to_have_count(0)
    finally:
        call(site.base, "/v1/settings/kernel-policy", method="PUT", body={"rules": []})


def test_tag_filter_accepts_colon_and_equals_and_rejects_a_bare_word(site, make_page):
    page = make_page()
    for typed in ("team:infra", "team=infra"):
        open_route(page, site.base, "#/hosts")
        box = page.get_by_label("태그 필터")
        with page.expect_request(lambda r: "/v1/hosts" in r.url and "tag=" in r.url) as info:
            box.fill(typed)
            box.press("Tab")
        assert parse_qs(urlparse(info.value.url).query)["tag"] == ["team:infra"], typed
        expect(page.get_by_label("태그 필터")).to_have_value("team:infra")
        tags = page.locator("tbody tr td:last-child").all_inner_texts()
        assert tags and all("team=infra" in t for t in tags), tags
    open_route(page, site.base, "#/hosts")
    box = page.get_by_label("태그 필터")
    box.fill("infra")
    box.press("Tab")
    expect(page.get_by_role("alert").filter(has_text="key:value 형식")).to_be_visible()
    expect(box).to_have_attribute("aria-invalid", "true")
    assert hash_query(page) == {}                                                       # 잘못된 값으로는 이동하지 않는다


def test_events_filter_by_hostname_not_by_raw_host_id(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/events")
    expect(page.get_by_placeholder("host_id")).to_have_count(0)
    picker = page.get_by_label("호스트 (이름으로 선택)")
    options = page.locator("datalist option").evaluate_all("els => els.map((e) => e.value)")
    assert "db10.corp.example" in options and len(options) == 29, options
    picker.fill("db10.corp.example")
    picker.press("Tab")
    host_id = call(site.base, "/v1/hosts")
    host_id = next(h["host_id"] for h in host_id if h["hostname"] == "db10.corp.example")
    expect(page).to_have_url(re.compile(f"host={host_id}"))
    expect(page.get_by_label("호스트 (이름으로 선택)")).to_have_value("db10.corp.example")      # 주소엔 id, 화면엔 이름
    hosts = set(page.locator("tbody tr td:nth-child(2)").all_inner_texts())
    assert hosts == {"db10.corp.example"}, hosts
    picker = page.get_by_label("호스트 (이름으로 선택)")
    picker.fill("없는-호스트")
    picker.press("Tab")
    expect(page.get_by_role("alert").filter(has_text="목록에 없는 호스트")).to_be_visible()
    # 호스트 상세 → 전체 이력
    open_route(page, site.base, f"#/hosts/{host_id}")
    page.get_by_role("link", name="이 호스트의 전체 이력 →").click()
    expect(page).to_have_url(re.compile(f"#/events\\?host={host_id}"))
    expect(page.get_by_label("호스트 (이름으로 선택)")).to_have_value("db10.corp.example")


@pytest.mark.parametrize("tz, day, utc", [
    ("Asia/Seoul", "2026-11-06", "2026-11-05T15:00:00Z"),                # UTC+9 — 시간대 없이 보내면 서버가 UTC 로 읽어 9시간 어긋난다
    ("Asia/Kolkata", "2026-11-06", "2026-11-05T18:30:00Z"),              # UTC+5:30 — 정시 단위 오프셋만 다루는 구현을 잡는다
    ("America/Los_Angeles", "2026-11-06", "2026-11-06T08:00:00Z"),       # UTC-8(표준시) — 부호가 반대여도 로컬 자정이어야 한다
    ("America/Los_Angeles", "2026-03-09", "2026-03-09T07:00:00Z"),       # 서머타임(UTC-7)이 시작된 다음 날 — 오프셋은 '그 날짜'의 값이다
    ("UTC", "2026-11-06", "2026-11-06T00:00:00Z"),
])
def test_events_since_date_is_sent_as_the_utc_instant_of_local_midnight(site, make_page, tz, day, utc):
    """'이후' 날짜(YYYY-MM-DD)는 브라우저 로컬 자정이다. 요청의 since 는 그 순간을 가리키는 시간대 있는 값이어야 한다(서버는 시간대 없는 값을 UTC 로 읽는다).
    기대값(utc)은 시간대 규칙을 손으로 계산해 적었다 — 구현과 같은 계산을 다시 하지 않는다."""
    page = make_page(timezone_id=tz)
    with page.expect_request(lambda r: urlparse(r.url).path == "/v1/events") as info:
        page.goto(f"{site.base}/?v={next(_seq)}#/events?since={day}")
    since = parse_qs(urlparse(info.value.url).query)["since"][0]
    got = datetime.fromisoformat(since.replace("Z", "+00:00"))
    assert got.tzinfo is not None, f"since={since!r} 에 시간대가 없다"
    assert got == datetime.fromisoformat(utc.replace("Z", "+00:00")), (tz, day, since, utc)
    expect(page.locator("#app h1").first).to_be_visible()                              # 서버가 그 값을 받아들였다(422 오류 화면이 아니다)
    assert page.locator("#app .error").count() == 0
    assert page.problems == []


def test_events_since_keeps_events_between_local_and_utc_midnight(events_base, make_page):
    """서울에서 '이후 11-06' 이면 11-06 01:00(KST) 이벤트가 보여야 한다. 그 순간은 UTC 로 아직 11-05 16:00 이라, 날짜를 UTC 자정으로 읽으면 빠졌다."""
    page = make_page(timezone_id="Asia/Seoul")
    rows = page.locator("#app tbody tr")
    open_route(page, events_base, "#/events?since=2026-11-06")
    expect(rows).to_have_count(1)
    expect(rows.first).to_contain_text("late-pkg")
    expect(rows.first.locator("time")).to_have_text("2026-11-06 01:00")                # 화면 시각은 로컬(서울) — 걸러진 기준과 같다
    open_route(page, events_base, "#/events?since=2026-11-05")                         # 하루 앞: 서울 11-05 23:00 의 early-pkg 도 포함
    expect(rows).to_have_count(2)
    assert {t.strip() for t in rows.locator("time").all_inner_texts()} == {"2026-11-05 23:00", "2026-11-06 01:00"}
    open_route(page, events_base, "#/events?since=2026-11-07")                         # 이후 이벤트가 없으면 빈 상태
    expect(page.get_by_text("변경 이력이 없습니다.")).to_be_visible()
    expect(rows).to_have_count(0)
    # 같은 주소라도 브라우저 시간대가 다르면 자정이 다르다(로스앤젤레스 11-05 00:00 PST = 11-05T08:00Z → 두 이벤트 모두 그 뒤)
    la = make_page(timezone_id="America/Los_Angeles")
    open_route(la, events_base, "#/events?since=2026-11-05")
    expect(la.locator("#app tbody tr")).to_have_count(2)
    open_route(la, events_base, "#/events?since=2026-11-06")                           # 로스앤젤레스 11-06 00:00 PST = 11-06T08:00Z → 둘 다 그 앞
    expect(la.get_by_text("변경 이력이 없습니다.")).to_be_visible()


def test_events_with_an_unparsable_since_report_the_server_error_instead_of_crashing(site, make_page):
    """주소를 손으로 고친 잘못된 날짜는 브라우저 예외(Invalid time value)가 아니라 서버의 422 안내가 화면에 나온다."""
    page = make_page(timezone_id="Asia/Seoul")
    page.goto(f"{site.base}/?v={next(_seq)}#/events?since=내일")
    expect(page.get_by_role("alert")).to_contain_text("since")
    expect(page.get_by_role("alert")).not_to_contain_text("Invalid time value")


def test_dates_are_compact_with_the_full_timestamp_in_the_tooltip(site, make_page):
    page = make_page()
    open_route(page, site.base, "#/events")
    times = page.locator("tbody time")
    assert times.count() > 5
    texts = times.all_inner_texts()
    assert all(re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", t) for t in texts), texts[:3]
    titles = times.evaluate_all("els => els.map((e) => e.title)")
    assert all(len(t) > 16 and t != texts[i] for i, t in enumerate(titles)), titles[:3]      # 초까지 있는 전체 시각


def test_malicious_agent_strings_stay_text_on_every_screen_that_shows_them(site, make_page):
    """시드에는 호스트명·파드명·인터페이스 이름·자산 비고에 `<img src=x onerror=alert(1)>` 가 들어 있다. 어느 화면에서도 요소가 되거나 실행되면 안 된다."""
    xss_host = f"{6:032x}"
    page = make_page()
    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    payload = "<img src=x onerror=alert(1)>"
    routes = ["#/hosts", f"#/hosts/{xss_host}", "#/kernels", "#/events", "#/assets", "#/containers/list", "#/network", "#/network/ports/tcp/22",
              "#/software/openssl", "#/containers/clusters/" + "b2" * 32, f"#/events?host={xss_host}", f"#/containers/list?host={xss_host}"]
    shown = 0
    for route in routes:
        open_route(page, site.base, route)
        assert page.locator("#app img, #top img").count() == 0, route                    # 데이터가 <img> 요소로 파싱되지 않았다
        if payload in page.locator("#app").inner_text():
            shown += 1                                                                     # 글자로는 그대로 보인다
    assert shown >= 6, shown                                                               # 악성 문자열이 실제로 화면에 나온 경로가 충분히 있었다
    # 자산 비고(입력란 값)·이벤트 호스트 선택(datalist)·칩에도 글자로만 들어간다
    note_asset = next(r for r in call(site.base, "/v1/assets") if r["asset"] and payload in r["asset"]["note"])["asset"]["id"]
    open_route(page, site.base, f"#/assets/{note_asset}")
    expect(page.get_by_label("비고")).to_have_value(payload)
    open_route(page, site.base, f"#/events?host={xss_host}")
    expect(page.get_by_label("호스트 (이름으로 선택)")).to_have_value(payload)
    assert page.locator("#app img").count() == 0
    assert dialogs == [] and page.problems == [], (dialogs, page.problems)


# --------------------------------------------------------------------------- 오류 경로

def test_ai_actions_report_failures_in_an_alert_and_do_not_stay_disabled(site, make_page):
    """AI 가 설정되지 않은 서버(테스트 서버)에서 관리자가 누르면: 이유를 알리고 버튼은 다시 눌릴 수 있어야 한다."""
    page = make_page(token=ADM)
    open_route(page, site.base, "#/settings")
    page.get_by_role("button", name="연결 테스트").click()
    expect(page.get_by_role("alert").filter(has_text="연결 실패")).to_be_visible()
    expect(page.get_by_role("button", name="연결 테스트")).to_be_enabled()
    open_route(page, site.base, "#/reports")
    generate = page.get_by_role("button", name="AI 리포트 생성")
    generate.click()
    expect(page.get_by_role("alert").filter(has_text="설정 화면에서 AI 연결을 입력하세요")).to_be_visible()
    expect(generate).to_be_enabled()                                               # 실패했다고 영구히 꺼지지 않는다
    assert [p for p in page.problems if "409" not in p] == [], page.problems          # 409(AI 미설정)로 인한 리소스 로드 오류만 허용한다



def test_a_network_failure_on_a_screen_offers_retry_and_a_401_returns_to_login(site, make_page):
    page = make_page(token=ADM)
    page.route("**/v1/overview", lambda r: r.abort())
    page.goto(f"{site.base}/?v={next(_seq)}#/overview")
    expect(page.get_by_role("alert")).to_contain_text("서버에 연결할 수 없습니다(잠시 후 다시 시도).")
    page.unroute("**/v1/overview")
    expect(page.get_by_role("button", name="다시 시도")).to_be_visible()
    page.get_by_role("button", name="다시 시도").click()
    expect(page.get_by_role("heading", name="개요", level=1)).to_be_visible()
    # 세션 중 토큰이 거부되면(회수·만료) 로그인 화면으로 돌아가 이유를 알린다
    page.route("**/v1/hosts*", lambda r: r.fulfill(status=401, json={"detail": "invalid token"}))
    page.get_by_role("navigation", name="주 메뉴").get_by_role("link", name="호스트", exact=True).click()
    expect(page.get_by_label("토큰")).to_be_visible()
    expect(page.get_by_role("alert")).to_contain_text("토큰이 올바르지 않거나 만료되었습니다")
    assert page.evaluate("() => sessionStorage.getItem('swinv.token')") is None         # 거부된 토큰은 지운다
    expect(page.locator("#top")).to_be_hidden()


# --------------------------------------------------------------------------- 전체 순회

def test_traversing_every_screen_with_both_tokens_raises_no_console_errors_or_literal_null(site, make_page):
    for token in (ADM, RD):
        page = make_page(token=token)
        for route in all_routes(site):
            open_route(page, site.base, route)
            text = page.locator("#app").inner_text()
            assert not re.search(r"(^|\s)null(\s|$)", text), (token, route)     # append(null) → 'null' 글자 함정(CLAUDE.md)
            assert "undefined" not in text, (token, route)
        assert page.problems == [], (token, page.problems)
    # 서버 등록(에이전트 파일 있음)도
    page.goto(f"{site.base_with_agents}/?v={next(_seq)}#/enroll")
    expect(page.locator(".enroll-grid")).to_be_visible()
    assert not re.search(r"(^|\s)null(\s|$)", page.locator("#app").inner_text())
    assert page.problems == []


@pytest.mark.parametrize('width', [390, 1360])
@pytest.mark.parametrize('route', ['#/containers/list', '#/network', '#/network/ports', '#/software?q=open'])
def test_inventory_groups_belong_to_servers_start_closed_and_filter_by_id(site, make_page, route, width):
    page = make_page(token=RD, width=width)
    open_route(page, site.base, route, expand_inventory=False)
    groups = page.locator('details.server-group')
    expect(groups.first).to_be_visible()
    total = groups.count()
    assert total > 1
    assert page.locator('details.server-group[open]').count() == 0
    first = groups.first
    owner = first.get_attribute('data-host-id')
    assert owner
    assert '서버' in first.locator('summary').inner_text()
    first.locator('summary').click()
    expect(first.locator('table')).to_be_visible()
    assert page.locator('details.server-group[open]').count() == 1
    page.get_by_label('서버 필터', exact=True).select_option(owner)
    expect(page.locator('details.server-group')).to_have_count(1)
    assert page.locator('details.server-group').get_attribute('data-host-id') == owner
    assert hash_query(page)['host'] == [owner]
    page.reload()
    expect(page.get_by_label('서버 필터', exact=True)).to_have_value(owner)
    assert page.locator('details.server-group[open]').count() == 0
    if route != '#/software?q=open':
        assert csv_query(page)['host'] == [owner]
    page.get_by_label('서버 필터', exact=True).select_option('')
    expect(page.locator('details.server-group')).to_have_count(total)
    assert 'host' not in hash_query(page)
    assert page.problems == []


def test_host_inventory_sections_start_closed_and_keep_their_server_context(site, make_page):
    page = make_page()
    host = next(row for row in call(site.base, '/v1/containers') if row['cluster_id'] is not None)
    open_route(page, site.base, f"#/hosts/{host['host_id']}", expand_inventory=False)
    sections = page.locator('details.inventory-section')
    expect(sections).to_have_count(4)
    assert page.locator('details.inventory-section[open]').count() == 0
    for section in sections.all():
        section.locator('summary').click()
        expect(section.locator('.scroll').first).to_be_visible()
    links = page.locator('details.inventory-section[data-kind="software"] a')
    assert links.count() > 0
    assert all(f"host={host['host_id']}" in href for href in links.evaluate_all('(els) => els.map(e => e.getAttribute("href"))'))


def test_software_loads_only_expanded_server_and_unknown_filter_stays_scoped(site, make_page):
    page = make_page(token=RD)
    requests = []
    page.on('request', lambda r: requests.append(urlparse(r.url).path))
    open_route(page, site.base, '#/software?q=open', expand_inventory=False)
    groups = page.locator('details.server-group')
    expect(groups.first).to_be_visible()
    assert not any(re.fullmatch('/v1/hosts/[^/]+', path) for path in requests)
    first = groups.first
    owner = first.get_attribute('data-host-id')
    first.locator('summary').click()
    expect(first.locator('table')).to_be_visible()
    assert [p for p in requests if re.fullmatch('/v1/hosts/[^/]+', p)] == [f'/v1/hosts/{owner}']
    first.locator('summary').click()
    first.locator('summary').click()
    expect(first.locator('table')).to_be_visible()
    assert requests.count(f'/v1/hosts/{owner}') == 1
    first.locator('a').filter(has_text='openssl').first.click()
    expect(page.get_by_label('서버 필터', exact=True)).to_have_value(owner)
    assert csv_query(page)['host'] == [owner]
    for route in ('#/software', '#/containers/list', '#/network', '#/network/ports'):
        open_route(page, site.base, route + '?host=missing', expand_inventory=False)
        expect(page.get_by_label('서버 필터', exact=True)).to_have_value('missing')
        expect(page.locator('details.server-group')).to_have_count(0)
        expect(page.get_by_text('조건에 맞는 서버 데이터가 없습니다.')).to_be_visible()
    assert page.problems == []
