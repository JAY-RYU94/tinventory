"""화면(UX) 개선이 쓰는 조회 API 확장: 호출자 역할(whoami) · 목록 필터(q·status·conflicts·mismatch·version·below·cluster) · 호스트 CSV.

필터는 **거르기만** 한다 — 필터가 없는 응답은 그대로이고, 일치하는 게 없으면 404 가 아니라 빈 목록이다(패키지·이미지가 아예 없을 때만 404).
데이터는 seed 한 곳에서 만든다: 정상 3·수집 오류 1·수집 끊김 1 호스트, 같은 IP 를 쓰는 두 호스트, IP 가 둘인 호스트,
한 호스트에 공존하는 두 버전, 대장과 어긋난 자산. 테스트의 all(...) 은 빈 목록에 항상 참이므로 먼저 비어 있지 않음을 단언한다.
DB 정렬(콜레이션)에 기대지 않도록 집합·딕셔너리로 비교한다.
"""
import csv
import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from tests.server.conftest import T0, ctr, dpkg, hw, iface, k8s, make_snapshot, port, rpm
from tests.server.test_containers_api import CA, CB, seed as seed_containers

ING, RD, AD = {"Authorization": "Bearer ing-tok"}, {"Authorization": "Bearer read-tok"}, {"Authorization": "Bearer adm-tok"}
ALPHA, BRAVO, CHARLIE, DELTA, ECHO = "id-alpha-1", "id-bravo-2", "id-charlie-3", "id-delta-4", "id-echo-5"
ALL_HOSTS = {"web01", "db01", "cache01", "old01", "bare01"}
HOSTS_CSV_HEADER = "hostname,host_id,asset_no,kind,domain,ips,os_name,running,kernel_compliant,reboot_required,status,last_seen,tags"


@pytest.fixture
def client(repo, clock):
    settings = ApiSettings(ingest_tokens=("ing-tok",), read_tokens=("read-tok",), admin_tokens=("adm-tok",))
    return TestClient(create_app(repo, settings, clock=clock))


def push(client, snap):
    r = client.post("/v1/ingest", json=snap.to_dict(), headers=ING)
    assert r.status_code == 200, r.text
    return r.json()


def get(client, path, **params):
    r = client.get(path, params=params, headers=RD)
    assert r.status_code == 200, r.text
    return r.json()


def csv_rows(client, path, **params):
    r = client.get(path, params={**params, "format": "csv"}, headers=RD)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    return list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))


def names(rows):
    return {r["hostname"] for r in rows}


def seed(client, clock):
    """web01(정상·자산 일치) · db01(수집 오류·자산 불일치) · cache01(정상·IP 둘) · old01(수집 끊김·web01 과 같은 IP) · bare01(커널·IP 없음)."""
    push(client, make_snapshot(host_id=DELTA, hostname="old01", kernel="5.15-91", packages=[dpkg("openssl", "10.0.0", "arm64")],
                               interfaces=[iface("eth0", "aa:00:00:00:00:04", ("10.0.0.5/24",))]))
    clock.advance(hours=100)                                                       # old01 은 이후 수집이 없어 stale 이 된다
    at = T0 + timedelta(hours=100)
    push(client, make_snapshot(host_id=ALPHA, hostname="web01", at=at, kernel="5.15-91", installed=["5.15-91", "5.15-100"], reboot=True,
                               packages=[dpkg("openssl", "3.0.2"), dpkg("bash", "5.1")],
                               interfaces=[iface("eth0", "aa:00:00:00:00:01", ("10.0.0.5/24",))],
                               hardware=hw("physical", "SN-A", "web01.corp.example.com")))
    push(client, make_snapshot(host_id=BRAVO, hostname="db01", at=at, os_family="rhel", sources=("rpm",), kernel="5.15-100",
                               packages=[rpm("openssl", "3.0.13")], interfaces=[iface("eth0", "aa:00:00:00:00:02", ("10.0.1.6/24",))],
                               errors={"containers": "boom"}, hardware=hw("virtual", "VM-B", "db01.lab.example.org", "kvm")))
    push(client, make_snapshot(host_id=CHARLIE, hostname="cache01", at=at, kernel="5.15-100",
                               packages=[dpkg("openssl", "3.0.9"), dpkg("openssl", "1.1.1w", "i386")],     # 한 호스트에 두 버전(아키텍처가 다르면 공존)
                               interfaces=[iface("eth0", "aa:00:00:00:00:03", ("172.16.0.3/24",)),
                                           iface("eth1", "aa:00:00:00:00:33", ("192.168.7.9/24",))]))
    push(client, make_snapshot(host_id=ECHO, hostname="bare01", at=at, kernel=None))
    assert client.put(f"/v1/hosts/{ALPHA}/tags", json={"team": "infra", "env": "prod"}, headers=AD).status_code == 200
    assert client.put(f"/v1/hosts/{BRAVO}/tags", json={"team": "data"}, headers=AD).status_code == 200
    for body in ({"asset_no": "AST-0001", "kind": "physical", "hostname": "web01"},
                 {"asset_no": "AST-0002", "kind": "physical", "hostname": "db01", "ip": "10.9.9.9"},   # 수집은 VM·10.0.1.6 → kind·ip 불일치
                 {"asset_no": "X-9", "kind": "physical", "hostname": "ghost"}):                       # 수집된 적 없는 자산
        assert client.post("/v1/assets", json=body, headers=AD).status_code == 201


@pytest.fixture
def seeded(client, clock):
    seed(client, clock)
    return client


# --- GET /v1/whoami ---------------------------------------------------------

def test_whoami_returns_the_role_of_the_token(client):
    r = client.get("/v1/whoami", headers=AD)
    assert r.status_code == 200 and r.json() == {"role": "admin"}
    assert r.headers["cache-control"] == "no-store"                                  # 토큰이 바뀐 뒤에도 옛 역할이 캐시되면 안 된다
    r = client.get("/v1/whoami", headers=RD)
    assert r.status_code == 200 and r.json() == {"role": "read"}


def test_whoami_needs_a_valid_token_with_read_access(client):
    assert client.get("/v1/whoami").status_code == 401
    bad = client.get("/v1/whoami", headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401 and bad.headers["www-authenticate"] == "Bearer" and "nope" not in bad.text   # 토큰을 에러에 싣지 않는다
    for header in ("Basic YWRtOnB3", "Basic adm-tok", "Token adm-tok", "Bearer", "adm-tok"):         # 올바른 토큰이어도 Bearer 형식이 아니면 거부
        assert client.get("/v1/whoami", headers={"Authorization": header}).status_code == 401, header
    assert client.get("/v1/whoami", headers={"Authorization": "bearer adm-tok"}).json() == {"role": "admin"}   # 스킴은 대소문자를 가리지 않는다
    assert client.get("/v1/whoami", headers=ING).status_code == 403                  # 수집 전용 토큰은 조회 권한이 없다


def test_whoami_reports_the_highest_role_when_one_token_is_in_several_groups(repo, clock):
    s = ApiSettings(ingest_tokens=("i-a", "i-r"), read_tokens=("i-r", "r-a"), admin_tokens=("i-a", "r-a"))
    app = TestClient(create_app(repo, s, clock=clock))
    role = lambda token: app.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})  # noqa: E731
    assert role("i-a").json() == {"role": "admin"} and role("r-a").json() == {"role": "admin"}
    assert role("i-r").json() == {"role": "read"}                                    # 수집+조회 → 조회


def test_whoami_role_agrees_with_what_the_server_enforces(client):
    """화면이 whoami 로 버튼을 숨기고 서버가 실제로 막는 것이 어긋나면 안 된다."""
    push(client, make_snapshot(host_id="h1"))
    for headers, role, tag_write in ((AD, "admin", 200), (RD, "read", 403)):
        assert client.get("/v1/whoami", headers=headers).json() == {"role": role}
        assert client.put("/v1/hosts/h1/tags", json={"a": "b"}, headers=headers).status_code == tag_write


@pytest.mark.parametrize("path", ["/v1/hosts?format=csv", "/v1/kernels/hosts?q=x", "/v1/network/ips?conflicts=true", "/v1/network/listening?q=ssh",
                                  "/v1/assets?status=mismatch", "/v1/software/openssl?below=1", "/v1/images/nginx?cluster=unknown"])
def test_extended_read_routes_still_need_a_read_token(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers=ING).status_code == 403


# --- GET /v1/software/{name}?version=&below= --------------------------------

def sw(client, **params):
    return get(client, "/v1/software/openssl", **params)


def pairs(detail):
    return {(h["host_id"], h["version"]) for h in detail["hosts"]}


@pytest.mark.parametrize("below, expected", [
    ("3.0.13", {(ALPHA, "3.0.2"), (CHARLIE, "3.0.9"), (CHARLIE, "1.1.1w")}),    # 3.0.2 < 3.0.9 < 3.0.13: 문자열로 비교하면 3.0.2 가 빠지고 10.0.0 이 들어온다
    ("3.0.2", {(CHARLIE, "1.1.1w")}),
    ("1.1.1w", set()),                                                          # 같은 버전은 '미만'이 아니다
    ("1.1.1x", {(CHARLIE, "1.1.1w")}),                                          # 문자 토큰도 비교한다
    ("3", {(CHARLIE, "1.1.1w")}),                                               # 3.0.2 는 3 보다 높다(앞부분이 같으면 긴 쪽이 높다)
    ("10.0.1", {(ALPHA, "3.0.2"), (BRAVO, "3.0.13"), (CHARLIE, "3.0.9"), (CHARLIE, "1.1.1w"), (DELTA, "10.0.0")}),   # 10 > 3
], ids=["multi-digit", "boundary-3.0.2", "equal-is-not-below", "letter-suffix", "shorter-prefix", "ten-over-three"])
def test_software_below_compares_version_tokens_numerically(seeded, below, expected):
    assert pairs(sw(seeded, below=below)) == expected


@pytest.mark.parametrize("version, expected", [
    ("3.0.13", {(BRAVO, "3.0.13")}),
    ("3.0.1", set()),                                                           # 3.0.13 의 접두사일 뿐 같은 버전이 아니다
    ("3.0", set()),
    ("1.1.1w", {(CHARLIE, "1.1.1w")}),
    ("10.0.0", {(DELTA, "10.0.0")}),
])
def test_software_version_filter_is_an_exact_match(seeded, version, expected):
    assert pairs(sw(seeded, version=version)) == expected


def test_software_filters_only_narrow_hosts_and_the_distribution_stays_complete(seeded):
    whole = sw(seeded)
    assert [v["version"] for v in whole["versions"]] == ["10.0.0", "3.0.13", "3.0.9", "3.0.2", "1.1.1w"] and len(whole["hosts"]) == 5
    for params in ({"below": "3.0.2"}, {"version": "3.0.13"}, {"version": "3.0.13", "below": "3.0.13"}, {"below": "0.1"}):
        d = sw(seeded, **params)
        assert len(d["hosts"]) < len(whole["hosts"]), params                   # 호스트는 실제로 줄었는데
        assert d["versions"] == whole["versions"], params                      # 분포는 필터와 무관하게 전체다
        assert d["name"] == "openssl"


def test_software_version_and_below_combine_with_and(seeded):
    assert pairs(sw(seeded, version="3.0.2", below="3.0.13")) == {(ALPHA, "3.0.2")}
    assert pairs(sw(seeded, version="3.0.13", below="3.0.13")) == set()           # 정확히 일치하지만 미만은 아니다
    assert pairs(sw(seeded, version="10.0.0", below="3.0.13")) == set()


def test_software_response_echoes_the_filter_and_keeps_asset_columns(seeded):
    assert sw(seeded)["filter"] == {"version": None, "below": None}
    assert sw(seeded, version="3.0.13")["filter"] == {"version": "3.0.13", "below": None}
    assert sw(seeded, below="3.0.13")["filter"] == {"version": None, "below": "3.0.13"}
    assert sw(seeded, version="3.0.2", below="3.0.13")["filter"] == {"version": "3.0.2", "below": "3.0.13"}
    assert sw(seeded, version="", below="")["filter"] == {"version": None, "below": None}      # 빈 값은 필터가 아니다
    assert len(sw(seeded, version="", below="")["hosts"]) == 5
    row = sw(seeded, version="3.0.13")["hosts"][0]
    assert (row["asset_no"], row["kind"], row["domain"]) == ("AST-0002", "physical", "lab.example.org")   # 거른 행에도 자산 열이 붙는다


def test_software_filter_without_a_match_is_an_empty_list_and_only_a_missing_package_is_404(seeded):
    d = sw(seeded, below="1.0")
    assert d["hosts"] == [] and len(d["versions"]) == 5 and d["filter"]["below"] == "1.0"
    assert seeded.get("/v1/software/nope", headers=RD).status_code == 404
    assert seeded.get("/v1/software/nope", params={"version": "1", "below": "9"}, headers=RD).status_code == 404
    assert seeded.get("/v1/software/nope", params={"format": "csv", "below": "9"}, headers=RD).status_code == 404


def test_software_below_filters_each_version_row_of_a_host_with_several_versions(client):
    """rpm kernel-core 처럼 한 호스트에 여러 버전이 공존한다 — 호스트 단위가 아니라 버전(행) 단위로 거른다."""
    push(client, make_snapshot(host_id="r1", hostname="r1", sources=("rpm",), kernel="5.14-427", installed=["5.14-362", "5.14-427"],
                               packages=[rpm("kernel-core", "5.14-362"), rpm("kernel-core", "5.14-427")]))
    push(client, make_snapshot(host_id="r2", hostname="r2", sources=("rpm",), kernel="5.14-427", packages=[rpm("kernel-core", "5.14-427")]))
    d = get(client, "/v1/software/kernel-core", below="5.14-400")
    assert pairs(d) == {("r1", "5.14-362")} and {v["version"] for v in d["versions"]} == {"5.14-362", "5.14-427"}
    assert pairs(get(client, "/v1/software/kernel-core", below="5.14-500")) == {("r1", "5.14-362"), ("r1", "5.14-427"), ("r2", "5.14-427")}


def test_software_csv_applies_the_same_filters(seeded):
    r = seeded.get("/v1/software/openssl", params={"format": "csv", "below": "3.0.13"}, headers=RD)
    assert r.status_code == 200 and r.content.decode("utf-8-sig").splitlines()[0] == "host_id,hostname,version,arch,source,asset_no,kind,domain"   # 열은 그대로
    rows = csv_rows(seeded, "/v1/software/openssl", below="3.0.13")
    assert {(x["host_id"], x["version"]) for x in rows} == {(ALPHA, "3.0.2"), (CHARLIE, "3.0.9"), (CHARLIE, "1.1.1w")} and len(rows) == 3
    exact = csv_rows(seeded, "/v1/software/openssl", version="3.0.13")
    assert [(x["host_id"], x["version"], x["asset_no"]) for x in exact] == [(BRAVO, "3.0.13", "AST-0002")]
    assert [(x["host_id"], x["version"]) for x in csv_rows(seeded, "/v1/software/openssl", version="3.0.2", below="3.0.13")] == [(ALPHA, "3.0.2")]
    assert csv_rows(seeded, "/v1/software/openssl", below="1.0") == []               # 일치가 없어도 404 가 아니라 머리글만 있는 CSV
    assert len(csv_rows(seeded, "/v1/software/openssl")) == 5                         # 필터가 없으면 전부


def test_software_without_filters_is_unchanged_apart_from_the_filter_echo(seeded):
    d = sw(seeded)
    assert set(d) == {"name", "versions", "hosts", "filter"}
    assert pairs(d) == {(ALPHA, "3.0.2"), (BRAVO, "3.0.13"), (CHARLIE, "3.0.9"), (CHARLIE, "1.1.1w"), (DELTA, "10.0.0")}
    assert {h["host_id"]: h["asset_no"] for h in d["hosts"]} == {ALPHA: "AST-0001", BRAVO: "AST-0002", CHARLIE: None, DELTA: None}
    assert {tuple(sorted(h)) for h in d["hosts"]} == {tuple(sorted(
        ["host_id", "hostname", "version", "arch", "source", "asset_id", "asset_no", "kind", "kind_source", "virt", "domain", "asset_flags"]))}


# --- GET /v1/hosts?q=&status=&format=csv ------------------------------------

@pytest.mark.parametrize("needle, expected", [
    ("web01", {"web01"}),                                                        # 호스트명
    ("BRAVO", {"db01"}),                                                         # 호스트 ID — 대소문자 무시
    ("rocky", {"db01"}),                                                         # OS 이름
    ("ast-0001", {"web01"}),                                                     # 자산번호 — annotate 로 붙는 열이라 annotate 뒤에 걸러야 한다
    ("LAB.example", {"db01"}),                                                   # 도메인 — 마찬가지
    ("172.16.0", {"cache01"}),                                                   # IP(첫째)
    ("192.168.7.", {"cache01"}),                                                 # IP(둘째) — 하나라도 맞으면 된다
    ("10.0.0.5", {"web01", "old01"}),                                            # 같은 IP 를 쓰는 둘
    ("ubuntu", {"web01", "cache01", "old01", "bare01"}),
    ("  WEB01  ", {"web01"}),                                                    # 앞뒤 공백은 무시
    ("   ", ALL_HOSTS),                                                          # 공백뿐이면 필터가 아니다
    ("5.15-91", set()),                                                          # 실행 커널·태그·구분은 검색 대상이 아니다
    ("infra", set()),
    ("physical", set()),
    ("no-such-host", set()),
], ids=["hostname", "host_id", "os_name", "asset_no", "domain", "ip-first", "ip-second", "ip-shared", "os-many", "trim", "blank",
        "not-kernel", "not-tag", "not-kind", "no-match"])
def test_hosts_q_searches_the_documented_fields_case_insensitively(seeded, needle, expected):
    assert names(get(seeded, "/v1/hosts", q=needle)) == expected


def test_hosts_status_filter(seeded):
    by_status = {s: names(get(seeded, "/v1/hosts", status=s)) for s in ("ok", "error", "stale")}
    assert by_status == {"ok": {"web01", "cache01", "bare01"}, "error": {"db01"}, "stale": {"old01"}}
    assert all(h["status"] == "stale" for h in get(seeded, "/v1/hosts", status="stale"))


@pytest.mark.parametrize("bad", ["bogus", "OK", "okay", "xok", "ok,error", "unknown"])
def test_hosts_status_rejects_values_outside_ok_error_stale(seeded, bad):
    assert seeded.get("/v1/hosts", params={"status": bad}, headers=RD).status_code == 422
    assert seeded.get("/v1/hosts", params={"status": bad, "format": "csv"}, headers=RD).status_code == 422


def test_hosts_new_filters_combine_with_each_other_and_with_tag_and_ip(seeded):
    assert names(get(seeded, "/v1/hosts", tag="team:infra")) == {"web01"}                        # 기존 필터는 그대로 동작한다
    assert names(get(seeded, "/v1/hosts", ip="10.0.0.5")) == {"web01", "old01"}
    assert names(get(seeded, "/v1/hosts", tag="team:infra", status="ok")) == {"web01"}
    assert names(get(seeded, "/v1/hosts", tag="team:infra", status="error")) == set()
    assert names(get(seeded, "/v1/hosts", ip="10.0.0.5", status="stale")) == {"old01"}
    assert names(get(seeded, "/v1/hosts", ip="10.0.0.5", q="web")) == {"web01"}
    assert names(get(seeded, "/v1/hosts", q="ubuntu", status="ok")) == {"web01", "cache01", "bare01"}
    assert names(get(seeded, "/v1/hosts", q="ubuntu", status="stale", tag="team:infra")) == set()


def test_hosts_without_the_new_params_returns_every_host_as_before(seeded):
    base = get(seeded, "/v1/hosts")
    assert names(base) == ALL_HOSTS and len(base) == 5
    assert {h["hostname"]: h["ips"] for h in base} == {"web01": ["10.0.0.5"], "db01": ["10.0.1.6"], "cache01": ["172.16.0.3", "192.168.7.9"],
                                                       "old01": ["10.0.0.5"], "bare01": []}      # ips 는 목록 그대로(CSV 의 ';' 이음이 새지 않는다)
    assert {h["hostname"]: h["status"] for h in base} == {"web01": "ok", "db01": "error", "cache01": "ok", "old01": "stale", "bare01": "ok"}
    assert get(seeded, "/v1/hosts", q="") == base                                 # 빈 q 는 필터가 아니다


def test_hosts_csv_has_exactly_the_documented_columns_and_values(seeded):
    assert seeded.put("/v1/settings/kernel-policy", json={"rules": [{"os_family": "debian", "min_kernel": "5.15-100"}]}, headers=AD).status_code == 200
    r = seeded.get("/v1/hosts", params={"format": "csv"}, headers=RD)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"] == 'attachment; filename="hosts.csv"'
    text = r.content.decode("utf-8-sig")
    assert text.splitlines()[0] == HOSTS_CSV_HEADER
    rows = {x["hostname"]: x for x in csv.DictReader(io.StringIO(text))}
    seen = {h["hostname"]: h["last_seen"] for h in get(seeded, "/v1/hosts")}
    assert set(rows) == ALL_HOSTS and all(seen.values()) and seen["old01"] != seen["web01"]       # 호스트마다 다른 last_seen 이라 열 위치가 바뀌면 잡힌다
    expected = {
        "web01": dict(host_id=ALPHA, asset_no="AST-0001", kind="physical", domain="corp.example.com", ips="10.0.0.5", os_name="Ubuntu 22.04",
                      running="5.15-91", kernel_compliant="false", reboot_required="true", status="ok", tags="env=prod;team=infra"),
        "db01": dict(host_id=BRAVO, asset_no="AST-0002", kind="physical", domain="lab.example.org", ips="10.0.1.6", os_name="Rocky Linux 9.4",
                     running="5.15-100", kernel_compliant="", reboot_required="false", status="error", tags="team=data"),   # rhel 규칙이 없으면 판정 안 함
        "cache01": dict(host_id=CHARLIE, asset_no="", kind="unknown", domain="", ips="172.16.0.3;192.168.7.9", os_name="Ubuntu 22.04",
                        running="5.15-100", kernel_compliant="true", reboot_required="false", status="ok", tags=""),
        "old01": dict(host_id=DELTA, asset_no="", kind="unknown", domain="", ips="10.0.0.5", os_name="Ubuntu 22.04",
                      running="5.15-91", kernel_compliant="false", reboot_required="false", status="stale", tags=""),
        "bare01": dict(host_id=ECHO, asset_no="", kind="unknown", domain="", ips="", os_name="Ubuntu 22.04",
                       running="", kernel_compliant="", reboot_required="", status="ok", tags=""),                       # 커널 정보가 없으면 빈 칸
    }
    for hostname, want in expected.items():
        assert rows[hostname] == {"hostname": hostname, "last_seen": seen[hostname], **want}, hostname


@pytest.mark.parametrize("params, count", [
    ({"status": "stale"}, 1), ({"status": "ok"}, 3), ({"status": "error"}, 1), ({"q": "ubuntu"}, 4), ({"q": "10.0.0.5", "status": "ok"}, 1),
    ({"tag": "team:infra"}, 1), ({"ip": "172.16.0.3"}, 1), ({"q": "192.168.7"}, 1), ({"q": "no-such-host"}, 0), ({}, 5),
])
def test_hosts_csv_rows_are_the_same_hosts_as_the_filtered_json(seeded, params, count):
    want = {h["host_id"] for h in get(seeded, "/v1/hosts", **params)}
    assert len(want) == count
    assert {x["host_id"] for x in csv_rows(seeded, "/v1/hosts", **params)} == want


def test_hosts_csv_neutralizes_formulas_in_agent_and_admin_controlled_columns(client):
    """호스트명·OS 이름은 에이전트가 보낸 값, 태그 키는 관리자 입력이다 — 엑셀이 수식으로 실행하지 않게 모두 접두 처리된다."""
    body = make_snapshot(host_id="x1", hostname="=cmd|' /C calc'!A0").to_dict()
    body["os"]["name"] = "@SUM(1+1)"
    assert client.post("/v1/ingest", json=body, headers=ING).status_code == 200
    assert client.put("/v1/hosts/x1/tags", json={"=evil": "1"}, headers=AD).status_code == 200
    rows = csv_rows(client, "/v1/hosts")
    assert len(rows) == 1
    assert rows[0]["hostname"].startswith("'=") and rows[0]["os_name"] == "'@SUM(1+1)" and rows[0]["tags"] == "'=evil=1"


# --- GET /v1/kernels/hosts?q= -----------------------------------------------

@pytest.mark.parametrize("needle, expected", [
    ("web01", {"web01"}),                                                        # 호스트명
    ("CHARLIE-3", {"cache01"}),                                                  # 호스트 ID — 대소문자 무시
    ("ast-0002", {"db01"}),                                                      # 자산번호 — annotate 뒤에 붙는 열
    ("ast-", {"web01", "db01"}),
    ("b01", {"web01", "db01"}),                                                  # 호스트명 일부 — 4대 중 둘
    ("5.15-91", set()),                                                          # 실행 커널·OS 계열·태그는 검색 대상이 아니다
    ("debian", set()),
    ("infra", set()),
], ids=["hostname", "host_id", "asset_no", "asset-prefix", "partial-hostname", "not-kernel", "not-family", "not-tag"])
def test_kernel_hosts_q_matches_hostname_host_id_and_asset_no(seeded, needle, expected):
    assert names(get(seeded, "/v1/kernels/hosts", q=needle)) == expected


def test_kernel_hosts_q_applies_to_csv_and_combines_with_other_filters(seeded):
    header = seeded.get("/v1/kernels/hosts", params={"format": "csv", "q": "web"}, headers=RD).content.decode("utf-8-sig").splitlines()[0]
    assert header == "host_id,hostname,os_family,running,min_kernel,compliant,latest_installed,reboot_required,asset_no,kind,domain,tags"   # 열은 그대로
    assert {x["hostname"] for x in csv_rows(seeded, "/v1/kernels/hosts", q="web")} == {"web01"}
    assert {x["hostname"] for x in csv_rows(seeded, "/v1/kernels/hosts", q="ast-")} == {"web01", "db01"}
    assert {x["hostname"] for x in csv_rows(seeded, "/v1/kernels/hosts", q="no-such-host")} == set()
    assert len(csv_rows(seeded, "/v1/kernels/hosts")) == 4                           # q 가 없으면 커널 정보가 있는 4대 전부(bare01 은 커널 정보가 없다)
    seeded.put("/v1/settings/kernel-policy", json={"rules": [{"os_family": "debian", "min_kernel": "5.15-100"}]}, headers=AD)
    assert names(get(seeded, "/v1/kernels/hosts", compliant="false", q="old")) == {"old01"}
    assert names(get(seeded, "/v1/kernels/hosts", compliant="false", q="cache")) == set()       # cache01 은 준수
    assert names(get(seeded, "/v1/kernels/hosts", reboot_required="true", q="web")) == {"web01"}
    assert names(get(seeded, "/v1/kernels/hosts", tag="team:infra", q="db")) == set()
    assert {x["hostname"] for x in csv_rows(seeded, "/v1/kernels/hosts", compliant="false", q="old")} == {"old01"}


def test_kernel_hosts_without_q_is_unchanged(seeded):
    rows = get(seeded, "/v1/kernels/hosts")
    assert names(rows) == {"web01", "db01", "cache01", "old01"}
    assert get(seeded, "/v1/kernels/hosts", q="") == rows and get(seeded, "/v1/kernels/hosts", q="  ") == rows


# --- GET /v1/network/ips?conflicts= -----------------------------------------

def test_ips_conflicts_keeps_only_rows_whose_ip_another_host_also_uses(seeded):
    rows = get(seeded, "/v1/network/ips", conflicts="true")
    assert {(r["ip"], r["hostname"]) for r in rows} == {("10.0.0.5", "web01"), ("10.0.0.5", "old01")} and len(rows) == 2
    assert all(r["duplicate"] is True for r in rows)
    assert {(r["ip"], r["hostname"]) for r in get(seeded, "/v1/network/ips", conflicts="true", q="old")} == {("10.0.0.5", "old01")}
    assert get(seeded, "/v1/network/ips", conflicts="true", q="172.16") == []        # 충돌이 아닌 IP 는 q 가 맞아도 빠진다


def test_ips_conflicts_is_judged_against_all_hosts_even_when_a_tag_narrows_the_list(seeded):
    """충돌 상대(old01)에 태그가 없어도 web01 의 10.0.0.5 는 여전히 충돌이다."""
    rows = get(seeded, "/v1/network/ips", conflicts="true", tag="team:infra")
    assert [(r["ip"], r["hostname"], r["duplicate"]) for r in rows] == [("10.0.0.5", "web01", True)]
    assert get(seeded, "/v1/network/ips", conflicts="true", tag="team:data") == []     # db01 의 IP 는 충돌이 아니다


def test_ips_conflicts_applies_to_csv(seeded):
    rows = csv_rows(seeded, "/v1/network/ips", conflicts="true")
    assert {(x["ip"], x["hostname"]) for x in rows} == {("10.0.0.5", "web01"), ("10.0.0.5", "old01")}
    assert {x["duplicate"] for x in rows} == {"true"}
    everything = csv_rows(seeded, "/v1/network/ips")
    assert len(everything) == 5 and {x["duplicate"] for x in everything} == {"true", "false"}


def test_ips_without_conflicts_or_with_conflicts_false_returns_everything(seeded):
    base = get(seeded, "/v1/network/ips")
    assert len(base) == 5 and {r["duplicate"] for r in base} == {True, False}
    assert get(seeded, "/v1/network/ips", conflicts="false") == base                   # false 는 필터가 아니다(충돌이 아닌 행만 보이는 것도 아님)
    assert seeded.get("/v1/network/ips", params={"conflicts": "maybe"}, headers=RD).status_code == 422


# --- GET /v1/network/ips?q= 가 자산번호도 본다(화면 검색창이 '자산번호'를 안내한다) ------------

def ip_pairs(rows):
    return {(r["ip"], r["hostname"]) for r in rows}


@pytest.mark.parametrize("needle, expected", [
    ("AST-0001", {("10.0.0.5", "web01")}),                                       # 자산번호 — 같은 IP 를 쓰는 old01(자산 없음)은 빠진다: IP 가 아니라 자산으로 맞았다
    ("ast-0002", {("10.0.1.6", "db01")}),                                        # 대소문자 무시
    ("  AST-0001  ", {("10.0.0.5", "web01")}),                                   # 앞뒤 공백은 무시
    ("ast-", {("10.0.0.5", "web01"), ("10.0.1.6", "db01")}),                     # 부분 일치 — 자산이 있는 두 호스트
    ("0002", {("10.0.1.6", "db01")}),
    ("X-9", set()),                                                              # 수집된 적 없는 자산(ghost)은 IP 행이 없다
    ("none", set()),                                                             # 자산이 없는 호스트의 asset_no(None)를 'None' 글자로 읽어 맞추면 안 된다
    ("non", set()),
    # 기존 검색 대상은 그대로다
    ("10.0.1.6", {("10.0.1.6", "db01")}),                                        # IP
    ("AA:00:00:00:00:33", {("192.168.7.9", "cache01")}),                         # MAC
    ("old", {("10.0.0.5", "old01")}),                                            # 호스트명
    ("eth1", {("192.168.7.9", "cache01")}),                                      # 인터페이스
    ("   ", {("10.0.0.5", "web01"), ("10.0.0.5", "old01"), ("10.0.1.6", "db01"), ("172.16.0.3", "cache01"), ("192.168.7.9", "cache01")}),   # 공백뿐이면 필터가 아니다
    ("physical", set()),                                                         # 자산의 다른 열(구분·도메인)은 검색 대상이 아니다
    ("lab.example", set()),
])
def test_ips_q_matches_asset_no_as_well_as_ip_mac_hostname_and_interface(seeded, needle, expected):
    assert ip_pairs(get(seeded, "/v1/network/ips", q=needle)) == expected


def test_ips_q_by_asset_no_returns_that_hosts_rows_with_asset_columns_and_the_global_duplicate_flag(seeded):
    rows = get(seeded, "/v1/network/ips", q="AST-0001")
    assert len(rows) == 1
    row = rows[0]
    assert (row["asset_no"], row["kind"], row["hostname"], row["host_id"]) == ("AST-0001", "physical", "web01", ALPHA)
    assert row["duplicate"] is True and row["cidr"] == "10.0.0.5/24"           # 충돌 판정은 거르기 전 전체(old01 도 같은 IP)를 기준으로 한다
    # 한 호스트의 인터페이스가 여럿이면 그 행이 모두 나온다(cache01 은 자산이 없으므로 호스트명으로)
    assert ip_pairs(get(seeded, "/v1/network/ips", q="cache01")) == {("172.16.0.3", "cache01"), ("192.168.7.9", "cache01")}


def test_ips_q_by_asset_no_combines_with_conflicts_and_tag(seeded):
    assert ip_pairs(get(seeded, "/v1/network/ips", q="AST-0001", conflicts="true")) == {("10.0.0.5", "web01")}    # web01 의 IP 는 충돌이다
    assert get(seeded, "/v1/network/ips", q="AST-0002", conflicts="true") == []                                   # db01 의 IP 는 충돌이 아니다
    assert ip_pairs(get(seeded, "/v1/network/ips", q="AST-0001", tag="team:infra")) == {("10.0.0.5", "web01")}
    assert get(seeded, "/v1/network/ips", q="AST-0001", tag="team:data") == []                                    # web01 은 team:infra 다


def test_ips_q_by_asset_no_applies_to_csv_with_the_same_rows_and_columns(seeded):
    header = seeded.get("/v1/network/ips", params={"format": "csv", "q": "AST-0001"}, headers=RD).content.decode("utf-8-sig").splitlines()[0]
    assert header == "ip,cidr,family,interface,mac,state,hostname,host_id,asset_no,kind,duplicate"                # 열은 그대로
    rows = csv_rows(seeded, "/v1/network/ips", q="AST-0001")
    assert [(x["ip"], x["hostname"], x["asset_no"], x["duplicate"]) for x in rows] == [("10.0.0.5", "web01", "AST-0001", "true")]
    for needle in ("ast-", "AST-0002", "X-9", "none", "old", "  AST-0001  "):                                      # 화면(JSON)과 CSV 는 같은 호스트×IP 를 담는다
        assert ip_pairs(csv_rows(seeded, "/v1/network/ips", q=needle)) == ip_pairs(get(seeded, "/v1/network/ips", q=needle)), needle
    assert len(csv_rows(seeded, "/v1/network/ips")) == 5                                                          # q 가 없으면 전부


# --- GET /v1/network/listening?q= (프론트 요청으로 계약에 더한 항목) ---------------

ALL_PORTS = {("web01", 22), ("web01", 443), ("web01", 161), ("web01", 9999), ("db01", 22), ("db01", 5432)}


def seed_ports(client):
    """서비스 이름이 있는 포트 다섯 개(ssh 둘·https·snmp·postgresql)와 이름이 없는 포트 하나(9999)."""
    push(client, make_snapshot(host_id="p1", hostname="web01", ports=[port("tcp", 22), port("tcp", 443), port("udp", 161), port("tcp", 9999)]))
    push(client, make_snapshot(host_id="p2", hostname="db01", ports=[port("tcp", 22), port("tcp", 5432, "127.0.0.1")]))


def listening(client, **params):
    return {(r["hostname"], r["port"]) for r in get(client, "/v1/network/listening", **params)}


@pytest.mark.parametrize("needle, expected", [
    ("ssh", {("web01", 22), ("db01", 22)}),                                      # 서비스 이름
    ("SSH", {("web01", 22), ("db01", 22)}),                                      # 대소문자 무시
    ("22", {("web01", 22), ("db01", 22)}),                                       # 포트 번호
    ("udp", {("web01", 161)}),                                                   # 프로토콜
    ("tcp", ALL_PORTS - {("web01", 161)}),
    ("postgres", {("db01", 5432)}),
    ("443 https", {("web01", 443)}),                                             # 화면 검색과 같은 문자열 "<포트> <서비스> <프로토콜>" 안에서 찾는다
    ("ssh tcp", {("web01", 22), ("db01", 22)}),
    ("tcp 22", set()),                                                           # 순서가 다르면 맞지 않는다(화면과 같은 규칙)
    ("9999", {("web01", 9999)}),                                                 # 서비스 이름이 없는 포트도 번호로 찾는다
    ("  ssh  ", {("web01", 22), ("db01", 22)}),                                  # 앞뒤 공백은 무시
    ("   ", ALL_PORTS),                                                          # 공백뿐이면 필터가 아니다
    ("web01", set()),                                                            # 호스트명·바인딩 주소·노출 구분은 화면 검색 대상이 아니다
    ("0.0.0.0", set()),
    ("loopback", set()),
    ("no-such", set()),
], ids=["service", "case", "port", "proto", "proto-many", "service-prefix", "port-service", "service-proto", "wrong-order", "no-service",
        "trim", "blank", "not-hostname", "not-bind", "not-exposure", "no-match"])
def test_listening_q_matches_port_service_and_proto_like_the_ports_page(client, needle, expected):
    seed_ports(client)
    assert listening(client, q=needle) == expected


def test_listening_q_combines_with_the_other_filters_and_applies_to_csv(client):
    seed_ports(client)
    assert listening(client, q="ssh", exposure="any") == {("web01", 22), ("db01", 22)}
    assert listening(client, q="postgres", exposure="loopback") == {("db01", 5432)}
    assert listening(client, q="postgres", exposure="any") == set()
    assert listening(client, q="tcp", port=22) == {("web01", 22), ("db01", 22)}
    assert listening(client, q="ssh", proto="udp") == set()
    assert listening(client, q="snmp", notable="true") == {("web01", 161)}        # udp 161 은 주의 포트
    assert listening(client, q="ssh", notable="true") == set()
    rows = csv_rows(client, "/v1/network/listening", q="ssh")
    assert {(x["hostname"], x["port"], x["service"]) for x in rows} == {("web01", "22", "ssh"), ("db01", "22", "ssh")} and len(rows) == 2
    assert csv_rows(client, "/v1/network/listening", q="no-such") == []
    assert len(csv_rows(client, "/v1/network/listening")) == 6                    # q 가 없으면 전부


def test_listening_without_q_is_unchanged(client):
    seed_ports(client)
    assert listening(client) == ALL_PORTS
    assert get(client, "/v1/network/listening", q="") == get(client, "/v1/network/listening")


# --- GET /v1/assets?status=mismatch -----------------------------------------

def test_assets_status_mismatch_lists_the_rows_that_have_flags(seeded):
    label = lambda rows: [(r["asset"] or {}).get("asset_no") or r["hostname"] for r in rows]  # noqa: E731  (미등록 행은 asset 이 None)
    rows = get(seeded, "/v1/assets", status="mismatch")
    assert label(rows) == ["AST-0002"] and rows[0]["flags"] == ["kind_mismatch", "ip_mismatch"]
    assert all(r["flags"] for r in rows)
    assert get(seeded, "/v1/assets", status="mismatch", q="web01") == []              # 일치하는 자산이 없으면 빈 목록(web01 은 flags 가 없다)
    assert label(get(seeded, "/v1/assets", status="mismatch", kind="physical")) == ["AST-0002"]
    assert get(seeded, "/v1/assets", status="mismatch", kind="virtual") == []


def test_assets_mismatch_applies_to_csv(seeded):
    rows = csv_rows(seeded, "/v1/assets", status="mismatch")
    assert [(x["asset_no"], x["status"], x["flags"]) for x in rows] == [("AST-0002", "linked", "kind_mismatch;ip_mismatch")]
    assert len(csv_rows(seeded, "/v1/assets")) == 6


def test_assets_other_statuses_are_unchanged_and_unknown_ones_rejected(seeded):
    by = lambda **p: [(r["asset"] or {}).get("asset_no") or r["hostname"] for r in get(seeded, "/v1/assets", **p)]  # noqa: E731
    assert by(status="linked") == ["AST-0001", "AST-0002"] and by(status="uncollected") == ["X-9"]
    assert sorted(by(status="unregistered")) == ["bare01", "cache01", "old01"]
    assert len(by()) == 6
    for bad in ("mismatches", "Mismatch", "bogus"):
        assert seeded.get("/v1/assets", params={"status": bad}, headers=RD).status_code == 422, bad


# --- GET /v1/images/{repo}?cluster= -----------------------------------------

def seed_clusters(client):
    """컨테이너 seed(클러스터 A·B·미확인, 도커 서버) + 클러스터 B 에도 nginx — 같은 이미지가 여러 곳에 있어야 한정이 의미가 있다."""
    seed_containers(client)
    push(client, make_snapshot(host_id="n3", hostname="k8s-b1", at=T0.replace(hour=1), k8s=k8s(CB, api="https://10.9.0.1:6443"), containers=[
        ctr("api", "team/api:2.0", pod="api-1", namespace="dev"), ctr("web", "nginx:1.27", pod="web-9", namespace="dev", cid="web9web9web9")]))


def test_image_detail_cluster_limits_containers_and_distribution_to_that_cluster(client):
    seed_clusters(client)
    whole = get(client, "/v1/images/nginx")
    assert (whole["host_count"], whole["container_count"]) == (4, 5)
    assert {c["hostname"] for c in whole["containers"]} == {"k8s-a1", "k8s-a2", "k8s-b1", "docker01"}
    a = get(client, "/v1/images/nginx", cluster=CA)
    assert {c["hostname"] for c in a["containers"]} == {"k8s-a1", "k8s-a2"} and len(a["containers"]) == 3
    assert all(c["cluster_id"] == CA for c in a["containers"])
    assert (a["repo"], a["host_count"], a["container_count"], a["tag_count"]) == ("nginx", 2, 3, 2)
    assert {t["tag"]: (t["host_count"], t["container_count"]) for t in a["tags"]} == {"1.25": (1, 2), "1.26": (1, 1)}
    b = get(client, "/v1/images/nginx", cluster=CB)
    assert [(c["hostname"], c["image"]) for c in b["containers"]] == [("k8s-b1", "nginx:1.27")]
    assert (b["host_count"], b["container_count"], b["tag_count"]) == (1, 1, 1)


def test_image_detail_cluster_unknown_means_the_empty_cluster_id(client):
    seed_clusters(client)
    d = get(client, "/v1/images/redis", cluster="unknown")
    assert [(c["hostname"], c["cluster_id"]) for c in d["containers"]] == [("k8s-x1", "")]
    assert client.get("/v1/images/redis", params={"cluster": CA}, headers=RD).status_code == 404
    assert client.get("/v1/images/nginx", params={"cluster": "unknown"}, headers=RD).status_code == 404    # 도커 서버(노드가 아님)는 '미확인 클러스터'가 아니다


def test_image_detail_cluster_without_a_match_is_404(client):
    seed_clusters(client)
    for repo_name, cluster in (("nginx", "f" * 64), ("registry.k8s.io/coredns/coredns", CB), ("team/api", CA), ("nope", CA), ("nope", "unknown")):
        assert client.get(f"/v1/images/{repo_name}", params={"cluster": cluster}, headers=RD).status_code == 404, (repo_name, cluster)
    assert get(client, "/v1/images/registry.k8s.io/coredns/coredns", cluster=CA)["containers"][0]["hostname"] == "k8s-a1"   # 경로에 '/' 가 있는 저장소


def test_image_detail_cluster_combines_with_active(client):
    seed_clusters(client)
    assert client.get("/v1/images/busybox", params={"cluster": CA}, headers=RD).status_code == 404            # 종료된 컨테이너뿐이라 기본(active)에선 없다
    d = get(client, "/v1/images/busybox", cluster=CA, active="false")
    assert [(c["hostname"], c["state"]) for c in d["containers"]] == [("k8s-a1", "exited")]
    assert client.get("/v1/images/busybox", params={"cluster": CB, "active": "false"}, headers=RD).status_code == 404


def test_image_detail_without_cluster_is_unchanged(client):
    seed_clusters(client)
    d = get(client, "/v1/images/nginx")
    assert set(d) == {"repo", "host_count", "container_count", "tag_count", "tags", "containers"}
    assert {t["tag"]: (t["host_count"], t["container_count"]) for t in d["tags"]} == {"1.25": (2, 3), "1.26": (1, 1), "1.27": (1, 1)}
    assert len(d["containers"]) == 5 and {c["cluster_id"] for c in d["containers"]} == {CA, CB, None}               # 도커 서버는 cluster_id 가 None
