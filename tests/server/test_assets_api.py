"""자산 대장(웹에서 관리) + 수집 호스트 연결 + 기존 목록에 붙는 자산 열 + 장비 정보 적재."""
import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from tests.server.conftest import T0, dpkg, hw, iface, make_snapshot, port

ING, RD, AD = {"Authorization": "Bearer ing-tok"}, {"Authorization": "Bearer read-tok"}, {"Authorization": "Bearer adm-tok"}


@pytest.fixture
def client(repo, clock):
    settings = ApiSettings(ingest_tokens=("ing-tok",), read_tokens=("read-tok",), admin_tokens=("adm-tok",))
    return TestClient(create_app(repo, settings, clock=clock))


def push(client, snap):
    r = client.post("/v1/ingest", json=snap.to_dict(), headers=ING)
    assert r.status_code == 200, r.text
    return r


def add(client, **kw):
    body = {"asset_no": "A-1", "kind": "physical", **kw}
    return client.post("/v1/assets", json=body, headers=AD)


def rows(client, **params):
    r = client.get("/v1/assets", params=params, headers=RD)
    assert r.status_code == 200, r.text
    return r.json()


def seed_hosts(client):
    push(client, make_snapshot(host_id="h1", hostname="esx01", hardware=hw("physical", "SN-ESX01", "esx01.corp.example.com"),
                               interfaces=[iface(addresses=("10.0.0.5/24",))], packages=[dpkg("openssl", "3.0.2")]))
    push(client, make_snapshot(host_id="h2", hostname="web01", hardware=hw("virtual", "VM-WEB01", "web01.corp.example.com", "vmware", "VMware, Inc.", "VMware7,1"),
                               interfaces=[iface(addresses=("10.0.0.6/24",))], packages=[dpkg("openssl", "3.0.13")], ports=[port("tcp", 22)]))
    push(client, make_snapshot(host_id="h3", hostname="old01"))                         # 장비 정보를 수집하지 못한 호스트(옛 에이전트)


# --- 장비 정보 적재 ---
def test_ingested_hardware_is_returned_in_host_detail(client):
    seed_hosts(client)
    d = client.get("/v1/hosts/h2", headers=RD).json()
    assert d["hardware"] == {"kind": "virtual", "virt": "vmware", "vendor": "VMware, Inc.", "model": "VMware7,1",
                             "serial": "VM-WEB01", "fqdn": "web01.corp.example.com", "domain": "corp.example.com"}
    assert client.get("/v1/hosts/h3", headers=RD).json()["hardware"] is None


def test_hardware_is_updated_and_a_failed_collector_keeps_the_previous_value(client, clock):
    push(client, make_snapshot(host_id="h1", hostname="a", hardware=hw("physical", "S1", "a.corp.com")))
    clock.advance(hours=1)
    push(client, make_snapshot(host_id="h1", hostname="a", at=T0.replace(hour=1), hardware=hw("virtual", "S2", "a.corp.com", "kvm")))
    assert client.get("/v1/hosts/h1", headers=RD).json()["hardware"]["kind"] == "virtual"
    push(client, make_snapshot(host_id="h1", hostname="a", at=T0.replace(hour=2), errors={"hardware": "boom"}))        # hardware 수집 실패
    assert client.get("/v1/hosts/h1", headers=RD).json()["hardware"]["serial"] == "S2"                                 # 실패한 회차는 건드리지 않는다


def test_hardware_strings_are_sanitized_at_ingest(client):
    snap = make_snapshot(host_id="h1", hostname="a", hardware=hw("physical", "SN\x001", "a.corp.com", vendor="Dell\x00 Inc."))
    body = snap.to_dict()
    assert client.post("/v1/ingest", json=body, headers=ING).status_code == 200
    h = client.get("/v1/hosts/h1", headers=RD).json()["hardware"]
    assert "\x00" not in h["serial"] + h["vendor"]


def test_unknown_kind_value_from_a_newer_agent_is_stored_as_unknown(client):
    body = make_snapshot(host_id="h1", hostname="a", hardware=hw("physical", "S", "a.c.com")).to_dict()
    body["hardware"]["kind"] = "quantum"
    assert client.post("/v1/ingest", json=body, headers=ING).status_code == 200
    assert client.get("/v1/hosts/h1", headers=RD).json()["hardware"]["kind"] == "unknown"


def test_placeholder_serial_is_dropped_at_ingest(client):
    push(client, make_snapshot(host_id="h1", hostname="a", hardware=hw("physical", "To Be Filled By O.E.M.", "a.c.com")))
    assert client.get("/v1/hosts/h1", headers=RD).json()["hardware"]["serial"] == ""


# --- 자산 CRUD·권한 ---
def test_asset_write_requires_admin_read_requires_read(client):
    body = {"asset_no": "A-1", "kind": "physical"}
    assert client.post("/v1/assets", json=body).status_code == 401
    assert client.post("/v1/assets", json=body, headers=RD).status_code == 403
    assert client.post("/v1/assets", json=body, headers=ING).status_code == 403
    aid = add(client).json()["id"]
    assert client.put(f"/v1/assets/{aid}", json=body, headers=RD).status_code == 403
    assert client.delete(f"/v1/assets/{aid}", headers=RD).status_code == 403
    assert client.get("/v1/assets").status_code == 401
    assert client.get("/v1/assets", headers=ING).status_code == 403
    assert client.get(f"/v1/assets/{aid}", headers=RD).status_code == 200
    assert client.get("/v1/assets/summary", headers=RD).status_code == 200


def test_create_update_delete_roundtrip(client):
    r = add(client, serial="SN1", hostname="Web01", domain="Corp.Example.com", ip="10.0.0.5", note="랙 A3")
    assert r.status_code == 201
    a = r.json()
    assert (a["asset_no"], a["kind"], a["serial"], a["hostname"], a["domain"], a["ip"], a["note"]) == \
        ("A-1", "physical", "SN1", "Web01", "corp.example.com", "10.0.0.5", "랙 A3")      # 도메인은 소문자로 저장
    put = client.put(f"/v1/assets/{a['id']}", json={"asset_no": "A-1", "kind": "virtual", "note": "VM 으로 전환"}, headers=AD)
    assert put.status_code == 200 and put.json()["kind"] == "virtual" and put.json()["serial"] == ""     # PUT 은 전체 교체
    assert client.delete(f"/v1/assets/{a['id']}", headers=AD).status_code == 200
    assert client.get(f"/v1/assets/{a['id']}", headers=RD).status_code == 404
    assert client.delete(f"/v1/assets/{a['id']}", headers=AD).status_code == 404
    assert client.put(f"/v1/assets/{a['id']}", json={"asset_no": "A-1", "kind": "physical"}, headers=AD).status_code == 404


@pytest.mark.parametrize("patch", [
    {"asset_no": ""}, {"asset_no": "   "}, {"asset_no": "x" * 65}, {"kind": "container"}, {"kind": ""},
    {"ip": "10.0.0.999"}, {"ip": "not-an-ip"}, {"domain": "bad domain"}, {"domain": "-x.com"}, {"hostname": "has space"},
    {"serial": "s" * 129}, {"note": "n" * 501}, {"asset_no": "\x00"}, {"parent_asset_id": 99999, "kind": "virtual"},
    {"parent_asset_id": 1},                                                      # 물리 장비는 상위 호스트가 없다
])
def test_validation_rejects_bad_input_with_422(client, patch):
    add(client, asset_no="P-1")                                                  # id=1, 물리
    body = {"asset_no": "A-2", "kind": "physical", **patch}
    assert client.post("/v1/assets", json=body, headers=AD).status_code == 422


def test_control_characters_are_stripped_not_stored(client):
    a = add(client, asset_no="A\x00-9", serial="S\x1bN", note="a\x00b").json()
    assert a["asset_no"] == "A-9" and a["serial"] == "SN" and a["note"] == "ab"


def test_parent_must_be_a_physical_asset_and_not_self(client):
    p = add(client, asset_no="P-1").json()
    v = add(client, asset_no="V-1", kind="virtual", parent_asset_id=p["id"]).json()
    assert add(client, asset_no="V-2", kind="virtual", parent_asset_id=v["id"]).status_code == 422       # VM 아래에 VM 불가
    r = client.put(f"/v1/assets/{v['id']}", json={"asset_no": "V-1", "kind": "virtual", "parent_asset_id": v["id"]}, headers=AD)
    assert r.status_code == 422


def test_duplicate_asset_no_is_409_case_insensitively(client):
    add(client, asset_no="ABC-1")
    assert add(client, asset_no="abc-1").status_code == 409
    other = add(client, asset_no="ABC-2").json()
    assert client.put(f"/v1/assets/{other['id']}", json={"asset_no": "Abc-1", "kind": "physical"}, headers=AD).status_code == 409
    assert client.put(f"/v1/assets/{other['id']}", json={"asset_no": "ABC-2", "kind": "physical", "note": "x"}, headers=AD).status_code == 200   # 자기 자신과는 충돌 아님


def test_physical_with_vms_cannot_be_deleted_or_turned_virtual(client):
    p = add(client, asset_no="P-1").json()
    v = add(client, asset_no="V-1", kind="virtual", parent_asset_id=p["id"]).json()
    d = client.delete(f"/v1/assets/{p['id']}", headers=AD)
    assert d.status_code == 409 and "V-1" in d.text
    assert client.put(f"/v1/assets/{p['id']}", json={"asset_no": "P-1", "kind": "virtual"}, headers=AD).status_code == 409
    assert client.delete(f"/v1/assets/{v['id']}", headers=AD).status_code == 200
    assert client.delete(f"/v1/assets/{p['id']}", headers=AD).status_code == 200


def test_explicit_host_link_must_exist_and_be_unique(client):
    seed_hosts(client)
    assert add(client, asset_no="A-1", host_id="nope").status_code == 422
    assert add(client, asset_no="A-1", host_id="h1").status_code == 201
    assert add(client, asset_no="A-2", host_id="h1").status_code == 409


# --- 연결과 통합 목록 ---
def test_unified_list_has_linked_uncollected_and_unregistered(client):
    seed_hosts(client)
    add(client, asset_no="P-1", serial="sn-esx01")                                                  # 시리얼로 h1 과 연결
    add(client, asset_no="V-1", kind="virtual", hostname="web01", parent_asset_id=1)                # 호스트명으로 h2 와 연결
    add(client, asset_no="X-9", hostname="ghost")                                                   # 수집 안 됨
    items = {i["asset"]["asset_no"] if i["asset"] else i["hostname"]: i for i in rows(client)}
    assert items["P-1"]["status"] == "linked" and items["P-1"]["host_id"] == "h1" and items["P-1"]["match_by"] == "serial"
    assert items["V-1"]["status"] == "linked" and items["V-1"]["host_id"] == "h2" and items["V-1"]["parent_asset_no"] == "P-1"
    assert items["P-1"]["vm_count"] == 1
    assert items["X-9"]["status"] == "uncollected" and items["X-9"]["host_id"] is None
    assert items["old01"]["status"] == "unregistered" and items["old01"]["kind"] == "unknown"       # 등록 안 됐어도 수집된 건 표시된다


def test_filters_kind_status_and_search(client):
    seed_hosts(client)
    add(client, asset_no="P-1", serial="SN-ESX01")
    add(client, asset_no="X-9", hostname="ghost", note="창고")
    assert {i["status"] for i in rows(client, status="uncollected")} == {"uncollected"}
    assert {i["status"] for i in rows(client, status="unregistered")} == {"unregistered"}
    assert all(i["kind"] == "virtual" for i in rows(client, kind="virtual")) and len(rows(client, kind="virtual")) == 1     # h2(감지: virtual)
    assert [i["asset"]["asset_no"] for i in rows(client, q="창고")] == ["X-9"]
    assert [i["hostname"] for i in rows(client, q="10.0.0.6")] == ["web01"]
    assert client.get("/v1/assets", params={"status": "bogus"}, headers=RD).status_code == 422


def test_summary_counts(client):
    seed_hosts(client)
    add(client, asset_no="P-1", serial="SN-ESX01")
    add(client, asset_no="X-9", hostname="ghost")
    s = client.get("/v1/assets/summary", headers=RD).json()
    assert s["assets"] == 2 and s["linked"] == 1 and s["uncollected"] == 1 and s["unregistered"] == 2
    assert s["physical"] == 2 and s["virtual"] == 1                                                  # P-1, X-9(물리) / h2(감지 virtual)


def test_mismatch_flags_are_reported(client):
    seed_hosts(client)
    add(client, asset_no="P-1", kind="virtual", hostname="esx01", ip="10.9.9.9")                      # 대장은 VM·다른 IP, 수집은 물리·10.0.0.5
    item = next(i for i in rows(client) if i["asset"] and i["asset"]["asset_no"] == "P-1")
    assert set(item["flags"]) == {"kind_mismatch", "ip_mismatch"}


def test_deleting_the_host_keeps_the_asset_as_uncollected_and_vice_versa(client):
    seed_hosts(client)
    aid = add(client, asset_no="P-1", serial="SN-ESX01").json()["id"]
    assert client.delete("/v1/hosts/h1", headers=AD).status_code == 200
    item = next(i for i in rows(client) if i["asset"] and i["asset"]["id"] == aid)
    assert item["status"] == "uncollected"
    push(client, make_snapshot(host_id="h1", hostname="esx01", hardware=hw("physical", "SN-ESX01", "esx01.corp.example.com")))   # 다시 수집
    assert next(i for i in rows(client) if i["asset"] and i["asset"]["id"] == aid)["status"] == "linked"
    client.delete(f"/v1/assets/{aid}", headers=AD)
    assert client.get("/v1/hosts/h1", headers=RD).status_code == 200


# --- 기존 목록과의 연계 ---
def test_asset_columns_appear_in_every_host_list_and_without_an_asset_the_detected_values_show(client):
    seed_hosts(client)
    add(client, asset_no="V-1", kind="virtual", hostname="web01")
    cols = lambda r: (r["asset_no"], r["kind"], r["kind_source"])  # noqa: E731

    hosts = {h["hostname"]: h for h in client.get("/v1/hosts", headers=RD).json()}
    assert cols(hosts["web01"]) == ("V-1", "virtual", "asset")
    assert cols(hosts["esx01"]) == (None, "physical", "detected")        # 자산 미등록이어도 수집된 구분이 보인다
    assert cols(hosts["old01"]) == (None, "unknown", "detected")
    assert hosts["web01"]["domain"] == "corp.example.com"

    kh = {h["hostname"]: h for h in client.get("/v1/kernels/hosts", headers=RD).json()}
    assert cols(kh["web01"]) == ("V-1", "virtual", "asset") and kh["esx01"]["asset_no"] is None

    sw = client.get("/v1/software/openssl", headers=RD).json()["hosts"]
    assert {h["hostname"]: h["asset_no"] for h in sw} == {"esx01": None, "web01": "V-1"}

    push(client, make_snapshot(host_id="h2", hostname="web01", at=T0.replace(hour=3), packages=[dpkg("openssl", "9.9.9")],
                               hardware=hw("virtual", "VM-WEB01", "web01.corp.example.com", "vmware")))        # 버전 변경 이벤트를 만든다
    ev = client.get("/v1/events", headers=RD).json()
    assert ev, "이벤트가 있어야 아래 단언이 의미가 있다(빈 목록에 대한 all() 은 항상 참)"
    assert all(e["asset_no"] == "V-1" and e["kind"] == "virtual" for e in ev if e["host_id"] == "h2")

    ips = client.get("/v1/network/ips", headers=RD).json()
    assert {r["hostname"]: r["asset_no"] for r in ips} == {"esx01": None, "web01": "V-1"}
    lp = client.get("/v1/network/listening", headers=RD).json()
    assert lp and all(r["asset_no"] == "V-1" for r in lp)

    detail = client.get("/v1/hosts/h2", headers=RD).json()
    assert detail["asset"]["asset_no"] == "V-1" and detail["asset"]["match_by"] == "hostname"
    assert client.get("/v1/hosts/h1", headers=RD).json()["asset"]["asset_id"] is None


def test_asset_columns_follow_edits_immediately(client):
    seed_hosts(client)
    aid = add(client, asset_no="V-1", kind="virtual", hostname="web01").json()["id"]
    assert next(h for h in client.get("/v1/hosts", headers=RD).json() if h["host_id"] == "h2")["asset_no"] == "V-1"
    client.put(f"/v1/assets/{aid}", json={"asset_no": "V-2", "kind": "virtual", "hostname": "web01"}, headers=AD)
    assert next(h for h in client.get("/v1/hosts", headers=RD).json() if h["host_id"] == "h2")["asset_no"] == "V-2"
    client.delete(f"/v1/assets/{aid}", headers=AD)
    assert next(h for h in client.get("/v1/hosts", headers=RD).json() if h["host_id"] == "h2")["asset_no"] is None


def test_csv_export_and_formula_injection_guard(client):
    seed_hosts(client)
    add(client, asset_no="=cmd|' /C calc'!A0", serial="SN-ESX01", note="+evil")
    r = client.get("/v1/assets", params={"format": "csv"}, headers=RD)
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    text = r.content.decode("utf-8-sig")
    assert text.splitlines()[0].startswith("asset_no,kind,status")
    assert "'=cmd" in text and "'+evil" in text                         # 수식으로 해석되지 않게 접두 처리
    assert "esx01" in text and "web01" in text


def test_nul_in_url_or_query_does_not_500(client):
    assert client.get("/v1/assets", params={"q": "a\x00b"}, headers=RD).status_code in (200, 400, 422)
    assert client.get("/v1/assets/%00", headers=RD).status_code in (400, 404, 422)


def test_overview_carries_the_asset_summary(client):
    seed_hosts(client)
    add(client, asset_no="P-1", serial="SN-ESX01")
    add(client, asset_no="X-9", hostname="ghost")
    o = client.get("/v1/overview", headers=RD).json()
    assert o["assets"]["assets"] == 2 and o["assets"]["uncollected"] == 1 and o["assets"]["unregistered"] == 2
    assert all("asset_no" in e for e in o["recent_events"])


def test_repo_enforces_case_insensitive_asset_no_uniqueness_on_its_own(repo):
    """API 가 먼저 막더라도 저장소 제약이 마지막 방어선이다(동시 요청 사이의 경쟁)."""
    from swinventory.server.repo.base import ConflictError

    base = {"kind": "physical", "serial": "", "hostname": "", "domain": "", "ip": "", "parent_asset_id": None, "host_id": None, "note": ""}
    repo.create_asset({**base, "asset_no": "ABC-1"}, "2026-11-05T00:00:00.000000Z")
    with pytest.raises(ConflictError):
        repo.create_asset({**base, "asset_no": "abc-1"}, "2026-11-05T00:00:00.000000Z")
    repo.create_asset({**base, "asset_no": "ABC-2"}, "2026-11-05T00:00:00.000000Z")      # 롤백 뒤에도 정상 동작
    assert len(repo.list_assets()) == 2
