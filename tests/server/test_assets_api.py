"""자산 대장(웹에서 관리) + 수집 호스트 연결 + 기존 목록에 붙는 자산 열 + 장비 정보 적재."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text

from swinventory.server.app import ApiSettings, create_app
from swinventory.server.timeutil import normalize_ts
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
    assert a["primary_owner"] == a["secondary_owner"] == ""
    put = client.put(f"/v1/assets/{a['id']}", json={"asset_no": "A-1", "kind": "virtual", "note": "VM 으로 전환"}, headers=AD)
    assert put.status_code == 200 and put.json()["kind"] == "virtual" and put.json()["serial"] == ""     # PUT 은 전체 교체
    assert client.delete(f"/v1/assets/{a['id']}", headers=AD).status_code == 200
    assert client.get(f"/v1/assets/{a['id']}", headers=RD).status_code == 404
    assert client.delete(f"/v1/assets/{a['id']}", headers=AD).status_code == 404
    assert client.put(f"/v1/assets/{a['id']}", json={"asset_no": "A-1", "kind": "physical"}, headers=AD).status_code == 404


def test_asset_owners_are_persisted_full_replacement_fields_and_can_be_entered_without_accounts(client):
    created = add(client, asset_no="OWNERS-1", primary_owner="홍길동", secondary_owner="담당팀 infra").json()
    assert created["primary_owner"] == "홍길동" and created["secondary_owner"] == "담당팀 infra"
    assert client.get("/v1/assets", headers=RD).json()[0]["asset"]["primary_owner"] == "홍길동"
    assert client.get(f"/v1/assets/{created['id']}", headers=RD).json()["asset"]["secondary_owner"] == "담당팀 infra"

    updated = client.put(f"/v1/assets/{created['id']}", headers=AD, json={
        "asset_no": "OWNERS-1", "kind": "physical", "primary_owner": "새 정 담당자", "secondary_owner": "새 부 담당자",
    })
    assert updated.status_code == 200
    assert updated.json()["primary_owner"] == "새 정 담당자" and updated.json()["secondary_owner"] == "새 부 담당자"

    # PUT 은 기존 전체 교체 계약이다. 필드를 생략하면 빈 값으로 지운다.
    cleared = client.put(f"/v1/assets/{created['id']}", headers=AD, json={"asset_no": "OWNERS-1", "kind": "physical"})
    assert cleared.status_code == 200 and cleared.json()["primary_owner"] == cleared.json()["secondary_owner"] == ""


@pytest.mark.parametrize("field", ["primary_owner", "secondary_owner"])
def test_asset_owner_is_length_limited_and_control_characters_are_sanitized(client, field):
    too_long = add(client, asset_no=f"LONG-{field}", **{field: "x" * 129})
    assert too_long.status_code == 422
    at_limit = add(client, asset_no=f"LIMIT-{field}", **{field: "x" * 128})
    assert at_limit.status_code == 201 and at_limit.json()[field] == "x" * 128
    created = add(client, asset_no=f"CLEAN-{field}", **{field: "홍\x00길동"})
    assert created.status_code == 201 and created.json()[field] == "홍길동"


def test_either_asset_owner_can_be_set_without_the_other(client):
    created = add(client, asset_no="ONE-SIDED", primary_owner="담당자는 계정이 없어도 된다").json()
    assert created["primary_owner"] == "담당자는 계정이 없어도 된다" and created["secondary_owner"] == ""


def test_asset_owner_updates_do_not_get_overwritten_by_agent_recollection_and_appear_in_host_detail(client):
    seed_hosts(client)
    asset = add(client, asset_no="OWNER-WEB", serial="VM-WEB01", primary_owner="주 담당자",
                secondary_owner="부 담당자").json()
    detail = client.get("/v1/hosts/h2", headers=RD).json()
    assert detail["asset"]["asset_id"] == asset["id"]
    assert detail["asset"]["primary_owner"] == "주 담당자"
    assert detail["asset"]["secondary_owner"] == "부 담당자"

    # 에이전트는 자산 메타데이터를 갱신하지 않으므로 재수집 후에도 관리자가 적은 값이 유지된다.
    push(client, make_snapshot(host_id="h2", hostname="web01", at=T0.replace(hour=3),
                               hardware=hw("virtual", "VM-WEB01", "web01.corp.example.com", "vmware")))
    after = client.get("/v1/hosts/h2", headers=RD).json()["asset"]
    assert after["primary_owner"] == "주 담당자" and after["secondary_owner"] == "부 담당자"
    assert client.get("/v1/hosts/h1", headers=RD).json()["asset"]["primary_owner"] == ""
    assert client.get("/v1/hosts/h1", headers=RD).json()["asset"]["secondary_owner"] == ""


def test_asset_owner_search_and_csv_export(client):
    add(client, asset_no="OWNER-SEARCH", primary_owner="정주인_742", secondary_owner="부주인_518", note="warehouse")
    assert [row["asset"]["asset_no"] for row in rows(client, q="정주인_742")] == ["OWNER-SEARCH"]
    assert [row["asset"]["asset_no"] for row in rows(client, q="부주인_518")] == ["OWNER-SEARCH"]

    response = client.get("/v1/assets", params={"q": "부주인_518", "format": "csv"}, headers=RD)
    text = response.content.decode("utf-8-sig")
    assert "primary_owner" in text.splitlines()[0] and "secondary_owner" in text.splitlines()[0]
    assert "정주인_742" in text and "부주인_518" in text


def test_asset_revision_rejects_a_stale_full_form_update(client):
    created = add(client, asset_no="REV-1", note="기존 값").json()
    assert created["revision"] == 1
    current = client.put(f"/v1/assets/{created['id']}", headers=AD, json={
        "asset_no": "REV-1", "kind": "physical", "note": "다른 담당자가 바꿈", "expected_revision": 1})
    assert current.status_code == 200 and current.json()["revision"] == 2
    stale = client.put(f"/v1/assets/{created['id']}", headers=AD, json={
        "asset_no": "REV-1", "kind": "physical", "note": "오래된 폼 값", "expected_revision": 1})
    assert stale.status_code == 409
    latest = client.get(f"/v1/assets/{created['id']}", headers=RD).json()
    assert latest["asset"]["note"] == "다른 담당자가 바꿈" and latest["asset"]["revision"] == 2


def test_registered_asset_card_scope_matches_its_summary_count(client):
    seed_hosts(client)
    add(client, asset_no="REG-1", serial="SN-ESX01")
    add(client, asset_no="REG-2", hostname="ghost")
    summary = client.get("/v1/assets/summary", headers=RD).json()
    registered = rows(client, status="registered")
    assert len(registered) == summary["assets"] == 2
    assert all(row["asset"] is not None for row in registered)


def test_existing_asset_table_gets_revision_without_losing_rows(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy-assets.db'}")
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE assets (
            id INTEGER PRIMARY KEY, asset_no VARCHAR(64) NOT NULL, asset_no_key VARCHAR(64) NOT NULL,
            kind VARCHAR(16) NOT NULL, serial VARCHAR(128) NOT NULL, hostname VARCHAR(255) NOT NULL,
            domain VARCHAR(255) NOT NULL, ip VARCHAR(45) NOT NULL, parent_asset_id INTEGER,
            host_id VARCHAR(128), note VARCHAR(500) NOT NULL, created_at VARCHAR(32) NOT NULL,
            updated_at VARCHAR(32) NOT NULL)"""))
        conn.execute(text("""INSERT INTO assets (id, asset_no, asset_no_key, kind, serial, hostname, domain, ip,
            parent_asset_id, host_id, note, created_at, updated_at)
            VALUES (1, 'LEGACY-1', 'legacy-1', 'virtual', '', 'vm1', '', '', NULL, NULL, '유지',
                    '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')"""))
    from swinventory.server.repo.sql import SqlInventoryRepository
    repo = SqlInventoryRepository(engine)
    assert "revision" in {column["name"] for column in inspect(engine).get_columns("assets")}
    assert {"primary_owner", "secondary_owner"} <= {column["name"] for column in inspect(engine).get_columns("assets")}
    row = repo.get_asset(1)
    assert row["asset_no"] == "LEGACY-1" and row["note"] == "유지" and row["revision"] == 1
    assert row["primary_owner"] == row["secondary_owner"] == ""
    values = {k: row[k] for k in ("asset_no", "kind", "serial", "hostname", "domain", "ip", "parent_asset_id", "host_id", "note")}
    values.update(primary_owner="레거시 후속 담당", secondary_owner="레거시 백업")
    assert repo.update_asset(1, values, "2026-11-05T01:00:00.000000Z")
    # 같은 DB를 두 번째로 열어도 migration 은 반복 안전하고 값은 보존된다.
    repo = SqlInventoryRepository(engine)
    migrated = repo.get_asset(1)
    assert migrated["primary_owner"] == "레거시 후속 담당" and migrated["secondary_owner"] == "레거시 백업"
    engine.dispose()


def test_postgresql_existing_assets_get_owner_columns_repeatably_without_losing_rows():
    """PG 레거시 컬럼 마이그레이션을 격리 schema 에서 검증한다. 운영/public schema 는 건드리지 않는다."""
    import os
    from uuid import uuid4

    url = os.environ.get("SWINV_TEST_DB_URL", "")
    if not url.startswith("postgresql"):
        pytest.skip("SWINV_TEST_DB_URL PostgreSQL 이 설정되지 않았다")

    from sqlalchemy.engine import make_url
    from swinventory.server.repo.sql import SqlInventoryRepository

    schema_name = f"test_asset_owner_{uuid4().hex}"
    admin_engine = create_engine(url)
    isolated_engine = None
    try:
        with admin_engine.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA "{schema_name}"'))
        isolated_url = make_url(url)
        connect_options = dict(isolated_url.query)
        connect_options["options"] = f"-csearch_path={schema_name}"
        isolated_engine = create_engine(isolated_url.set(query=connect_options))
        with isolated_engine.begin() as conn:
            conn.execute(text("""CREATE TABLE assets (
                id INTEGER PRIMARY KEY, asset_no VARCHAR(64) NOT NULL, asset_no_key VARCHAR(64) NOT NULL,
                kind VARCHAR(16) NOT NULL, serial VARCHAR(128) NOT NULL, hostname VARCHAR(255) NOT NULL,
                domain VARCHAR(255) NOT NULL, ip VARCHAR(45) NOT NULL, parent_asset_id INTEGER,
                host_id VARCHAR(128), note VARCHAR(500) NOT NULL, created_at VARCHAR(32) NOT NULL,
                updated_at VARCHAR(32) NOT NULL)"""))
            conn.execute(text("""INSERT INTO assets (id, asset_no, asset_no_key, kind, serial, hostname, domain, ip,
                parent_asset_id, host_id, note, created_at, updated_at)
                VALUES (1, 'PG-LEGACY-1', 'pg-legacy-1', 'physical', '', 'pg-host', '', '', NULL, NULL, '보존',
                        '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')"""))

        repo = SqlInventoryRepository(isolated_engine)
        row = repo.get_asset(1)
        assert row["note"] == "보존" and row["revision"] == 1
        assert row["primary_owner"] == row["secondary_owner"] == ""
        values = {key: row[key] for key in (
            "asset_no", "kind", "serial", "hostname", "domain", "ip", "parent_asset_id", "host_id", "note",
        )}
        values.update(primary_owner="PG 정 담당", secondary_owner="PG 부 담당")
        assert repo.update_asset(1, values, "2026-11-05T01:00:00.000000Z")

        repo = SqlInventoryRepository(isolated_engine)
        migrated = repo.get_asset(1)
        assert migrated["primary_owner"] == "PG 정 담당" and migrated["secondary_owner"] == "PG 부 담당"
        assert {column["name"] for column in inspect(isolated_engine).get_columns("assets")} >= {
            "revision", "primary_owner", "secondary_owner",
        }
    finally:
        if isolated_engine is not None:
            isolated_engine.dispose()
        with admin_engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
        admin_engine.dispose()


def test_software_collector_freshness_keeps_last_success_across_failure(client):
    push(client, make_snapshot(host_id="fresh-1", packages=[dpkg("openssl", "3.0.2")]))
    first = client.get("/v1/hosts/fresh-1", headers=RD).json()
    status = next(r for r in first["source_freshness"] if r["source"] == "software.dpkg")
    assert status["state"] == "ok" and status["last_success_at"] == normalize_ts(T0)

    failed_at = T0.replace(hour=1)
    push(client, make_snapshot(host_id="fresh-1", at=failed_at, packages=[], collected=["os", "kernel"],
                               errors={"software.dpkg": "package manager unavailable"}))
    failed = client.get("/v1/hosts/fresh-1", headers=RD).json()
    status = next(r for r in failed["source_freshness"] if r["source"] == "software.dpkg")
    assert status["state"] == "failed" and status["last_success_at"] == normalize_ts(T0)
    assert status["last_attempt_at"] == normalize_ts(failed_at) and "unavailable" in status["last_error"]
    assert [(p["name"], p["version"]) for p in failed["packages"]] == [("openssl", "3.0.2")]

    recovered_at = T0.replace(hour=2)
    push(client, make_snapshot(host_id="fresh-1", at=recovered_at, packages=[dpkg("openssl", "3.0.2")]))
    recovered = client.get("/v1/hosts/fresh-1", headers=RD).json()
    status = next(r for r in recovered["source_freshness"] if r["source"] == "software.dpkg")
    assert status["state"] == "ok" and status["last_success_at"] == normalize_ts(recovered_at) and status["last_error"] == ""


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
    add(client, asset_no="=cmd|' /C calc'!A0", serial="SN-ESX01", note="+evil", primary_owner="=SUM(1,2)")
    r = client.get("/v1/assets", params={"format": "csv"}, headers=RD)
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    text = r.content.decode("utf-8-sig")
    assert text.splitlines()[0].startswith("asset_no,kind,status")
    assert "'=cmd" in text and "'+evil" in text                         # 수식으로 해석되지 않게 접두 처리
    assert "'=SUM" in text
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
