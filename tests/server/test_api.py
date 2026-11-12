from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from tests.server.conftest import T0, dpkg, make_snapshot, rpm

ING, RD, AD = {"Authorization": "Bearer ing-tok"}, {"Authorization": "Bearer read-tok"}, {"Authorization": "Bearer adm-tok"}


@pytest.fixture
def client(repo, clock):
    settings = ApiSettings(ingest_tokens=("ing-tok",), read_tokens=("read-tok",), admin_tokens=("adm-tok",))
    return TestClient(create_app(repo, settings, clock=clock))


def push(client, snap, headers=ING):
    return client.post("/v1/ingest", json=snap.to_dict(), headers=headers)


def seed(client):
    push(client, make_snapshot(host_id="a", hostname="web01", kernel="5.15-91",
                               installed=["5.15-91", "5.15-100"], reboot=True,
                               packages=[dpkg("openssl", "3.0.2"), dpkg("bash", "5.1")]))
    push(client, make_snapshot(host_id="b", hostname="web02", kernel="5.15-100",
                               packages=[dpkg("openssl", "3.0.13")]))
    push(client, make_snapshot(host_id="c", hostname="db01", kernel="5.15-100",
                               packages=[], collected=["os", "kernel"], errors={"software.dpkg": "x"}))


def test_auth_matrix(client):
    snap = make_snapshot().to_dict()
    assert client.post("/v1/ingest", json=snap).status_code == 401
    assert client.post("/v1/ingest", json=snap, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/v1/ingest", json=snap, headers=RD).status_code == 403
    assert client.get("/v1/hosts", headers=ING).status_code == 403
    assert client.get("/v1/hosts").status_code == 401
    assert client.get("/v1/hosts", headers=RD).status_code == 200
    assert client.get("/v1/hosts", headers=AD).status_code == 200
    assert client.put("/v1/hosts/h1/tags", json={"team": "x"}, headers=RD).status_code == 403


def test_ingest_response_and_validation(client):
    r = push(client, make_snapshot())
    assert r.status_code == 200 and r.json() == {"status": "baseline", "event_count": 0}
    bad = make_snapshot().to_dict()
    bad["collected_at"] = "not-a-date"
    assert client.post("/v1/ingest", json=bad, headers=ING).status_code == 422
    assert client.post("/v1/ingest", json={"host_id": "x"}, headers=ING).status_code == 422


def test_hosts_and_host_detail(client):
    seed(client)
    hosts = client.get("/v1/hosts", headers=RD).json()
    assert {h["host_id"] for h in hosts} == {"a", "b", "c"}
    d = client.get("/v1/hosts/a", headers=RD).json()
    assert d["kernel"]["reboot_required"] is True
    assert [p["name"] for p in d["packages"]] == ["bash", "openssl"]
    assert client.get("/v1/hosts/zzz", headers=RD).status_code == 404


def test_kernel_distribution_and_hosts(client):
    seed(client)
    dist = {k["version"]: k["host_count"] for k in client.get("/v1/kernels", headers=RD).json()}
    assert dist == {"5.15-91": 1, "5.15-100": 2}
    rows = client.get("/v1/kernels/hosts", params={"reboot_required": "true"}, headers=RD).json()
    assert [(r["host_id"], r["running"], r["latest_installed"]) for r in rows] == [("a", "5.15-91", "5.15-100")]
    rows = client.get("/v1/kernels/hosts", params={"running": "5.15-100"}, headers=RD).json()
    assert {r["host_id"] for r in rows} == {"b", "c"}


def test_software_search_and_detail(client):
    seed(client)
    found = client.get("/v1/software", params={"q": "SSL"}, headers=RD).json()
    assert [(f["name"], f["host_count"], f["version_count"]) for f in found] == [("openssl", 2, 2)]
    assert client.get("/v1/software", params={"q": "%"}, headers=RD).json() == []  # 와일드카드 이스케이프
    d = client.get("/v1/software/openssl", headers=RD).json()
    assert {v["version"]: v["host_count"] for v in d["versions"]} == {"3.0.2": 1, "3.0.13": 1}
    assert {(h["host_id"], h["version"]) for h in d["hosts"]} == {("a", "3.0.2"), ("b", "3.0.13")}


def test_events_filters(client, clock):
    seed(client)
    push(client, make_snapshot(host_id="a", at=T0 + timedelta(hours=1), kernel="5.15-100",
                               packages=[dpkg("openssl", "3.0.13")]))
    ev = client.get("/v1/events", headers=RD).json()
    assert {e["event_type"] for e in ev} == {"package_removed", "package_version_changed", "kernel_changed"}
    only = client.get("/v1/events", params={"type": "kernel_changed", "host": "a"}, headers=RD).json()
    assert [(e["old_value"], e["new_value"], e["hostname"]) for e in only] == [("5.15-91", "5.15-100", "web01")]
    future = (T0 + timedelta(days=1)).isoformat()
    assert client.get("/v1/events", params={"since": future}, headers=RD).json() == []


def test_overview(client, clock):
    seed(client)
    clock.advance(hours=1)
    o = client.get("/v1/overview", headers=RD).json()
    assert o["host_count"] == 3
    assert o["healthy_count"] == 2          # c 는 마지막 수집에 오류
    assert o["healthy_rate"] == pytest.approx(2 / 3)
    assert o["reboot_required_count"] == 1
    assert (o["stale_count"], o["error_count"]) == (0, 1)
    assert {k["version"]: k["host_count"] for k in o["kernel_distribution"]} == {"5.15-91": 1, "5.15-100": 2}
    clock.advance(hours=100)  # 수집이 끊기면 정상률에서 빠진다
    o = client.get("/v1/overview", headers=RD).json()
    assert (o["healthy_count"], o["stale_count"], o["error_count"]) == (0, 3, 0)


def test_tags_roundtrip_and_filter(client):
    seed(client)
    r = client.put("/v1/hosts/a/tags", json={"team": "infra", "env": "prod"}, headers=AD)
    assert r.status_code == 200
    assert client.get("/v1/hosts/a", headers=RD).json()["tags"] == {"team": "infra", "env": "prod"}
    client.put("/v1/hosts/a/tags", json={"team": "infra"}, headers=AD)  # 전체 교체
    assert client.get("/v1/hosts/a", headers=RD).json()["tags"] == {"team": "infra"}
    assert client.put("/v1/hosts/zzz/tags", json={}, headers=AD).status_code == 404
    rows = client.get("/v1/kernels/hosts", headers=RD).json()
    assert next(r for r in rows if r["host_id"] == "a")["tags"] == {"team": "infra"}


def test_rpm_multi_version_visible_in_software_detail(client):
    push(client, make_snapshot(host_id="r", sources=("rpm",), kernel="5.14-362",
                               installed=["5.14-362", "5.14-427"], reboot=True,
                               packages=[rpm("kernel-core", "5.14-362"), rpm("kernel-core", "5.14-427")]))
    d = client.get("/v1/software/kernel-core", headers=RD).json()
    assert {v["version"] for v in d["versions"]} == {"5.14-362", "5.14-427"}


def test_software_server_summary_and_detail_scope(client):
    seed(client)
    response = client.get('/v1/software-hosts', params={'q': 'open', 'host': 'a'}, headers=RD)
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1 and rows[0]['host_id'] == 'a' and rows[0]['package_count'] == 1
    assert client.get('/v1/software-hosts', params={'host': 'missing'}, headers=RD).json() == []
    assert client.get('/v1/software-hosts', params={'q': '%'}, headers=RD).json() == []
    detail = client.get('/v1/software/openssl', params={'host': 'b'}, headers=RD).json()
    assert detail['hosts'] and {row['host_id'] for row in detail['hosts']} == {'b'}
    assert detail['versions'] == [{'version': '3.0.13', 'host_count': 1}]
    exported = client.get('/v1/software/openssl', params={'host': 'b', 'format': 'csv'}, headers=RD).text
    assert 'web02' in exported and 'web01' not in exported


def test_software_summary_keeps_duplicate_server_names_and_multiple_versions(client):
    for host in ('a', 'b'):
        assert push(client, make_snapshot(host_id=host, hostname='same-name', sources=('rpm', 'dpkg'), packages=[
            rpm('kernel-core', '1.0'), rpm('kernel-core', '2.0'), dpkg('bash', '5.1')])).status_code == 200
    rows = client.get('/v1/software-hosts', params={'q': 'kernel'}, headers=RD).json()
    assert {r['host_id'] for r in rows} == {'a', 'b'}
    assert len(rows) == 2 and all(r['package_count'] == 2 for r in rows)
    assert all('packages' not in r for r in rows)
    scoped = client.get('/v1/software/kernel-core', params={'host': 'b', 'below': '2.0'}, headers=RD).json()
    assert [r['version'] for r in scoped['hosts']] == ['1.0']
    assert {r['host_id'] for r in scoped['hosts']} == {'b'}
    assert scoped['versions'] == [{'version': '2.0', 'host_count': 1}, {'version': '1.0', 'host_count': 1}]
