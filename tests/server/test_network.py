"""IP·MAC 와 열린 포트: 저장·diff·이력·조회·노출 판정."""
import csv
import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from swinventory.common.models import ListeningPort, NetworkInterface
from swinventory.server.app import ApiSettings, create_app
from swinventory.server.diff import NetworkDiffer
from swinventory.server.domain import EventType
from tests.server.conftest import T0, dpkg, iface, make_snapshot, port

ING, RD, AD = ({"Authorization": f"Bearer {t}"} for t in ("ing", "rd", "adm"))


def types(repo, host="h1"):
    return sorted(e["event_type"] for e in repo.list_events(host_id=host, limit=1000))


# --- diff ---------------------------------------------------------------

def kinds(events):
    return sorted((e.event_type.value, e.subject_key, e.old_value, e.new_value) for e in events)


def test_ip_added_removed_and_prefix_change_is_not_an_event():
    prev = [iface("eth0", addresses=("10.0.0.5/24", "10.0.0.6/24"))]
    curr = [iface("eth0", addresses=("10.0.0.5/16", "10.0.0.7/24"))]       # .5 는 접두사만 변경, .6 제거, .7 추가
    assert kinds(NetworkDiffer().diff_interfaces(prev, curr)) == [
        ("ip_added", "10.0.0.7", None, "10.0.0.7/24"), ("ip_removed", "10.0.0.6", "10.0.0.6/24", None)]


def test_ip_moving_between_interfaces_is_not_an_event_but_mac_change_is():
    prev = [iface("eth0", "aa:aa:aa:aa:aa:01", ("10.0.0.5/24",)), iface("eth1", "aa:aa:aa:aa:aa:02", ())]
    curr = [iface("eth0", "aa:aa:aa:aa:aa:01", ()), iface("eth1", "aa:aa:aa:aa:aa:09", ("10.0.0.5/24",))]
    assert kinds(NetworkDiffer().diff_interfaces(prev, curr)) == [("mac_changed", "eth1", "aa:aa:aa:aa:aa:02", "aa:aa:aa:aa:aa:09")]


def test_mac_change_ignored_when_either_side_has_no_mac_and_new_interface_is_not_a_mac_change():
    assert NetworkDiffer().diff_interfaces([iface("wg0", "", ())], [iface("wg0", "aa:aa:aa:aa:aa:01", ())]) == []
    assert NetworkDiffer().diff_interfaces([], [iface("eth9", "aa:aa:aa:aa:aa:01", ())]) == []


def test_port_opened_closed_by_proto_port_bind():
    prev = [port("tcp", 22), port("tcp", 22, "::"), port("tcp", 5432, "127.0.0.1")]
    curr = [port("tcp", 22), port("tcp", 5432, "0.0.0.0"), port("udp", 123)]          # 5432 는 루프백→전체 바인딩으로 노출이 넓어짐
    ev = NetworkDiffer().diff_ports(prev, curr)
    assert kinds(ev) == [("port_closed", "tcp/22", "::", None), ("port_closed", "tcp/5432", "127.0.0.1", None),
                         ("port_opened", "tcp/5432", None, "0.0.0.0"), ("port_opened", "udp/123", None, "0.0.0.0")]
    assert next(e for e in ev if e.new_value == "0.0.0.0" and e.subject_key == "tcp/5432").detail["exposure"] == "any"


def test_unchanged_network_has_no_events():
    i, p = [iface()], [port("tcp", 22), port("udp", 53, "127.0.0.1")]
    assert NetworkDiffer().diff_interfaces(i, list(i)) == [] and NetworkDiffer().diff_ports(p, list(reversed(p))) == []


# --- 적재 ---------------------------------------------------------------

def test_baseline_stores_network_without_events_and_detail_exposes_it(service, repo):
    res = service.ingest(make_snapshot(interfaces=[iface("eth0", addresses=("10.0.0.5/24", "2001:db8::5/64")), iface("eth1", "", ())],
                                       ports=[port("tcp", 22), port("tcp", 5432, "127.0.0.1")]))
    assert res.status == "baseline" and res.event_count == 0
    d = repo.host_detail("h1")
    assert [(i["name"], i["mac"], i["addresses"]) for i in d["interfaces"]] == [
        ("eth0", "02:42:ac:11:00:02", ["10.0.0.5/24", "2001:db8::5/64"]), ("eth1", "", [])]
    assert [(p["proto"], p["port"], p["bind"]) for p in d["ports"]] == [("tcp", 22, "0.0.0.0"), ("tcp", 5432, "127.0.0.1")]


def test_changes_produce_events_and_replace_state(service, repo):
    service.ingest(make_snapshot(interfaces=[iface(addresses=("10.0.0.5/24",))], ports=[port("tcp", 22), port("tcp", 8080)]))
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=1), interfaces=[iface(addresses=("10.0.0.9/24",))],
                                       ports=[port("tcp", 22), port("tcp", 3306)]))
    assert res.event_count == 4
    assert types(repo) == sorted([EventType.IP_ADDED, EventType.IP_REMOVED, EventType.PORT_OPENED, EventType.PORT_CLOSED])
    d = repo.host_detail("h1")
    assert d["interfaces"][0]["addresses"] == ["10.0.0.9/24"] and [p["port"] for p in d["ports"]] == [22, 3306]


def test_failed_network_collectors_leave_previous_state_and_emit_nothing(service, repo):
    service.ingest(make_snapshot(interfaces=[iface()], ports=[port("tcp", 22)]))
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=1), errors={"network.ports": "boom"}))   # 네트워크 수집기는 이번 회차에 실패/미실행
    assert res.event_count == 0
    d = repo.host_detail("h1")
    assert len(d["interfaces"]) == 1 and len(d["ports"]) == 1


def test_empty_successful_collection_means_everything_closed(service, repo):
    service.ingest(make_snapshot(interfaces=[iface()], ports=[port("tcp", 22)]))
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=1), interfaces=[], ports=[]))
    assert res.event_count == 2 and repo.host_detail("h1")["ports"] == []


def test_network_collected_for_the_first_time_on_an_existing_host_is_baseline(service, repo):
    """에이전트를 업그레이드하면 이미 등록된 호스트에 네트워크 데이터가 처음 도착한다 — '포트 열림' 이벤트 폭주 금지."""
    service.ingest(make_snapshot(packages=[dpkg("bash", "1")]))
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=1), packages=[dpkg("bash", "1")],
                                       interfaces=[iface()], ports=[port("tcp", 22), port("tcp", 80)]))
    assert res.event_count == 0 and len(repo.host_detail("h1")["ports"]) == 2
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=2), packages=[dpkg("bash", "1")],
                                       interfaces=[iface()], ports=[port("tcp", 22)]))
    assert types(repo) == [EventType.PORT_CLOSED]                                     # 그 뒤부터는 정상 diff


def test_interfaces_and_ports_baseline_independently(service, repo):
    service.ingest(make_snapshot(interfaces=[iface()]))                                # ports 는 아직 수집된 적 없음
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=1), interfaces=[iface()], ports=[port("tcp", 22)]))
    assert res.event_count == 0


def test_delete_host_and_prune_remove_network_rows(service, repo):
    service.ingest(make_snapshot(host_id="a", interfaces=[iface()], ports=[port("tcp", 22)]))
    service.ingest(make_snapshot(host_id="b", interfaces=[iface(addresses=("10.0.0.6/24",))], ports=[port("tcp", 22)]))
    assert repo.delete_host("a") is True and repo.list_ips() != [] and {r["host_id"] for r in repo.list_ips()} == {"b"}
    assert {r["host_id"] for r in repo.list_ports()} == {"b"}
    assert repo.prune(hosts_before="9999-12-31T00:00:00.000000Z")["hosts"] == 1
    assert repo.list_ips() == [] and repo.list_ports() == []


# --- 수신 검증 ----------------------------------------------------------

@pytest.fixture
def client(repo, clock):
    return TestClient(create_app(repo, ApiSettings(ingest_tokens=("ing",), read_tokens=("rd",), admin_tokens=("adm",)), clock=clock, env={}))


def push(client, **kw):
    r = client.post("/v1/ingest", json=make_snapshot(**kw).to_dict(), headers=ING)
    assert r.status_code == 200, r.text


def test_invalid_network_entries_are_dropped_not_fatal(client, repo):
    """잘못된 항목 하나가 호스트의 커널·소프트웨어 수집 전체를 막으면 안 된다 — 걸러내고 받는다."""
    body = make_snapshot(interfaces=[iface()], ports=[port("tcp", 22)]).to_dict()
    body["interfaces"] += [{"name": "bad1", "mac": "not-a-mac", "state": "weird", "addresses": ["10.0.0.1/24", "999.1.1.1", "x"]},
                           {"name": "", "mac": "", "addresses": []}, {"mac": "aa"}]
    body["ports"] += [{"proto": "icmp", "port": 1, "bind": "0.0.0.0"}, {"proto": "tcp", "port": 70000, "bind": "0.0.0.0"},
                      {"proto": "tcp", "port": 0, "bind": "0.0.0.0"}, {"proto": "tcp", "port": 80, "bind": "not-an-ip"},
                      {"proto": "tcp", "port": 443, "bind": "::FFFF:10.0.0.1"}, {"proto": "tcp"}]
    assert client.post("/v1/ingest", json=body, headers=ING).status_code == 200
    d = repo.host_detail("h1")
    bad1 = next(i for i in d["interfaces"] if i["name"] == "bad1")
    assert (bad1["mac"], bad1["state"], bad1["addresses"]) == ("", "unknown", ["10.0.0.1/24"])
    assert [i["name"] for i in d["interfaces"]] == ["bad1", "eth0"]
    assert [(p["proto"], p["port"]) for p in d["ports"]] == [("tcp", 22), ("tcp", 443)]


def test_mac_is_normalized_and_control_characters_stripped(client, repo):
    push(client, interfaces=[iface("et\x00h0", "02-42-AC-11-00-02", ("10.0.0.5/24",))], ports=[])
    assert repo.host_detail("h1")["interfaces"][0]["name"] == "eth0"
    assert repo.host_detail("h1")["interfaces"][0]["mac"] == "02:42:ac:11:00:02"


# --- 조회 API -----------------------------------------------------------

def seed(client):
    push(client, host_id="a", hostname="web01", interfaces=[iface("eth0", "aa:00:00:00:00:01", ("10.0.0.5/24", "2001:db8::5/64"))],
         ports=[port("tcp", 22), port("tcp", 22, "::"), port("tcp", 5432, "127.0.0.1"), port("tcp", 23)])
    push(client, host_id="b", hostname="db01", interfaces=[iface("eth0", "aa:00:00:00:00:02", ("10.0.0.6/24",))],
         ports=[port("tcp", 22), port("tcp", 5432, "10.0.0.6"), port("udp", 161)])
    push(client, host_id="c", hostname="dup01", interfaces=[iface("ens3", "aa:00:00:00:00:03", ("10.0.0.5/24",))], ports=[])   # a 와 IP 충돌
    push(client, host_id="d", hostname="old01")                                                                               # 네트워크 수집 없음
    client.put("/v1/hosts/a/tags", json={"team": "infra"}, headers=AD)


def rows(resp):
    return list(csv.DictReader(io.StringIO(resp.content.decode("utf-8-sig"))))


def test_ip_inventory_search_duplicates_and_csv(client):
    seed(client)
    allips = client.get("/v1/network/ips", headers=RD).json()
    assert [(r["ip"], r["hostname"]) for r in allips] == [          # 정렬: IP 체계 → 숫자값 → 호스트명(항상 같은 순서)
        ("10.0.0.5", "dup01"), ("10.0.0.5", "web01"), ("10.0.0.6", "db01"), ("2001:db8::5", "web01")]
    dup = {(r["ip"], r["hostname"]): r["duplicate"] for r in allips}
    assert dup[("10.0.0.5", "web01")] is True and dup[("10.0.0.5", "dup01")] is True and dup[("10.0.0.6", "db01")] is False
    one = client.get("/v1/network/ips", params={"q": "10.0.0.6"}, headers=RD).json()
    assert [(r["ip"], r["mac"], r["interface"], r["family"]) for r in one] == [("10.0.0.6", "aa:00:00:00:00:02", "eth0", 4)]
    assert [r["hostname"] for r in client.get("/v1/network/ips", params={"q": "AA:00:00:00:00:03"}, headers=RD).json()] == ["dup01"]
    assert [r["hostname"] for r in client.get("/v1/network/ips", params={"q": "db0"}, headers=RD).json()] == ["db01"]
    assert [r["hostname"] for r in client.get("/v1/network/ips", params={"tag": "team:infra"}, headers=RD).json()] == ["web01", "web01"]
    csvrows = rows(client.get("/v1/network/ips", params={"format": "csv"}, headers=RD))
    assert {"ip", "cidr", "interface", "mac", "hostname", "duplicate"} <= set(csvrows[0]) and len(csvrows) == 4


def test_same_ip_on_two_interfaces_of_one_host_is_not_a_conflict(client):
    """가상 IP·본딩·컨테이너 브리지로 한 호스트의 여러 인터페이스가 같은 IP 를 가질 수 있다. 충돌은 '다른 호스트'가 쓸 때만이다."""
    push(client, host_id="x", hostname="vip01", interfaces=[iface("eth0", "aa:00:00:00:00:10", ("10.0.0.9/24",)),
                                                            iface("eth1", "aa:00:00:00:00:11", ("10.0.0.9/24",))], ports=[])
    assert client.get("/v1/network/ip-conflicts", headers=RD).json() == []
    assert {r["duplicate"] for r in client.get("/v1/network/ips", headers=RD).json()} == {False}
    assert client.get("/v1/overview", headers=RD).json()["ip_conflict_count"] == 0


def test_ip_conflicts_endpoint(client):
    seed(client)
    c = client.get("/v1/network/ip-conflicts", headers=RD).json()
    assert [(x["ip"], sorted(h["hostname"] for h in x["hosts"])) for x in c] == [("10.0.0.5", ["dup01", "web01"])]


def test_ports_summary_counts_hosts_and_exposure(client):
    seed(client)
    s = {(r["proto"], r["port"]): r for r in client.get("/v1/network/ports", headers=RD).json()}
    assert (s[("tcp", 22)]["host_count"], s[("tcp", 22)]["exposed_count"], s[("tcp", 22)]["service"]) == (2, 2, "ssh")
    assert (s[("tcp", 5432)]["host_count"], s[("tcp", 5432)]["exposed_count"]) == (2, 1)       # a 는 루프백 전용, b 는 특정 주소
    assert s[("tcp", 23)]["notable"] is True and s[("tcp", 22)]["notable"] is False
    assert s[("tcp", 5432)]["notable"] is True                                                 # b 가 비루프백 주소로 DB 포트를 연다
    assert s[("udp", 161)]["notable"] is True
    top = client.get("/v1/network/ports", headers=RD).json()
    assert top[0]["port"] == 22 and top[0]["host_count"] == 2                                  # 호스트 수 많은 순
    only_any = client.get("/v1/network/ports", params={"exposure": "any"}, headers=RD).json()
    assert {(r["proto"], r["port"]) for r in only_any} == {("tcp", 22), ("tcp", 23), ("udp", 161)}


def test_listening_filters_and_csv(client):
    seed(client)
    get = lambda **p: client.get("/v1/network/listening", params=p, headers=RD).json()  # noqa: E731
    assert {r["hostname"] for r in get(port=5432)} == {"web01", "db01"}
    assert [(r["hostname"], r["bind"], r["exposure"]) for r in get(port=5432, exposure="loopback")] == [("web01", "127.0.0.1", "loopback")]
    assert {(r["hostname"], r["bind"]) for r in get(proto="tcp", port=22, exposure="any")} == {("web01", "0.0.0.0"), ("web01", "::"), ("db01", "0.0.0.0")}
    assert {(r["hostname"], r["port"]) for r in get(notable="true")} == {("web01", 23), ("db01", 5432), ("db01", 161)}
    assert {r["hostname"] for r in get(exposure="exposed", tag="team:infra")} == {"web01"}
    assert client.get("/v1/network/listening", params={"exposure": "bogus"}, headers=RD).status_code == 422
    assert client.get("/v1/network/listening", params={"proto": "icmp"}, headers=RD).status_code == 422
    assert client.get("/v1/network/listening", params={"format": "xml"}, headers=RD).status_code == 422
    r = rows(client.get("/v1/network/listening", params={"format": "csv", "port": 23}, headers=RD))
    assert r[0]["service"] == "telnet" and r[0]["notable"] == "true" and r[0]["exposure"] == "any"


def test_host_detail_and_list_include_network(client):
    seed(client)
    d = client.get("/v1/hosts/a", headers=RD).json()
    assert [(p["port"], p["bind"], p["exposure"], p["service"], p["notable"]) for p in d["ports"] if p["port"] in (22, 23, 5432)] == [
        (22, "0.0.0.0", "any", "ssh", False), (22, "::", "any", "ssh", False), (23, "0.0.0.0", "any", "telnet", True),
        (5432, "127.0.0.1", "loopback", "postgresql", False)]
    assert d["interfaces"][0]["addresses"] == ["10.0.0.5/24", "2001:db8::5/64"]
    hosts = {h["host_id"]: h for h in client.get("/v1/hosts", headers=RD).json()}
    assert hosts["a"]["ips"] == ["10.0.0.5", "2001:db8::5"] and hosts["d"]["ips"] == []
    assert [h["host_id"] for h in client.get("/v1/hosts", params={"ip": "10.0.0.6"}, headers=RD).json()] == ["b"]


def test_overview_counts_ip_conflicts_and_hosts_exposing_notable_ports(client):
    seed(client)
    o = client.get("/v1/overview", headers=RD).json()
    assert o["ip_conflict_count"] == 1
    assert o["notable_exposed_host_count"] == 2      # web01(telnet 23), db01(5432 를 특정 주소로, snmp 161)


def test_network_endpoints_require_read_role(client):
    for path in ("/v1/network/ips", "/v1/network/ip-conflicts", "/v1/network/ports", "/v1/network/listening"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers=ING).status_code == 403


def test_server_filter_preserves_global_conflicts_and_csv_scope(client):
    seed(client)
    ips = client.get('/v1/network/ips', params={'host': 'a'}, headers=RD).json()
    assert ips and {row['host_id'] for row in ips} == {'a'}
    assert next(row for row in ips if row['ip'] == '10.0.0.5')['duplicate'] is True
    bindings = client.get('/v1/network/listening', params={'host': 'b'}, headers=RD).json()
    assert bindings and {row['host_id'] for row in bindings} == {'b'}
    summary = client.get('/v1/network/ports', params={'host': 'b'}, headers=RD).json()
    assert summary and all(row['host_count'] == 1 for row in summary)
    assert not any(row['port'] == 23 for row in summary)
    for endpoint in ('ips', 'ports', 'listening'):
        assert client.get(f'/v1/network/{endpoint}', params={'host': 'missing'}, headers=RD).json() == []
    for endpoint in ('ips', 'listening'):
        exported = rows(client.get(f'/v1/network/{endpoint}', params={'host': 'b', 'format': 'csv'}, headers=RD))
        assert exported and {row['host_id'] for row in exported} == {'b'}
