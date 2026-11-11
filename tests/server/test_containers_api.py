"""컨테이너·쿠버네티스 노드 수집, 이미지 변경 이벤트, 클러스터 묶기, 목록 API. 노드는 기존 호스트이므로 자산 열도 그대로 붙는다."""
import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from tests.server.conftest import T0, ctr, dpkg, hw, k8s, make_snapshot

ING, RD, AD = {"Authorization": "Bearer ing-tok"}, {"Authorization": "Bearer read-tok"}, {"Authorization": "Bearer adm-tok"}
CA, CB = "a" * 64, "b" * 64


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


def events(client, host=None, type=None):
    return get(client, "/v1/events", **({"host": host} if host else {}), **({"type": type} if type else {}))


def seed(client):
    """클러스터 A(노드 2대), 클러스터 B(노드 1대), 클러스터를 못 알아낸 노드 1대, 일반 도커 서버 1대, 컨테이너 없는 호스트 1대."""
    push(client, make_snapshot(host_id="n1", hostname="k8s-a1", containers=[
        ctr("web", "nginx:1.25", pod="web-1", namespace="prod"), ctr("web", "nginx:1.25", pod="web-2", namespace="prod", cid="web2web2web2"),
        ctr("coredns", "registry.k8s.io/coredns/coredns:v1.11", pod="coredns-x", namespace="kube-system"),
        ctr("job", "busybox:1.36", pod="job-1", namespace="prod", state="exited")], k8s=k8s(CA)))
    push(client, make_snapshot(host_id="n2", hostname="k8s-a2", containers=[ctr("web", "nginx:1.26", pod="web-3", namespace="prod")], k8s=k8s(CA, version="v1.29.4")))
    push(client, make_snapshot(host_id="n3", hostname="k8s-b1", containers=[ctr("api", "team/api:2.0", pod="api-1", namespace="dev")], k8s=k8s(CB, api="https://10.9.0.1:6443")))
    push(client, make_snapshot(host_id="n4", hostname="k8s-x1", containers=[ctr("misc", "redis:7", pod="misc-1", namespace="default")], k8s=k8s("", "", "v1.28.0")))
    push(client, make_snapshot(host_id="d1", hostname="docker01", containers=[ctr("db", "postgres:16", runtime="docker"), ctr("web", "nginx:1.25", runtime="docker")]))
    push(client, make_snapshot(host_id="p1", hostname="plain01"))


# --- 적재 ---
def test_containers_and_node_identity_are_stored_and_returned_in_host_detail(client):
    seed(client)
    d = get(client, "/v1/hosts/n1")
    assert d["k8s"] == {"cluster_id": CA, "api_server": "https://10.0.0.1:6443", "version": "v1.29.3", "runtime": "containerd"}
    assert {(c["name"], c["pod"], c["namespace"], c["state"]) for c in d["containers"]} == {
        ("web", "web-1", "prod", "running"), ("web", "web-2", "prod", "running"), ("coredns", "coredns-x", "kube-system", "running"), ("job", "job-1", "prod", "exited")}
    assert get(client, "/v1/hosts/p1")["containers"] == [] and get(client, "/v1/hosts/p1")["k8s"] is None


def test_every_ingest_replaces_the_container_set_and_a_failed_collector_keeps_the_previous_one(client, clock):
    push(client, make_snapshot(host_id="n1", hostname="a", containers=[ctr("web", "nginx:1.25"), ctr("db", "postgres:16")], k8s=k8s(CA)))
    push(client, make_snapshot(host_id="n1", hostname="a", at=T0.replace(hour=1), containers=[ctr("web", "nginx:1.25")], k8s=k8s(CA)))
    assert [c["name"] for c in get(client, "/v1/hosts/n1")["containers"]] == ["web"]
    push(client, make_snapshot(host_id="n1", hostname="a", at=T0.replace(hour=2), errors={"containers": "헬퍼 결과가 오래됐다"}))      # containers 수집 실패
    assert [c["name"] for c in get(client, "/v1/hosts/n1")["containers"]] == ["web"] and get(client, "/v1/hosts/n1")["k8s"]["cluster_id"] == CA
    push(client, make_snapshot(host_id="n1", hostname="a", at=T0.replace(hour=3)))                                                    # 헬퍼 없는 옛 에이전트: 건드리지 않는다
    assert [c["name"] for c in get(client, "/v1/hosts/n1")["containers"]] == ["web"]


def test_node_that_stops_being_a_k8s_node_loses_its_k8s_record(client):
    push(client, make_snapshot(host_id="n1", hostname="a", containers=[ctr("web")], k8s=k8s(CA)))
    push(client, make_snapshot(host_id="n1", hostname="a", at=T0.replace(hour=1), containers=[ctr("web")]))
    assert get(client, "/v1/hosts/n1")["k8s"] is None and get(client, "/v1/k8s/clusters") == []


def test_input_is_sanitized_not_rejected(client):
    body = make_snapshot(host_id="n1", hostname="a", containers=[ctr("web")], k8s=k8s(CA)).to_dict()
    body["containers"] = [
        {"runtime": "containerd", "container_id": "abc123", "name": "ok\x00", "image": "Nginx:1.25", "state": "weird", "pod": "p", "namespace": "ns", "labels": {"x": "y"}},
        {"container_id": "", "name": "no-id", "image": "x:1"}, "not-a-dict", {"container_id": "z", "name": "", "image": "x"}, {"container_id": "z2", "name": "n", "image": ""},
    ]
    body["k8s"] = {"cluster_id": "not-hex", "api_server": "https://admin:pw@10.0.0.1:6443", "version": "v1.29.3\x00", "runtime": "x" * 500, "extra": 1}
    assert client.post("/v1/ingest", json=body, headers=ING).status_code == 200
    d = get(client, "/v1/hosts/n1")
    assert [(c["name"], c["state"]) for c in d["containers"]] == [("ok", "unknown")]
    assert d["k8s"]["cluster_id"] == "" and d["k8s"]["api_server"] == "" and "\x00" not in d["k8s"]["version"] and len(d["k8s"]["runtime"]) <= 32


def test_more_than_5000_containers_are_capped_without_failing_the_host(client):
    body = make_snapshot(host_id="n1", hostname="a", containers=[ctr("web")]).to_dict()
    body["containers"] = [{"container_id": f"{i:012x}", "name": f"c{i}", "image": "x:1", "state": "running"} for i in range(5100)]
    assert client.post("/v1/ingest", json=body, headers=ING).status_code == 200
    assert len(get(client, "/v1/hosts/n1")["containers"]) == 5000


def test_deleting_a_host_removes_its_containers_and_k8s_membership(client):
    seed(client)
    assert client.delete("/v1/hosts/n3", headers=AD).status_code == 200
    assert all(c["hostname"] != "k8s-b1" for c in get(client, "/v1/containers"))
    assert CB not in {c["cluster_id"] for c in get(client, "/v1/k8s/clusters")}


# --- 이미지 변경 이벤트 ---
def test_first_containers_are_a_baseline_without_events(client):
    seed(client)
    assert not [e for e in events(client) if e["event_type"].startswith("container_image")]


def test_image_tag_change_new_image_and_removed_image_become_events(client):
    push(client, make_snapshot(host_id="n1", hostname="a", containers=[ctr("web", "nginx:1.25", pod="web-1", namespace="prod"), ctr("db", "postgres:16", pod="db-1", namespace="prod")], k8s=k8s(CA)))
    push(client, make_snapshot(host_id="n1", hostname="a", at=T0.replace(hour=1), containers=[
        ctr("web", "nginx:1.26", pod="web-9", namespace="prod"), ctr("cache", "redis:7", pod="cache-1", namespace="prod")], k8s=k8s(CA)))
    ev = {(e["event_type"], e["subject_key"]): (e["old_value"], e["new_value"]) for e in events(client, "n1") if e["event_type"].startswith("container_image")}
    assert ev == {("container_image_changed", "nginx"): ("1.25", "1.26"), ("container_image_added", "redis"): (None, "7"), ("container_image_removed", "postgres"): ("16", None)}


def test_pod_churn_with_the_same_images_makes_no_events(client):
    """롤링 업데이트가 아니라 재시작이면 파드 이름·컨테이너 ID 만 바뀐다 — 이미지가 그대로면 변경 이력이 쏟아지면 안 된다."""
    push(client, make_snapshot(host_id="n1", hostname="a", containers=[ctr("web", "nginx:1.25", pod="web-1", namespace="prod", cid="aaaaaaaaaaaa")], k8s=k8s(CA)))
    push(client, make_snapshot(host_id="n1", hostname="a", at=T0.replace(hour=1), containers=[ctr("web", "nginx:1.25", pod="web-7", namespace="prod", cid="bbbbbbbbbbbb")], k8s=k8s(CA)))
    assert not [e for e in events(client, "n1") if e["event_type"].startswith("container_image")]


def test_exited_containers_do_not_count_as_a_running_image(client):
    push(client, make_snapshot(host_id="d1", hostname="a", containers=[ctr("web", "nginx:1.25", runtime="docker")]))
    push(client, make_snapshot(host_id="d1", hostname="a", at=T0.replace(hour=1), containers=[ctr("web", "nginx:1.25", runtime="docker", state="exited")]))
    ev = [e for e in events(client, "d1") if e["event_type"].startswith("container_image")]
    assert [(e["event_type"], e["subject_key"]) for e in ev] == [("container_image_removed", "nginx")]


def test_containers_that_arrive_after_a_failed_first_collection_are_a_baseline(client):
    push(client, make_snapshot(host_id="n1", hostname="a", errors={"containers": "x"}))
    push(client, make_snapshot(host_id="n1", hostname="a", at=T0.replace(hour=1), containers=[ctr("web", "nginx:1.25")]))
    assert not [e for e in events(client, "n1") if e["event_type"].startswith("container_image")]


# --- 컨테이너 목록 ---
def test_containers_list_filters_and_asset_columns(client):
    seed(client)
    client.post("/v1/assets", json={"asset_no": "SRV-9", "kind": "physical", "hostname": "k8s-a1"}, headers=AD)
    rows = get(client, "/v1/containers")
    assert len(rows) == 9
    web = [r for r in rows if r["hostname"] == "k8s-a1" and r["name"] == "web"]
    assert {r["asset_no"] for r in web} == {"SRV-9"} and all(r["cluster_id"] == CA for r in web)
    assert {r["hostname"] for r in get(client, "/v1/containers", namespace="prod")} == {"k8s-a1", "k8s-a2"}
    assert {r["image"] for r in get(client, "/v1/containers", image="nginx")} == {"nginx:1.25", "nginx:1.26"}
    assert {r["state"] for r in get(client, "/v1/containers", active="true")} == {"running"}
    assert all(r["runtime"] == "docker" for r in get(client, "/v1/containers", runtime="docker"))
    assert {r["hostname"] for r in get(client, "/v1/containers", cluster=CB)} == {"k8s-b1"}
    assert {r["hostname"] for r in get(client, "/v1/containers", q="coredns")} == {"k8s-a1"}
    assert client.get("/v1/containers", params={"state": "bogus"}, headers=RD).status_code == 422


def test_containers_csv_neutralizes_formulas(client):
    push(client, make_snapshot(host_id="d1", hostname="a", containers=[ctr("=cmd|' /C calc'!A0", "x:1", runtime="docker")]))
    r = client.get("/v1/containers", params={"format": "csv"}, headers=RD)
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"] and "'=cmd" in r.content.decode("utf-8-sig")


# --- 이미지 ---
def test_image_distribution_counts_hosts_and_containers_per_tag(client):
    seed(client)
    imgs = {i["repo"]: i for i in get(client, "/v1/images")}
    nginx = imgs["nginx"]
    assert (nginx["host_count"], nginx["container_count"], nginx["tag_count"]) == (3, 4, 2)
    assert {t["tag"]: (t["host_count"], t["container_count"]) for t in nginx["tags"]} == {"1.25": (2, 3), "1.26": (1, 1)}
    assert "busybox" not in imgs                                                    # 종료된 컨테이너의 이미지는 기본 목록에서 제외
    assert "busybox" in {i["repo"] for i in get(client, "/v1/images", active="false")}
    d = get(client, "/v1/images/registry.k8s.io/coredns/coredns")                    # 경로에 '/' 가 있는 저장소
    assert d["repo"] == "registry.k8s.io/coredns/coredns" and [c["hostname"] for c in d["containers"]] == ["k8s-a1"]
    assert client.get("/v1/images/nope", headers=RD).status_code == 404


# --- 클러스터 ---
def test_nodes_are_grouped_into_clusters_by_ca_hash(client):
    seed(client)
    cl = {c["cluster_id"]: c for c in get(client, "/v1/k8s/clusters")}
    assert set(cl) == {CA, CB, ""}
    a = cl[CA]
    assert (a["node_count"], a["pod_count"], a["namespace_count"], a["container_count"]) == (2, 4, 2, 4) and a["versions"] == ["v1.29.3", "v1.29.4"]
    assert sorted(n["hostname"] for n in a["nodes"]) == ["k8s-a1", "k8s-a2"] and a["api_servers"] == ["https://10.0.0.1:6443"]
    assert cl[CB]["node_count"] == 1 and cl[""]["name"] == "(클러스터 미확인)"
    assert "d1" not in {n["host_id"] for c in cl.values() for n in c["nodes"]}      # 일반 도커 서버는 노드가 아니다


def test_cluster_detail_has_nodes_namespaces_and_images(client):
    seed(client)
    d = get(client, f"/v1/k8s/clusters/{CA}")
    assert {n["hostname"]: n["container_count"] for n in d["nodes"]} == {"k8s-a1": 3, "k8s-a2": 1}                # 종료된 컨테이너는 센 값에서 제외
    ns = {n["namespace"]: (n["pod_count"], n["container_count"]) for n in d["namespaces"]}
    assert ns == {"prod": (3, 3), "kube-system": (1, 1)}
    assert {i["repo"] for i in d["images"]} == {"nginx", "registry.k8s.io/coredns/coredns"}
    assert get(client, "/v1/k8s/clusters/unknown")["cluster_id"] == "" and client.get("/v1/k8s/clusters/" + "f" * 64, headers=RD).status_code == 404


def test_cluster_names_are_set_by_admins_only(client):
    seed(client)
    assert client.put(f"/v1/k8s/clusters/{CA}/name", json={"name": "운영"}, headers=RD).status_code == 403
    assert client.put(f"/v1/k8s/clusters/{CA}/name", json={"name": "운영\x00 클러스터"}, headers=AD).status_code == 200
    assert {c["cluster_id"]: c["name"] for c in get(client, "/v1/k8s/clusters")}[CA] == "운영 클러스터"
    assert client.put(f"/v1/k8s/clusters/{CA}/name", json={"name": "x" * 65}, headers=AD).status_code == 422
    assert client.put("/v1/k8s/clusters/" + "f" * 64 + "/name", json={"name": "x"}, headers=AD).status_code == 404
    assert client.put(f"/v1/k8s/clusters/{CA}/name", json={"name": ""}, headers=AD).status_code == 200            # 비우면 기본 이름으로
    assert {c["cluster_id"]: c["name"] for c in get(client, "/v1/k8s/clusters")}[CA].startswith("aaaaaaaa")


def test_read_endpoints_need_a_read_token(client):
    for path in ("/v1/containers", "/v1/images", "/v1/k8s/clusters"):
        assert client.get(path).status_code == 401 and client.get(path, headers=ING).status_code == 403
        assert client.get(path, headers=RD).status_code == 200


# --- 개요 ---
def test_overview_has_container_and_cluster_counts(client):
    seed(client)
    o = get(client, "/v1/overview")["containers"]
    assert (o["cluster_count"], o["node_count"], o["running_container_count"]) == (3, 4, 8)


def test_a_pod_with_a_sidecar_counts_once_as_a_pod_and_twice_as_containers(client):
    push(client, make_snapshot(host_id="n1", hostname="a", k8s=k8s(CA), containers=[
        ctr("app", "team/app:1", pod="app-1", namespace="prod", cid="aaaaaaaaaaaa"), ctr("istio-proxy", "istio/proxyv2:1.20", pod="app-1", namespace="prod", cid="bbbbbbbbbbbb")]))
    c = get(client, "/v1/k8s/clusters")[0]
    assert (c["pod_count"], c["container_count"]) == (1, 2)
    assert get(client, f"/v1/k8s/clusters/{CA}")["namespaces"] == [{"namespace": "prod", "pod_count": 1, "container_count": 2}]
    assert get(client, f"/v1/k8s/clusters/{CA}")["nodes"][0]["pod_count"] == 1
