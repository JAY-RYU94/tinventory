"""컨테이너·클러스터 집계(순수 로직, DB·HTTP 비의존).

노드는 '쿠버네티스 노드로 식별된 호스트'다 — 클러스터는 노드의 CA 인증서 해시(cluster_id)로 묶는다. 에이전트가 없는 노드의 파드는 보이지 않는다.
**실행 중(종료되지 않은) 컨테이너만 센다** — 종료된 컨테이너가 이미지 사용 현황을 부풀리지 않게.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable
from urllib.parse import urlparse

from swinventory.common.containers import split_image

UNKNOWN_CLUSTER = "(클러스터 미확인)"


def is_active(row: dict[str, Any]) -> bool:
    return row["state"] != "exited"


def image_key(row: dict[str, Any]) -> tuple[str, str]:
    repo, tag, digest = split_image(row["image"])
    return repo or row["image"], tag or digest[:19]


def attach_clusters(containers: Iterable[dict[str, Any]], nodes: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """컨테이너 행에 cluster_id 를 붙인다(쿠버네티스 노드가 아닌 호스트는 None)."""
    by_host = {n["host_id"]: n["cluster_id"] for n in nodes}
    return [{**c, "cluster_id": by_host.get(c["host_id"])} for c in containers]


def image_distribution(rows: Iterable[dict[str, Any]], active_only: bool = True) -> list[dict[str, Any]]:
    repos: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if active_only and not is_active(r):
            continue
        repo, tag = image_key(r)
        repos[repo][tag].append(r)
    out = []
    for repo, tags in repos.items():
        entries = [{"tag": tag, "host_count": len({r["host_id"] for r in rs}), "container_count": len(rs)} for tag, rs in tags.items()]
        entries.sort(key=lambda t: (-t["host_count"], t["tag"]))
        every = [r for rs in tags.values() for r in rs]
        out.append({"repo": repo, "host_count": len({r["host_id"] for r in every}), "container_count": len(every),
                    "tag_count": len(tags), "tags": entries})
    return sorted(out, key=lambda i: (-i["host_count"], i["repo"]))


def _default_name(cluster_id: str, api_servers: list[str]) -> str:
    if not cluster_id:
        return UNKNOWN_CLUSTER
    host = urlparse(api_servers[0]).hostname if api_servers else ""
    return f"{cluster_id[:8]} ({host})" if host else cluster_id[:8]


def _node_view(node: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    mine = [r for r in rows if r["host_id"] == node["host_id"] and is_active(r)]
    return {**node, "container_count": len(mine), "pod_count": len({(r["namespace"], r["pod"]) for r in mine if r["pod"]})}


def clusters(nodes: list[dict[str, Any]], rows: list[dict[str, Any]], names: dict[str, str]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for n in nodes:
        groups[n["cluster_id"]].append(n)
    out = []
    for cid, members in groups.items():
        host_ids = {n["host_id"] for n in members}
        active = [r for r in rows if r["host_id"] in host_ids and is_active(r)]
        servers = sorted({n["api_server"] for n in members if n["api_server"]})
        out.append({
            "cluster_id": cid, "name": names.get(cid) or _default_name(cid, servers),
            "api_servers": servers, "versions": sorted({n["version"] for n in members if n["version"]}),
            "node_count": len(members), "container_count": len(active),
            "pod_count": len({(r["namespace"], r["pod"]) for r in active if r["pod"]}),
            "namespace_count": len({r["namespace"] for r in active if r["namespace"]}),
            "image_count": len({image_key(r)[0] for r in active}),
            "nodes": [_node_view(n, rows) for n in sorted(members, key=lambda n: n["hostname"])],
        })
    return sorted(out, key=lambda c: (c["cluster_id"] == "", c["name"]))


def namespaces(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ns: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        if is_active(r) and r["pod"]:
            by_ns[r["namespace"]].append(r)
    return [{"namespace": ns, "pod_count": len({r["pod"] for r in rs}), "container_count": len(rs)} for ns, rs in sorted(by_ns.items())]


def summary(nodes: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, int]:
    return {"cluster_count": len({n["cluster_id"] for n in nodes}), "node_count": len(nodes),
            "running_container_count": sum(1 for r in rows if r["state"] == "running"),
            "image_count": len({image_key(r)[0] for r in rows if is_active(r)})}
