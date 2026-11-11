"""컨테이너·이미지·쿠버네티스 클러스터 조회 API. 노드는 기존 호스트이므로 자산 열(자산번호·구분)이 그대로 붙는다."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator

from swinventory.common.hardware import clean_text
from swinventory.server import containerview as V
from swinventory.server.api.csvutil import csv_response
from swinventory.server.api.models import strip_controls
from swinventory.server.api.params import FORMAT
from swinventory.server.assets import AssetService
from swinventory.server.repo.base import InventoryRepository
from swinventory.server.timeutil import normalize_ts

NAMES_KEY = "k8s_cluster_names"
_STATE = Query(None, pattern="^(running|exited|created|paused|unknown)$")


class ClusterNameIn(BaseModel):
    name: str = Field(max_length=64, description="비우면 기본 이름(CA 해시 앞 8자 + API 주소)으로 돌아간다")

    @field_validator("name", mode="before")
    @classmethod
    def _clean(cls, v: Any) -> Any:
        return clean_text(strip_controls(v)) if isinstance(v, str) else v


def build_router(repo: InventoryRepository, assets: AssetService, require_read: Callable[..., None],
                 require_admin: Callable[..., None], clock: Callable[[], datetime]) -> APIRouter:
    router = APIRouter(prefix="/v1")
    read = [Depends(require_read)]

    def names() -> dict[str, str]:
        raw = repo.get_setting(NAMES_KEY)
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            return {}
        return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}

    def cluster_key(value: str) -> str:
        return "" if value == "unknown" else value

    @router.get("/containers", dependencies=read, response_model=None)
    def list_containers(q: str | None = Query(None, max_length=200), state: str | None = _STATE, active: bool | None = None,
                        namespace: str | None = Query(None, max_length=255), cluster: str | None = Query(None, max_length=64),
                        host: str | None = Query(None, max_length=128), image: str | None = Query(None, max_length=200),
                        runtime: str | None = Query(None, max_length=32), fmt: str = FORMAT) -> Response | list[dict]:
        rows = V.attach_clusters(repo.list_containers(), repo.list_k8s_nodes())
        needle, img = (q or "").strip().lower(), (image or "").strip().lower()
        want_cluster = None if cluster is None else cluster_key(cluster)
        rows = [r for r in rows
                if (state is None or r["state"] == state) and (not active or V.is_active(r))
                and (namespace is None or r["namespace"] == namespace) and (want_cluster is None or r["cluster_id"] == want_cluster)
                and (host is None or r["host_id"] == host) and (runtime is None or r["runtime"] == runtime)
                and (not img or img in r["image"].lower())
                and (not needle or needle in f"{r['name']} {r['image']} {r['pod']} {r['namespace']} {r['hostname']}".lower())]
        assets.annotate(rows)
        if fmt == "csv":
            return csv_response(rows, ["hostname", "host_id", "asset_no", "kind", "cluster_id", "runtime", "namespace", "pod", "name",
                                       "image", "image_digest", "state", "created_at"], "containers.csv")
        return rows

    @router.get("/images", dependencies=read)
    def images(active: bool = True, q: str | None = Query(None, max_length=200)) -> list[dict]:
        needle = (q or "").strip().lower()
        return [i for i in V.image_distribution(repo.list_containers(), active_only=active) if not needle or needle in i["repo"]]

    @router.get("/images/{repo_name:path}", dependencies=read)
    def image_detail(repo_name: str, active: bool = True,
                     cluster: str | None = Query(None, max_length=64, description="클러스터 ID(미확인 클러스터는 unknown) — 그 클러스터 노드의 컨테이너만")) -> dict:
        rows = V.attach_clusters(repo.list_containers(), repo.list_k8s_nodes())
        want_cluster = None if cluster is None else cluster_key(cluster)   # 도커 서버(노드가 아님)의 cluster_id 는 None 이라 어느 클러스터에도 속하지 않는다
        mine = [r for r in rows if V.image_key(r)[0] == repo_name and (not active or V.is_active(r))
                and (want_cluster is None or r["cluster_id"] == want_cluster)]
        if not mine:
            raise HTTPException(404, "image not found")
        dist = V.image_distribution(mine, active_only=False)[0]
        return {**dist, "containers": assets.annotate(mine)}

    @router.get("/k8s/clusters", dependencies=read)
    def list_clusters() -> list[dict]:
        nodes = repo.list_k8s_nodes()
        out = V.clusters(nodes, repo.list_containers(), names())
        book = assets.book()
        for c in out:
            assets.annotate(c["nodes"], book)
        return out

    @router.get("/k8s/clusters/{cluster_id}", dependencies=read)
    def cluster_detail(cluster_id: str) -> dict:
        cid = cluster_key(cluster_id)
        nodes, rows = repo.list_k8s_nodes(), repo.list_containers()
        found = next((c for c in V.clusters(nodes, rows, names()) if c["cluster_id"] == cid), None)
        if found is None:
            raise HTTPException(404, "cluster not found")
        members = {n["host_id"] for n in found["nodes"]}
        mine = V.attach_clusters([r for r in rows if r["host_id"] in members], nodes)
        assets.annotate(found["nodes"])
        return {**found, "namespaces": V.namespaces(mine), "images": V.image_distribution(mine), "containers": assets.annotate(mine)}

    @router.put("/k8s/clusters/{cluster_id}/name", dependencies=[Depends(require_admin)])
    def set_cluster_name(cluster_id: str, body: ClusterNameIn) -> dict:
        cid = cluster_key(cluster_id)
        if not any(n["cluster_id"] == cid for n in repo.list_k8s_nodes()):
            raise HTTPException(404, "cluster not found")
        current = names()
        if body.name:
            current[cid] = body.name
        else:
            current.pop(cid, None)
        repo.set_setting(NAMES_KEY, json.dumps(current, ensure_ascii=False, sort_keys=True), normalize_ts(clock()))
        return {"cluster_id": cid, "name": body.name}

    return router
