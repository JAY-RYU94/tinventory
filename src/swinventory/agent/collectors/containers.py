"""컨테이너·쿠버네티스 노드 수집. **비특권(root 아님)** 에이전트가 root 헬퍼(deploy/agent/containers-helper.sh)가 남긴 원본 파일을 읽어 해석한다.

root 로 도는 코드는 고정 조회 명령만 실행하는 헬퍼뿐이고 JSON 해석은 전부 여기(비특권)에서 한다. 라벨·환경변수는 화이트리스트한 필드만 꺼낸다.
"""
from __future__ import annotations

import json
import re
from abc import ABC
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from swinventory.agent.collectors.base import BaseCollector
from swinventory.agent.runtime.fs import FileReader
from swinventory.common.containers import normalize_image_ref, split_image
from swinventory.common.hardware import clean_text
from swinventory.common.models import ContainerRecord, K8sNodeInfo

HELPER_DIR = "/var/lib/swinventory-helper"
MAX_CONTAINERS = 5000            # 노드 하나가 보고할 수 있는 상한(서버 수신 상한과 같다)
MAX_AGE = timedelta(hours=3)     # 헬퍼 타이머(15분)가 이보다 오래 멈추면 마지막 값을 현재 상태로 믿지 않는다

_CRI_STATE = {"CONTAINER_RUNNING": "running", "CONTAINER_EXITED": "exited", "CONTAINER_CREATED": "created"}
_DOCKER_STATE = {"running": "running", "restarting": "running", "exited": "exited", "dead": "exited", "removing": "exited",
                 "created": "created", "paused": "paused"}
_SHA = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
_VERSION = re.compile(r"v\d+\.\d+\.\d+[^\s]*")
_DOCKER_TS = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4}")


class ContainerCollector(BaseCollector[Any], ABC):
    """optional: 헬퍼가 설치되지 않은 호스트에서는 '적용 대상 아님'(값 None)이며 collected 에도 errors 에도 넣지 않는다."""

    optional = True

    @property
    def name(self) -> str:
        return "containers"


def _iso_from_ns(ns: Any) -> str:
    try:
        return datetime.fromtimestamp(int(ns) // 10**9, timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _iso_from_docker(text: str) -> str:
    m = _DOCKER_TS.match(text or "")
    if not m:
        return ""
    try:
        return datetime.strptime(m.group(0), "%Y-%m-%d %H:%M:%S %z").astimezone(timezone.utc).isoformat()
    except ValueError:
        return ""


def _short(container_id: str) -> str:
    return clean_text(container_id).replace("sha256:", "")[:12]


def parse_crictl(ps_text: str, images_text: str, version_text: str) -> list[ContainerRecord]:
    runtime = ""
    for line in version_text.splitlines():
        if line.strip().startswith("RuntimeName:"):
            runtime = clean_text(line.split(":", 1)[1])
    by_id: dict[str, dict[str, Any]] = {}
    if images_text.strip():
        for im in json.loads(images_text).get("images") or []:
            by_id[im.get("id", "")] = im
    out = []
    for c in json.loads(ps_text).get("containers") or []:
        labels = c.get("labels") or {}
        image = c.get("image") or {}
        image_id = clean_text(c.get("imageRef") or image.get("image") or "")
        known = by_id.get(image_id, {})
        # 최신 containerd 는 image.image 에 sha 를, 읽을 수 있는 참조는 userSpecifiedImage 에 둔다(옛 버전은 반대)
        ref = clean_text(image.get("userSpecifiedImage") or "")
        if not ref:
            ref = clean_text(image.get("image") or "")
        if not ref or _SHA.match(ref):
            tags = known.get("repoTags") or []
            ref = clean_text(tags[0]) if tags else (ref or image_id)
        digest = next((d.split("@", 1)[1] for d in known.get("repoDigests") or [] if "@" in d), "")
        out.append(ContainerRecord(
            runtime=runtime or "containerd", container_id=_short(c.get("id", "")),
            name=clean_text(labels.get("io.kubernetes.container.name") or (c.get("metadata") or {}).get("name") or ""),
            image=ref if _SHA.match(ref) else normalize_image_ref(ref), image_id=image_id, image_digest=clean_text(digest),
            state=_CRI_STATE.get(c.get("state", ""), "unknown"), created_at=_iso_from_ns(c.get("createdAt")),
            pod=clean_text(labels.get("io.kubernetes.pod.name") or ""), namespace=clean_text(labels.get("io.kubernetes.pod.namespace") or "")))
    return out


def parse_docker(ps_text: str, images_text: str) -> list[ContainerRecord]:
    images = [json.loads(line) for line in images_text.splitlines() if line.strip()]
    by_ref = {normalize_image_ref(f"{i.get('repository', '')}:{i.get('tag', '')}"): i for i in images if i.get("repository") not in ("", "<none>")}
    by_id = {i.get("id", ""): i for i in images}
    out = []
    for line in ps_text.splitlines():
        if not line.strip():
            continue
        c = json.loads(line)
        raw = clean_text(c.get("image", ""))
        known = by_id.get(raw if raw.startswith("sha256:") else f"sha256:{raw}") if _SHA.match(raw) else by_ref.get(normalize_image_ref(raw), {})
        ref = raw
        if _SHA.match(raw) and known and known.get("repository") not in (None, "", "<none>"):
            ref = f"{known['repository']}:{known.get('tag', 'latest')}"
        digest = clean_text((known or {}).get("digest", ""))
        out.append(ContainerRecord(
            runtime="docker", container_id=_short(c.get("id", "")), name=clean_text((c.get("name") or "").split(",")[0].lstrip("/")),
            image=ref if _SHA.match(ref) else normalize_image_ref(ref), image_id=clean_text((known or {}).get("id", "")),
            image_digest="" if digest in ("<none>", "") else digest, state=_DOCKER_STATE.get(clean_text(c.get("state", "")).lower(), "unknown"),
            created_at=_iso_from_docker(c.get("created", ""))))
    return out


def parse_k8s(ca: str, server: str, version: str, runtime: str, has_pods: bool) -> K8sNodeInfo | None:
    cluster_id = clean_text(ca).lower() if re.fullmatch(r"[0-9a-fA-F]{64}", clean_text(ca)) else ""
    api = clean_text(server)
    if "@" in api:                       # 자격증명이 섞인 주소는 버린다(표시용 값일 뿐이다)
        api = ""
    m = _VERSION.search(version)
    ver = m.group(0) if m else ""
    if not (cluster_id or api or ver or has_pods):
        return None
    return K8sNodeInfo(cluster_id=cluster_id, api_server=api, version=ver, runtime=runtime)


class HelperContainers(ContainerCollector):
    def __init__(self, fs: FileReader, clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc), helper_dir: str = HELPER_DIR):
        self._fs = fs
        self._clock = clock
        self._dir = helper_dir

    def _read(self, name: str) -> str | None:
        try:
            return self._fs.read_text(f"{self._dir}/{name}")
        except OSError:
            return None

    def _run(self) -> dict[str, str | None] | None:
        stamp = self._read("collected_at.txt")
        if stamp is None:
            return None                                              # 헬퍼 미설치 — 적용 대상 아님
        try:
            collected = datetime.fromtimestamp(int(stamp.strip()), timezone.utc)
        except (ValueError, OverflowError, OSError):
            raise ValueError(f"collected_at.txt 를 해석하지 못했다: {stamp.strip()[:40]!r}") from None
        age = self._clock() - collected
        if age > MAX_AGE:
            raise RuntimeError(f"컨테이너 헬퍼 결과가 {int(age.total_seconds() // 3600)}시간 넘게 오래됐다 — swinventory-containers.timer 를 확인한다")
        names = ("crictl_ps.json", "crictl_images.json", "crictl_version.txt", "docker_ps.jsonl", "docker_images.jsonl",
                 "k8s_ca_sha256.txt", "k8s_server.txt", "k8s_version.txt")
        return {n: self._read(n) for n in names}

    def _parse(self, raw: Any) -> tuple[list[ContainerRecord], K8sNodeInfo | None] | None:
        if raw is None:
            return None
        containers: list[ContainerRecord] = []
        runtime = ""
        if raw["crictl_ps.json"] is not None:
            containers += parse_crictl(raw["crictl_ps.json"], raw["crictl_images.json"] or "", raw["crictl_version.txt"] or "")
            runtime = containers[0].runtime if containers else next(
                (clean_text(l.split(":", 1)[1]) for l in (raw["crictl_version.txt"] or "").splitlines() if l.strip().startswith("RuntimeName:")), "")
        if raw["docker_ps.jsonl"] is not None:
            containers += parse_docker(raw["docker_ps.jsonl"], raw["docker_images.jsonl"] or "")
        containers.sort(key=lambda c: (c.namespace, c.pod, c.name, c.container_id))
        k8s = parse_k8s(raw["k8s_ca_sha256.txt"] or "", raw["k8s_server.txt"] or "", raw["k8s_version.txt"] or "", runtime,
                        any(c.pod for c in containers))
        return containers[:MAX_CONTAINERS], k8s
