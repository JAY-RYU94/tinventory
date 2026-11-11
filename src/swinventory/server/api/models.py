"""수신(ingest) 계약. 이 모델에서 contracts/snapshot.v1.schema.json 이 생성된다."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

from swinventory.common.hardware import clean_serial, domain_of
from swinventory.common.models import Snapshot
from swinventory.server.timeutil import normalize_ts


# NUL 은 PostgreSQL 텍스트 컬럼에 저장할 수 없고(적재가 500 으로 실패 → 에이전트가 같은 스냅샷을 영원히 재전송),
# 그 밖의 제어문자도 화면·CSV·AI 프롬프트에서 위험하다. 거부(422)하면 패키지명 하나가 호스트 전체의 수집을 막으므로
# 제거하고 받는다. 탭·개행·CR 은 오류 메시지에 쓰이므로 유지한다.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def has_control(text: str) -> bool:
    return bool(_CONTROL.search(text))


def strip_controls(value: Any) -> Any:
    if isinstance(value, str):
        return _CONTROL.sub("", value)
    if isinstance(value, list):
        return [strip_controls(v) for v in value]
    if isinstance(value, dict):
        return {strip_controls(k): strip_controls(v) for k, v in value.items()}
    return value


class _Sanitized(BaseModel):
    @field_validator("*", mode="before")  # 길이·필수 검증보다 먼저 — "\x00" 하나뿐인 값이 빈 문자열로 통과하지 않게
    @classmethod
    def _strip(cls, value: Any) -> Any:
        return strip_controls(value)


class PackageIn(_Sanitized):
    source: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=512)
    version: str = Field(default="", max_length=256)
    arch: str = Field(default="", max_length=32)


class OsIn(_Sanitized):
    family: str = Field(max_length=32)
    name: str = Field(max_length=255)
    version: str = Field(max_length=64)


class KernelIn(_Sanitized):
    running: str = Field(min_length=1, max_length=128)
    installed: list[str] = Field(max_length=256)
    reboot_required: bool


_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _clean_interfaces(raw: Any) -> Any:
    """잘못된 항목 하나가 호스트의 커널·소프트웨어 수집까지 막지 않도록, 형식이 틀린 값은 고치거나 버리고 받는다."""
    if not isinstance(raw, list):
        return raw
    out = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"] or len(item["name"]) > 64:
            continue
        mac = str(item.get("mac") or "").lower().replace("-", ":")
        addrs = []
        for a in item.get("addresses") or []:
            try:
                addrs.append(str(ipaddress.ip_interface(a)))
            except (ValueError, TypeError):
                continue
        out.append({"name": item["name"], "mac": mac if _MAC.match(mac) else "",
                    "state": item.get("state") if item.get("state") in ("up", "down", "unknown") else "unknown",
                    "addresses": sorted(set(addrs))[:256]})
    return out


def _clean_ports(raw: Any) -> Any:
    if not isinstance(raw, list):
        return raw
    out = []
    for item in raw:
        if not isinstance(item, dict) or item.get("proto") not in ("tcp", "udp"):
            continue
        port, bind = item.get("port"), item.get("bind")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            continue
        if bind == "*":
            bind = "0.0.0.0"
        try:
            ip = ipaddress.ip_address(bind)
        except (ValueError, TypeError):
            continue
        out.append({"proto": item["proto"], "port": port, "bind": str(getattr(ip, "ipv4_mapped", None) or ip)})   # IPv4 에는 ipv4_mapped 가 없다
    return out


_HARDWARE_KINDS = ("physical", "virtual", "container", "unknown")
_HARDWARE_MAX = {"virt": 64, "vendor": 255, "model": 255, "serial": 128, "fqdn": 255, "domain": 255}


def _clean_hardware(raw: Any) -> Any:
    """장비 정보는 부가 정보다 — 값 하나가 이상해도 호스트의 커널·소프트웨어 수집을 막지 않게 고치거나 비우고 받는다."""
    if not isinstance(raw, dict):
        return None
    out: dict[str, str] = {}
    for key, limit in _HARDWARE_MAX.items():
        value = raw.get(key)
        out[key] = value.strip()[:limit] if isinstance(value, str) else ""
    out["kind"] = raw.get("kind") if raw.get("kind") in _HARDWARE_KINDS else "unknown"
    out["serial"] = clean_serial(out["serial"])
    out["domain"] = out["domain"].lower() or domain_of(out["fqdn"])
    return out


class HardwareIn(_Sanitized):
    kind: str = Field(default="unknown", max_length=16, description="physical | virtual | container | unknown")
    virt: str = Field(default="", max_length=64, description="하이퍼바이저·컨테이너 이름(vmware, kvm, hyperv, docker …)")
    vendor: str = Field(default="", max_length=255)
    model: str = Field(default="", max_length=255)
    serial: str = Field(default="", max_length=128, description="root 가 아니면 읽지 못해 비어 있을 수 있다")
    fqdn: str = Field(default="", max_length=255)
    domain: str = Field(default="", max_length=255)


_CONTAINER_STATES = ("running", "exited", "created", "paused", "unknown")
_CONTAINER_MAX = {"runtime": 32, "container_id": 64, "name": 255, "image": 512, "image_id": 80, "image_digest": 80, "created_at": 32, "pod": 255, "namespace": 255}
MAX_CONTAINERS = 5000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _clean_containers(raw: Any) -> Any:
    """컨테이너 한 건이 이상해도 호스트의 커널·소프트웨어 수집까지 막지 않도록 고치거나 버리고 받는다. 알 수 없는 필드(라벨 등)는 무시한다."""
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        row = {k: (item.get(k).strip()[:limit] if isinstance(item.get(k), str) else "") for k, limit in _CONTAINER_MAX.items()}
        if not (row["container_id"] and row["name"] and row["image"]):
            continue
        row["state"] = item.get("state") if item.get("state") in _CONTAINER_STATES else "unknown"
        out.append(row)
        if len(out) >= MAX_CONTAINERS:
            break
    return out


def _clean_k8s(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return None
    def text(key: str, limit: int) -> str:
        v = raw.get(key)
        return v.strip()[:limit] if isinstance(v, str) else ""
    cluster = text("cluster_id", 64).lower()
    api = text("api_server", 255)
    out = {"cluster_id": cluster if _HEX64.match(cluster) else "", "api_server": "" if "@" in api else api,
           "version": text("version", 64), "runtime": text("runtime", 32)}
    return out if any(out.values()) else None


class ContainerIn(_Sanitized):
    runtime: str = Field(default="", max_length=32)
    container_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    image: str = Field(min_length=1, max_length=512)
    image_id: str = Field(default="", max_length=80)
    image_digest: str = Field(default="", max_length=80)
    state: str = Field(default="unknown", max_length=16, description="running | exited | created | paused | unknown")
    created_at: str = Field(default="", max_length=32)
    pod: str = Field(default="", max_length=255, description="쿠버네티스 파드(노드의 CRI 라벨에서)")
    namespace: str = Field(default="", max_length=255)


class K8sIn(_Sanitized):
    cluster_id: str = Field(default="", max_length=64, description="클러스터 CA 인증서 SHA-256(소문자 hex 64자). 비면 클러스터 미확인")
    api_server: str = Field(default="", max_length=255, description="표시용. 자격증명이 섞인 주소는 버린다")
    version: str = Field(default="", max_length=64)
    runtime: str = Field(default="", max_length=32)


class InterfaceIn(_Sanitized):
    name: str = Field(min_length=1, max_length=64)
    mac: str = Field(default="", max_length=17)
    state: str = Field(default="unknown", max_length=16)
    addresses: list[str] = Field(default_factory=list, max_length=256)


class PortIn(_Sanitized):
    proto: str = Field(max_length=8)
    port: int = Field(ge=1, le=65535)
    bind: str = Field(max_length=64)


class IngestSnapshot(_Sanitized):
    """미지의 필드는 무시한다 — 새 에이전트가 먼저 배포돼도 서버가 깨지지 않게."""

    host_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    collected_at: str = Field(description="ISO-8601. 타임존이 없으면 UTC 로 간주")
    agent_version: str = Field(max_length=32)
    os: OsIn | None = None
    kernel: KernelIn | None = None
    packages: list[PackageIn] = Field(default_factory=list, max_length=100_000)
    interfaces: list[InterfaceIn] = Field(default_factory=list, max_length=256, description="네트워크 인터페이스(전역 주소만). 수집기 network.interfaces")
    ports: list[PortIn] = Field(default_factory=list, max_length=20_000, description="리슨 중인 포트. 수집기 network.ports")
    hardware: HardwareIn | None = Field(default=None, description="장비 정보(VM/물리·제조사·시리얼·FQDN). 수집기 hardware")
    containers: list[ContainerIn] = Field(default_factory=list, max_length=MAX_CONTAINERS, description="컨테이너(노드의 CRI·Docker). 수집기 containers")
    k8s: K8sIn | None = Field(default=None, description="이 호스트가 쿠버네티스 노드일 때의 식별 정보")
    collected: list[str] = Field(default_factory=list, description="성공한 수집기 이름")
    errors: dict[str, str] = Field(default_factory=dict, description="실패한 수집기 이름 → 사유")

    @field_validator("interfaces", mode="before")
    @classmethod
    def _interfaces(cls, v: Any) -> Any:
        return _clean_interfaces(strip_controls(v))

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, v: Any) -> Any:
        return _clean_ports(strip_controls(v))

    @field_validator("hardware", mode="before")
    @classmethod
    def _hardware(cls, v: Any) -> Any:
        return _clean_hardware(strip_controls(v))

    @field_validator("containers", mode="before")
    @classmethod
    def _containers(cls, v: Any) -> Any:
        return _clean_containers(strip_controls(v))

    @field_validator("k8s", mode="before")
    @classmethod
    def _k8s(cls, v: Any) -> Any:
        return _clean_k8s(strip_controls(v))

    @field_validator("collected_at")
    @classmethod
    def _valid_ts(cls, v: str) -> str:
        normalize_ts(v)  # 형식 오류면 ValueError → 422
        return v

    def to_snapshot(self) -> Snapshot:
        return Snapshot.from_dict(self.model_dump())
