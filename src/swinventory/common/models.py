"""agent·server 가 공유하는 전송/도메인 모델. 표준 라이브러리만 사용한다."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class PackageRecord:
    """설치 항목 1건.

    같은 (source, name, arch) 가 여러 버전으로 동시 설치될 수 있다(rpm kernel-core 등).
    그래서 식별자(identity)와 인스턴스 키(버전 포함)를 구분한다.
    """

    source: str
    name: str
    version: str
    arch: str = ""

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.source, self.name, self.arch)

    @property
    def instance_key(self) -> tuple[str, str, str, str]:
        return (*self.identity, self.version)

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "name": self.name, "version": self.version, "arch": self.arch}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PackageRecord":
        return cls(source=d["source"], name=d["name"], version=d["version"], arch=d.get("arch", ""))


@dataclass(frozen=True)
class OsInfo:
    family: str  # debian | rhel | windows
    name: str
    version: str

    def to_dict(self) -> dict[str, str]:
        return {"family": self.family, "name": self.name, "version": self.version}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OsInfo":
        return cls(family=d["family"], name=d["name"], version=d["version"])


@dataclass(frozen=True)
class KernelInfo:
    running: str
    installed: tuple[str, ...]
    reboot_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {"running": self.running, "installed": list(self.installed),
                "reboot_required": self.reboot_required}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "KernelInfo":
        return cls(running=d["running"], installed=tuple(d["installed"]),
                   reboot_required=bool(d["reboot_required"]))


@dataclass(frozen=True)
class NetworkInterface:
    """네트워크 인터페이스 1개. addresses 는 CIDR 문자열(10.0.0.5/24, 2001:db8::5/64)이며 전역 주소만 담는다."""

    name: str
    mac: str = ""
    state: str = "unknown"  # up | down | unknown
    addresses: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "mac": self.mac, "state": self.state, "addresses": list(self.addresses)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NetworkInterface":
        return cls(name=d["name"], mac=d.get("mac", ""), state=d.get("state", "unknown"),
                   addresses=tuple(d.get("addresses", ())))


@dataclass(frozen=True)
class ListeningPort:
    """열려 있는(리슨 중인) 포트 1개 = (프로토콜, 포트, 바인딩 주소). 같은 포트가 IPv4/IPv6 로 각각 열릴 수 있다."""

    proto: str  # tcp | udp
    port: int
    bind: str   # 0.0.0.0, ::, 127.0.0.1, 10.0.0.5 ...

    def to_dict(self) -> dict[str, Any]:
        return {"proto": self.proto, "port": self.port, "bind": self.bind}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ListeningPort":
        return cls(proto=d["proto"], port=int(d["port"]), bind=d["bind"])


@dataclass(frozen=True)
class HardwareInfo:
    """장비 정보. kind: physical | virtual | container | unknown(판정 근거 없음 — 추측하지 않는다).

    serial 은 Linux 에서 root 만 읽을 수 있는 경우가 많아 비어 있을 수 있다(자산 대장의 값으로 보완한다).
    domain 은 FQDN 에서 호스트 이름을 뺀 부분이며 Windows 워크그룹명은 도메인이 아니다.
    """

    kind: str = "unknown"
    virt: str = ""          # 하이퍼바이저/컨테이너 이름(vmware, kvm, hyperv, docker …). 물리면 빈 값
    vendor: str = ""
    model: str = ""
    serial: str = ""
    fqdn: str = ""
    domain: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "virt": self.virt, "vendor": self.vendor, "model": self.model,
                "serial": self.serial, "fqdn": self.fqdn, "domain": self.domain}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HardwareInfo":
        return cls(**{k: str(d.get(k) or "") for k in ("kind", "virt", "vendor", "model", "serial", "fqdn", "domain")})


@dataclass(frozen=True)
class ContainerRecord:
    """컨테이너 1개. 라벨·환경변수·마운트·명령줄은 담지 않는다(비밀이 들어 있을 수 있다) — 파드 이름·네임스페이스만 꺼낸다.

    image 는 정규화된 참조(docker.io/ 제거, 태그 없으면 :latest). state: running | exited | created | paused | unknown.
    """

    runtime: str            # containerd | cri-o | docker
    container_id: str       # 12자
    name: str
    image: str
    image_id: str = ""
    image_digest: str = ""
    state: str = "unknown"
    created_at: str = ""
    pod: str = ""           # 쿠버네티스 파드(노드의 CRI 라벨에서)
    namespace: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"runtime": self.runtime, "container_id": self.container_id, "name": self.name, "image": self.image,
                "image_id": self.image_id, "image_digest": self.image_digest, "state": self.state,
                "created_at": self.created_at, "pod": self.pod, "namespace": self.namespace}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ContainerRecord":
        return cls(**{k: str(d.get(k) or "") for k in ("runtime", "container_id", "name", "image", "image_id", "image_digest", "state", "created_at", "pod", "namespace")})


@dataclass(frozen=True)
class K8sNodeInfo:
    """이 호스트가 쿠버네티스 노드일 때의 식별 정보. cluster_id 는 클러스터 CA 인증서 해시(공개 정보, 모든 노드가 같음) —
    API 주소는 k3s 처럼 루프백일 수 있어 클러스터를 구분하는 키가 못 된다(표시용)."""

    cluster_id: str = ""
    api_server: str = ""
    version: str = ""
    runtime: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"cluster_id": self.cluster_id, "api_server": self.api_server, "version": self.version, "runtime": self.runtime}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "K8sNodeInfo":
        return cls(**{k: str(d.get(k) or "") for k in ("cluster_id", "api_server", "version", "runtime")})


@dataclass
class Snapshot:
    """한 회차 수집 결과.

    collected: 성공한 수집기 이름. 서버는 이 source 만 동기화한다(실패 source 는 건드리지 않음).
    errors: 실패한 수집기 이름 → 사유.
    """

    host_id: str
    hostname: str
    collected_at: str  # ISO-8601, UTC
    agent_version: str
    os: OsInfo | None = None
    kernel: KernelInfo | None = None
    packages: list[PackageRecord] = field(default_factory=list)
    interfaces: list[NetworkInterface] = field(default_factory=list)
    ports: list[ListeningPort] = field(default_factory=list)
    hardware: HardwareInfo | None = None
    containers: list[ContainerRecord] = field(default_factory=list)
    k8s: K8sNodeInfo | None = None
    collected: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "hostname": self.hostname,
            "collected_at": self.collected_at,
            "agent_version": self.agent_version,
            "os": self.os.to_dict() if self.os else None,
            "kernel": self.kernel.to_dict() if self.kernel else None,
            "packages": [p.to_dict() for p in self.packages],
            "interfaces": [i.to_dict() for i in self.interfaces],
            "ports": [p.to_dict() for p in self.ports],
            "hardware": self.hardware.to_dict() if self.hardware else None,
            "containers": [c.to_dict() for c in self.containers],
            "k8s": self.k8s.to_dict() if self.k8s else None,
            "collected": list(self.collected),
            "errors": dict(self.errors),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Snapshot":
        return cls(
            host_id=d["host_id"],
            hostname=d["hostname"],
            collected_at=d["collected_at"],
            agent_version=d["agent_version"],
            os=OsInfo.from_dict(d["os"]) if d.get("os") else None,
            kernel=KernelInfo.from_dict(d["kernel"]) if d.get("kernel") else None,
            packages=[PackageRecord.from_dict(p) for p in d.get("packages", [])],
            interfaces=[NetworkInterface.from_dict(i) for i in d.get("interfaces", [])],
            ports=[ListeningPort.from_dict(p) for p in d.get("ports", [])],
            hardware=HardwareInfo.from_dict(d["hardware"]) if d.get("hardware") else None,
            containers=[ContainerRecord.from_dict(c) for c in d.get("containers", [])],
            k8s=K8sNodeInfo.from_dict(d["k8s"]) if d.get("k8s") else None,
            collected=list(d.get("collected", [])),
            errors=dict(d.get("errors", {})),
        )


def group_versions(packages: Iterable[PackageRecord]) -> dict[tuple[str, str, str], frozenset[str]]:
    """identity → 설치된 버전 집합. diff 의 비교 단위."""
    grouped: dict[tuple[str, str, str], set[str]] = {}
    for p in packages:
        grouped.setdefault(p.identity, set()).add(p.version)
    return {k: frozenset(v) for k, v in grouped.items()}
