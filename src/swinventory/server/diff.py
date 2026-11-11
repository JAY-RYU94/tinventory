"""이전 상태와 현재 상태의 diff. 순수 함수(저장소 비의존)라 단독 테스트할 수 있다."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable

from swinventory.common.containers import split_image
from swinventory.common.models import ContainerRecord, KernelInfo, ListeningPort, NetworkInterface, OsInfo, PackageRecord, group_versions
from swinventory.common.net import bind_exposure, ip_of
from swinventory.common.versioning import version_key
from swinventory.server.domain import ChangeEvent, EventType


class Differ(ABC):
    @abstractmethod
    def diff(self, prev: Any, curr: Any) -> list[ChangeEvent]: ...


class PackageDiffer(Differ):
    """(source, name, arch) 별 버전 집합으로 비교한다.

    - 양쪽 모두 버전이 정확히 1개이고 다르면 version_changed.
    - 그 외(다중 버전 공존 포함)는 차집합만 installed/removed. kernel-core 처럼 여러 버전이
      동시에 설치되는 패키지가 수집 순서만 바뀌어도 가짜 version_changed 를 만들지 않는다.
    """

    def diff(self, prev: Iterable[PackageRecord], curr: Iterable[PackageRecord]) -> list[ChangeEvent]:
        before, after = group_versions(prev), group_versions(curr)
        events: list[ChangeEvent] = []
        for ident in sorted(set(before) | set(after)):
            old, new = before.get(ident, frozenset()), after.get(ident, frozenset())
            if old == new:
                continue
            source, name, arch = ident
            detail = {"source": source, "arch": arch}
            if len(old) == 1 and len(new) == 1:
                events.append(ChangeEvent(EventType.PACKAGE_VERSION_CHANGED, "package", name,
                                          next(iter(old)), next(iter(new)), detail))
                continue
            for v in sorted(old - new, key=version_key):
                events.append(ChangeEvent(EventType.PACKAGE_REMOVED, "package", name, v, None, detail))
            for v in sorted(new - old, key=version_key):
                events.append(ChangeEvent(EventType.PACKAGE_INSTALLED, "package", name, None, v, detail))
        return events


class KernelDiffer(Differ):
    """prev 는 이전에 실행 중이던 커널(없으면 None=기준선)."""

    def diff(self, prev: str | None, curr: KernelInfo) -> list[ChangeEvent]:
        if prev is None or prev == curr.running:
            return []
        return [ChangeEvent(EventType.KERNEL_CHANGED, "kernel", "running", prev, curr.running)]


class OsDiffer(Differ):
    def diff(self, prev: OsInfo | None, curr: OsInfo) -> list[ChangeEvent]:
        if prev is None or (prev.name, prev.version) == (curr.name, curr.version):
            return []
        return [ChangeEvent(EventType.OS_CHANGED, "os", "os",
                            f"{prev.name} ({prev.version})", f"{curr.name} ({curr.version})")]


class NetworkDiffer:
    """인터페이스(IP·MAC)와 열린 포트의 변경. 인터페이스·포트는 서로 다른 수집기라 따로 호출한다."""

    def diff_interfaces(self, prev: list[NetworkInterface], curr: list[NetworkInterface]) -> list[ChangeEvent]:
        # IP 는 인터페이스를 가로질러 비교한다 — 같은 IP 가 다른 인터페이스로 옮겨간 것은 '추가+삭제'가 아니다.
        # 접두사만 바뀐 것(10.0.0.5/24 → /16)도 같은 IP 라 이벤트가 아니다.
        before = {ip_of(a): (i, a) for i in prev for a in i.addresses}
        after = {ip_of(a): (i, a) for i in curr for a in i.addresses}
        events = [ChangeEvent(EventType.IP_REMOVED, "network", ip, cidr, None, {"interface": i.name, "mac": i.mac})
                  for ip, (i, cidr) in sorted(before.items()) if ip not in after]
        events += [ChangeEvent(EventType.IP_ADDED, "network", ip, None, cidr, {"interface": i.name, "mac": i.mac})
                   for ip, (i, cidr) in sorted(after.items()) if ip not in before]
        old_mac = {i.name: i.mac for i in prev}
        for i in curr:  # MAC 은 양쪽 모두 값이 있을 때만 비교한다(새 인터페이스·MAC 없는 터널은 변경이 아니다)
            if i.name in old_mac and old_mac[i.name] and i.mac and old_mac[i.name] != i.mac:
                events.append(ChangeEvent(EventType.MAC_CHANGED, "network", i.name, old_mac[i.name], i.mac))
        return events

    def diff_ports(self, prev: list[ListeningPort], curr: list[ListeningPort]) -> list[ChangeEvent]:
        before, after = set(prev), set(curr)

        def event(kind: EventType, p: ListeningPort) -> ChangeEvent:
            old, new = (p.bind, None) if kind is EventType.PORT_CLOSED else (None, p.bind)
            return ChangeEvent(kind, "port", f"{p.proto}/{p.port}", old, new, {"bind": p.bind, "exposure": bind_exposure(p.bind)})

        key = lambda p: (p.proto, p.port, p.bind)  # noqa: E731
        return [event(EventType.PORT_CLOSED, p) for p in sorted(before - after, key=key)] + \
               [event(EventType.PORT_OPENED, p) for p in sorted(after - before, key=key)]


class ImageDiffer(Differ):
    """호스트에서 **실행 중인** 이미지의 변화를 저장소 단위로 본다(태그 집합 비교).

    파드 이름·컨테이너 ID 는 재시작할 때마다 바뀌므로 비교 대상이 아니다 — 같은 이미지로 재시작해도 이벤트가 없다.
    종료(exited)된 컨테이너는 '실행 중인 이미지'가 아니다.
    """

    @staticmethod
    def _tags(containers: Iterable[ContainerRecord]) -> dict[str, frozenset[str]]:
        out: dict[str, set[str]] = {}
        for c in containers:
            if c.state == "exited":
                continue
            repo, tag, digest = split_image(c.image)
            out.setdefault(repo or c.image, set()).add(tag or digest[:19])
        return {k: frozenset(v) for k, v in out.items()}

    def diff(self, prev: Iterable[ContainerRecord], curr: Iterable[ContainerRecord]) -> list[ChangeEvent]:
        before, after = self._tags(prev), self._tags(curr)
        events: list[ChangeEvent] = []
        for repo in sorted(set(before) | set(after)):
            old, new = before.get(repo), after.get(repo)
            if old == new:
                continue
            join = lambda tags: ",".join(sorted(tags)) if tags else None  # noqa: E731
            if old is None:
                kind = EventType.CONTAINER_IMAGE_ADDED
            elif new is None:
                kind = EventType.CONTAINER_IMAGE_REMOVED
            else:
                kind = EventType.CONTAINER_IMAGE_CHANGED
            events.append(ChangeEvent(kind, "container_image", repo, join(old), join(new)))
        return events
