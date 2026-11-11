from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Callable

from swinventory import __version__
from swinventory.agent.collectors.containers import ContainerCollector
from swinventory.agent.collectors.hardware import HardwareCollector
from swinventory.agent.collectors.kernel import KernelCollector
from swinventory.agent.collectors.network import InterfaceCollector, PortCollector
from swinventory.agent.collectors.os_info import OsCollector
from swinventory.agent.collectors.software import SoftwareCollector
from swinventory.agent.profiles.base import PlatformProfile
from swinventory.common.models import Snapshot


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SnapshotOrchestrator:
    """프로필의 수집기를 모두 실행해 Snapshot 을 조립한다. 수집기 하나가 실패해도 나머지는 계속한다."""

    def __init__(
        self, profile: PlatformProfile, *,
        clock: Callable[[], datetime] = _utcnow,
        hostname_fn: Callable[[], str] = socket.gethostname,
        agent_version: str = __version__,
    ):
        self._profile = profile
        self._clock = clock
        self._hostname_fn = hostname_fn
        self._agent_version = agent_version

    def collect(self) -> Snapshot:
        snap = Snapshot(
            host_id=self._profile.host_id(),
            hostname=self._hostname_fn(),
            collected_at=self._clock().astimezone(timezone.utc).isoformat(),
            agent_version=self._agent_version,
        )
        for collector in self._profile.collectors():
            result = collector.collect()
            if not result.ok:
                snap.errors[result.name] = result.error or "unknown error"
                continue
            if result.value is None and getattr(collector, "optional", False):
                continue                                      # 적용 대상 아님(예: 컨테이너 헬퍼 미설치) — 성공도 실패도 아니다
            snap.collected.append(result.name)
            if isinstance(collector, SoftwareCollector):
                snap.packages.extend(result.value)
            elif isinstance(collector, KernelCollector):
                snap.kernel = result.value
            elif isinstance(collector, OsCollector):
                snap.os = result.value
            elif isinstance(collector, InterfaceCollector):
                snap.interfaces = result.value
            elif isinstance(collector, PortCollector):
                snap.ports = result.value
            elif isinstance(collector, HardwareCollector):
                snap.hardware = result.value
            elif isinstance(collector, ContainerCollector):
                snap.containers, snap.k8s = result.value
        return snap
