from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from swinventory.common.models import OsInfo, Snapshot
from swinventory.common.versioning import latest_version
from swinventory.server.diff import ImageDiffer, KernelDiffer, NetworkDiffer, OsDiffer, PackageDiffer
from swinventory.server.domain import ChangeEvent, HostRecord
from swinventory.server.repo.base import ConflictError, InventoryRepository
from swinventory.server.timeutil import normalize_ts

SOFTWARE_PREFIX = "software."
NETWORK_SOURCES = ("network.interfaces", "network.ports")


@dataclass(frozen=True)
class IngestResult:
    status: str  # baseline | applied | duplicate | stale
    event_count: int = 0


class IngestService:
    """스냅샷 1건 = 트랜잭션 1건. diff 규칙:

    - 호스트의 첫 스냅샷은 기준선이라 이벤트가 없다.
    - collected 에 없는(=실패한) source 는 동기화하지 않는다 → 일시 오류로 '전부 삭제됨'이 쏟아지지 않는다.
    - 호스트에서 처음 성공한 source 도 그 source 의 기준선이다(첫 회차에 실패했던 경우).
    """

    def __init__(self, repo: InventoryRepository,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._repo = repo
        self._clock = clock

    def ingest(self, snap: Snapshot) -> IngestResult:
        """동시 요청(재전송·같은 호스트 중복 기동)이 유니크 제약에 부딪히면 롤백 후 한 번 재시도한다.
        재시도에서는 상대가 만든 행이 보이므로 duplicate/applied 로 자연스럽게 수렴한다."""
        try:
            return self._ingest_once(snap)
        except ConflictError:
            return self._ingest_once(snap)

    def _ingest_once(self, snap: Snapshot) -> IngestResult:
        repo = self._repo
        received = normalize_ts(self._clock())
        collected_at = normalize_ts(snap.collected_at)
        with repo.transaction():
            host = repo.get_host(snap.host_id)
            if repo.snapshot_exists(snap.host_id, collected_at):
                return IngestResult("duplicate")
            if host is None:  # snapshots FK 때문에 호스트 행을 먼저 만든다
                host = HostRecord(snap.host_id, snap.hostname, snap.agent_version,
                                  first_seen=received, last_seen=received, last_snapshot_at=collected_at)
                repo.upsert_host(host)
                is_new = True
            else:
                is_new = False
            snapshot_id = repo.insert_snapshot(snap.host_id, collected_at, received,
                                               snap.collected, snap.errors)
            if not is_new and collected_at < host.last_snapshot_at:
                return IngestResult("stale")  # 늦게 도착한 옛 스냅샷은 보관만 한다

            events = self._sync(snap, host, is_new, received)
            self._update_host(snap, host, collected_at, received)
            repo.add_events(snap.host_id, snapshot_id, collected_at, events)
            return IngestResult("baseline" if is_new else "applied", len(events))

    def _sync(self, snap: Snapshot, host: HostRecord, is_new: bool, received: str) -> list[ChangeEvent]:
        repo, events = self._repo, []
        sources = {c[len(SOFTWARE_PREFIX):] for c in snap.collected if c.startswith(SOFTWARE_PREFIX)}

        known = set() if is_new else repo.synced_sources(snap.host_id)
        prev = {p.instance_key: p for p in repo.load_packages(snap.host_id, sources)}
        curr = {p.instance_key: p for p in snap.packages if p.source in sources}
        diff_sources = sources & known
        events += PackageDiffer().diff([p for p in prev.values() if p.source in diff_sources],
                                       [p for p in curr.values() if p.source in diff_sources])
        repo.apply_package_changes(
            snap.host_id,
            installed=[p for k, p in curr.items() if k not in prev],
            removed=[p for k, p in prev.items() if k not in curr])

        # 네트워크: 인터페이스·포트는 별개의 수집기라 각각 기준선을 갖는다(에이전트 업그레이드 시 폭주 방지)
        net = [n for n in NETWORK_SOURCES if n in snap.collected]
        if net:
            prev_ifaces, prev_ports = repo.get_network(snap.host_id)
            if "network.interfaces" in net:
                if "network.interfaces" in known:
                    events += NetworkDiffer().diff_interfaces(prev_ifaces, snap.interfaces)
                repo.replace_interfaces(snap.host_id, snap.interfaces)
            if "network.ports" in net:
                if "network.ports" in known:
                    events += NetworkDiffer().diff_ports(prev_ports, snap.ports)
                repo.replace_ports(snap.host_id, snap.ports)
        extra = {"containers"} if "containers" in snap.collected else set()
        if extra:   # 컨테이너: 이미지 단위로만 변경 이력을 남긴다(파드·컨테이너 ID 는 재시작마다 바뀐다). 처음 성공한 회차는 기준선
            if "containers" in known:
                events += ImageDiffer().diff(repo.get_containers(snap.host_id), snap.containers)
            repo.replace_containers(snap.host_id, snap.containers)
            repo.save_k8s(snap.host_id, snap.k8s, received)
        repo.mark_sources_synced(snap.host_id, (sources | set(net) | extra) - known, received)

        if snap.kernel is not None and "kernel" in snap.collected:
            prev_state = repo.get_kernel_state(snap.host_id)
            events += KernelDiffer().diff(prev_state.running if prev_state else None, snap.kernel)
            latest = latest_version(snap.kernel.installed) or snap.kernel.running
            repo.save_kernel_state(snap.host_id, snap.kernel, latest, received)

        if snap.hardware is not None and "hardware" in snap.collected:  # 부가 정보 — 이력 없이 현재 값만 덮어쓴다
            repo.save_hardware(snap.host_id, snap.hardware, received)

        if snap.os is not None and "os" in snap.collected:
            prev_os = OsInfo(host.os_family, host.os_name, host.os_version) if host.os_name else None
            events += OsDiffer().diff(prev_os, snap.os)
        return events

    def _update_host(self, snap: Snapshot, host: HostRecord, collected_at: str, received: str) -> None:
        host.hostname = snap.hostname
        host.agent_version = snap.agent_version
        host.last_seen = received
        host.last_snapshot_at = collected_at
        host.last_errors = dict(snap.errors)
        if snap.os is not None and "os" in snap.collected:  # 실패한 회차에는 기존 값을 유지
            host.os_family, host.os_name, host.os_version = snap.os.family, snap.os.name, snap.os.version
        self._repo.upsert_host(host)
