"""SQLAlchemy Core 구현. 같은 코드가 SQLite(개발/테스트)와 PostgreSQL 에서 동작한다."""
from __future__ import annotations

import json
import threading
from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterable, Iterator

from sqlalchemy import (
    Connection, Engine, and_, create_engine, delete, distinct, event, exists, func, insert, select, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

import ipaddress

from swinventory.common.models import ContainerRecord, HardwareInfo, K8sNodeInfo, KernelInfo, ListeningPort, NetworkInterface, PackageRecord
from swinventory.common.versioning import version_key
from swinventory.server.domain import ChangeEvent, HostRecord, KernelState
from swinventory.server.repo import schema as S
from swinventory.server.repo.base import ConflictError, InventoryRepository

_MEMORY_URLS = {"sqlite://", "sqlite:///:memory:"}


def _ip_sort_key(address: str) -> tuple[int, int]:
    ip = ipaddress.ip_address(address.split("/", 1)[0])
    return ip.version, int(ip)


def _bind_key(bind: str) -> tuple[int, int]:
    """바인딩 주소의 정렬 키(IP 체계 → 숫자값). SQL 문자열 정렬은 DB 콜레이션마다 달라('::' 와 '0.0.0.0' 의 순서가 PG/SQLite 에서 반대) 파이썬에서 정렬한다."""
    try:
        ip = ipaddress.ip_address(bind)
    except ValueError:
        return 9, 0
    return ip.version, int(ip)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class SqlInventoryRepository(InventoryRepository):
    def __init__(self, engine: Engine):
        self._engine = engine
        self._auth_thread_lock = threading.RLock()
        self._tx: ContextVar[Connection | None] = ContextVar(f"inventory_tx_{id(self)}", default=None)
        S.metadata.create_all(engine)
        # 첫 행 생성도 여러 프로세스에서 멱등이다. 아래 UPDATE 가 DB 간 공통 쓰기 잠금이다.
        if engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as guard_insert
        else:
            from sqlalchemy.dialects.sqlite import insert as guard_insert
        with engine.begin() as c:
            c.execute(guard_insert(S.auth_guard).values(id=1, revision=0).on_conflict_do_nothing())

    @classmethod
    def from_url(cls, url: str) -> "SqlInventoryRepository":
        if url in _MEMORY_URLS:  # 인메모리는 커넥션 하나를 스레드 간 공유해야 테이블이 유지된다
            engine = create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
        else:
            engine = create_engine(url, pool_pre_ping=True)
        if engine.dialect.name == "sqlite":
            @event.listens_for(engine, "connect")
            def _fk_on(dbapi_conn, _record):  # noqa: ANN001
                dbapi_conn.execute("PRAGMA foreign_keys=ON")
        return cls(engine)

    # --- 트랜잭션 ---------------------------------------------------------
    @contextmanager
    def transaction(self) -> Iterator[None]:
        if self._tx.get() is not None:
            yield
            return
        try:
            with self._engine.begin() as conn:
                token = self._tx.set(conn)
                try:
                    yield
                finally:
                    self._tx.reset(token)
        except IntegrityError as exc:  # 롤백된 뒤에 도메인 예외로 바꿔 호출자가 재시도를 판단하게 한다
            raise ConflictError(str(exc.orig)) from exc

    @contextmanager
    def _conn(self, write: bool = False) -> Iterator[Connection]:
        active = self._tx.get()
        if active is not None:
            yield active
            return
        with (self._engine.begin() if write else self._engine.connect()) as conn:
            yield conn

    def ping(self) -> None:
        with self._conn() as c:
            c.execute(select(1))

    # --- 적재(쓰기) -------------------------------------------------------
    def get_host(self, host_id: str) -> HostRecord | None:
        with self._conn() as c:
            row = c.execute(select(S.hosts).where(S.hosts.c.host_id == host_id)).mappings().first()
        if row is None:
            return None
        d = dict(row)
        d["last_errors"] = json.loads(d["last_errors"])
        return HostRecord(**d)

    def upsert_host(self, host: HostRecord) -> None:
        values = {
            "hostname": host.hostname, "os_family": host.os_family, "os_name": host.os_name,
            "os_version": host.os_version, "agent_version": host.agent_version,
            "last_seen": host.last_seen, "last_snapshot_at": host.last_snapshot_at,
            "last_errors": json.dumps(host.last_errors, sort_keys=True),
        }
        with self._conn(write=True) as c:
            res = c.execute(update(S.hosts).where(S.hosts.c.host_id == host.host_id).values(**values))
            if res.rowcount == 0:
                c.execute(insert(S.hosts).values(host_id=host.host_id, first_seen=host.first_seen, **values))

    def snapshot_exists(self, host_id: str, collected_at: str) -> bool:
        with self._conn() as c:
            return c.execute(select(S.snapshots.c.id).where(and_(
                S.snapshots.c.host_id == host_id, S.snapshots.c.collected_at == collected_at))).first() is not None

    def insert_snapshot(self, host_id: str, collected_at: str, received_at: str,
                        collected: list[str], errors: dict[str, str]) -> int:
        with self._conn(write=True) as c:
            res = c.execute(insert(S.snapshots).values(
                host_id=host_id, collected_at=collected_at, received_at=received_at,
                collected=json.dumps(collected), errors=json.dumps(errors, sort_keys=True)))
            return int(res.inserted_primary_key[0])

    def synced_sources(self, host_id: str) -> set[str]:
        with self._conn() as c:
            rows = c.execute(select(S.host_sources.c.source).where(S.host_sources.c.host_id == host_id))
            return {r[0] for r in rows}

    def mark_sources_synced(self, host_id: str, sources: Iterable[str], at: str) -> None:
        rows = [{"host_id": host_id, "source": s, "first_synced_at": at} for s in sorted(set(sources))]
        if rows:
            with self._conn(write=True) as c:
                c.execute(insert(S.host_sources), rows)

    def load_packages(self, host_id: str, sources: Iterable[str]) -> list[PackageRecord]:
        srcs = list(sources)
        if not srcs:
            return []
        t = S.installed_packages
        with self._conn() as c:
            rows = c.execute(select(t.c.source, t.c.name, t.c.version, t.c.arch).where(
                and_(t.c.host_id == host_id, t.c.source.in_(srcs))))
            return [PackageRecord(r.source, r.name, r.version, r.arch) for r in rows]

    def apply_package_changes(self, host_id: str, installed: list[PackageRecord],
                              removed: list[PackageRecord]) -> None:
        t = S.installed_packages
        with self._conn(write=True) as c:
            for p in removed:
                c.execute(delete(t).where(and_(
                    t.c.host_id == host_id, t.c.source == p.source, t.c.name == p.name,
                    t.c.arch == p.arch, t.c.version == p.version)))
            if installed:
                c.execute(insert(t), [{"host_id": host_id, **p.to_dict()} for p in installed])

    def get_kernel_state(self, host_id: str) -> KernelState | None:
        t = S.host_kernel_state
        with self._conn() as c:
            r = c.execute(select(t).where(t.c.host_id == host_id)).mappings().first()
        if r is None:
            return None
        return KernelState(r["running"], r["latest_installed"], bool(r["reboot_required"]))

    def save_kernel_state(self, host_id: str, kernel: KernelInfo, latest_installed: str, at: str) -> None:
        st, hk = S.host_kernel_state, S.host_kernels
        values = {"running": kernel.running, "latest_installed": latest_installed,
                  "reboot_required": kernel.reboot_required, "updated_at": at}
        with self._conn(write=True) as c:
            if c.execute(update(st).where(st.c.host_id == host_id).values(**values)).rowcount == 0:
                c.execute(insert(st).values(host_id=host_id, **values))
            c.execute(delete(hk).where(hk.c.host_id == host_id))
            versions = dict.fromkeys(kernel.installed)
            c.execute(insert(hk), [{"host_id": host_id, "version": v, "is_running": v == kernel.running}
                                   for v in versions])

    def get_network(self, host_id: str) -> tuple[list[NetworkInterface], list[ListeningPort]]:
        with self._conn() as c:
            ifs = sorted(c.execute(select(S.host_interfaces).where(S.host_interfaces.c.host_id == host_id)).mappings().all(),
                         key=lambda i: i["name"])
            addrs: dict[str, list[str]] = defaultdict(list)
            for r in c.execute(select(S.host_addresses.c.interface, S.host_addresses.c.address)
                               .where(S.host_addresses.c.host_id == host_id)):
                addrs[r.interface].append(r.address)
            ports = sorted(c.execute(select(S.host_ports).where(S.host_ports.c.host_id == host_id)).mappings().all(),
                           key=lambda p: (p["proto"], p["port"], _bind_key(p["bind"])))
        return ([NetworkInterface(i["name"], i["mac"], i["state"], tuple(sorted(addrs[i["name"]], key=_ip_sort_key)))
                 for i in ifs], [ListeningPort(p["proto"], p["port"], p["bind"]) for p in ports])

    def replace_interfaces(self, host_id: str, interfaces: list[NetworkInterface]) -> None:
        with self._conn(write=True) as c:
            c.execute(delete(S.host_addresses).where(S.host_addresses.c.host_id == host_id))
            c.execute(delete(S.host_interfaces).where(S.host_interfaces.c.host_id == host_id))
            unique = {i.name: i for i in interfaces}  # 같은 이름이 중복되면 마지막 것
            if unique:
                c.execute(insert(S.host_interfaces), [{"host_id": host_id, "name": i.name, "mac": i.mac, "state": i.state}
                                                      for i in unique.values()])
            rows = [{"host_id": host_id, "interface": i.name, "address": a, "ip": a.split("/", 1)[0],
                     "family": ipaddress.ip_interface(a).version} for i in unique.values() for a in dict.fromkeys(i.addresses)]
            if rows:
                c.execute(insert(S.host_addresses), rows)

    def replace_ports(self, host_id: str, ports: list[ListeningPort]) -> None:
        with self._conn(write=True) as c:
            c.execute(delete(S.host_ports).where(S.host_ports.c.host_id == host_id))
            unique = dict.fromkeys(ports)
            if unique:
                c.execute(insert(S.host_ports), [{"host_id": host_id, **p.to_dict()} for p in unique])

    def save_hardware(self, host_id: str, hardware: HardwareInfo, at: str) -> None:
        values = {**hardware.to_dict(), "updated_at": at}
        with self._conn(write=True) as c:
            res = c.execute(update(S.host_hardware).where(S.host_hardware.c.host_id == host_id).values(**values))
            if res.rowcount == 0:
                c.execute(insert(S.host_hardware).values(host_id=host_id, **values))

    def get_hardware(self, host_id: str) -> HardwareInfo | None:
        with self._conn() as c:
            row = c.execute(select(S.host_hardware).where(S.host_hardware.c.host_id == host_id)).mappings().first()
        return HardwareInfo.from_dict(dict(row)) if row else None

    def list_hardware(self) -> dict[str, HardwareInfo]:
        with self._conn() as c:
            return {r["host_id"]: HardwareInfo.from_dict(dict(r)) for r in c.execute(select(S.host_hardware)).mappings()}

    _CONTAINER_FIELDS = ("runtime", "container_id", "name", "image", "image_id", "image_digest", "state", "created_at", "pod", "namespace")

    def get_containers(self, host_id: str) -> list[ContainerRecord]:
        t = S.host_containers
        with self._conn() as c:
            rows = c.execute(select(t).where(t.c.host_id == host_id).order_by(t.c.container_id)).mappings().all()
        return [ContainerRecord.from_dict(dict(r)) for r in rows]

    def replace_containers(self, host_id: str, containers: list[ContainerRecord]) -> None:
        t = S.host_containers
        with self._conn(write=True) as c:
            c.execute(delete(t).where(t.c.host_id == host_id))
            seen: set[str] = set()
            rows = []
            for rec in containers:                       # 같은 ID 가 둘이면 PK 충돌 — 뒤의 것을 버린다
                if rec.container_id not in seen:
                    seen.add(rec.container_id)
                    rows.append({"host_id": host_id, **rec.to_dict()})
            if rows:
                c.execute(insert(t), rows)

    def get_k8s(self, host_id: str) -> K8sNodeInfo | None:
        with self._conn() as c:
            row = c.execute(select(S.host_k8s).where(S.host_k8s.c.host_id == host_id)).mappings().first()
        return K8sNodeInfo.from_dict(dict(row)) if row else None

    def save_k8s(self, host_id: str, k8s: K8sNodeInfo | None, at: str) -> None:
        t = S.host_k8s
        with self._conn(write=True) as c:
            if k8s is None:
                c.execute(delete(t).where(t.c.host_id == host_id))
                return
            values = {**k8s.to_dict(), "updated_at": at}
            if c.execute(update(t).where(t.c.host_id == host_id).values(**values)).rowcount == 0:
                c.execute(insert(t).values(host_id=host_id, **values))

    def list_containers(self) -> list[dict[str, Any]]:
        t, h = S.host_containers, S.hosts
        with self._conn() as c:
            rows = c.execute(select(t, h.c.hostname).select_from(t.join(h, h.c.host_id == t.c.host_id))
                             .order_by(h.c.hostname, t.c.namespace, t.c.pod, t.c.name, t.c.container_id)).mappings().all()
        return [dict(r) for r in rows]

    def list_k8s_nodes(self) -> list[dict[str, Any]]:
        t, h = S.host_k8s, S.hosts
        with self._conn() as c:
            rows = c.execute(select(t.c.host_id, h.c.hostname, t.c.cluster_id, t.c.api_server, t.c.version, t.c.runtime)
                             .select_from(t.join(h, h.c.host_id == t.c.host_id)).order_by(h.c.hostname)).mappings().all()
        return [dict(r) for r in rows]

    def add_events(self, host_id: str, snapshot_id: int | None, occurred_at: str,
                   events: list[ChangeEvent]) -> None:
        if not events:
            return
        with self._conn(write=True) as c:
            c.execute(insert(S.change_events), [{
                "host_id": host_id, "snapshot_id": snapshot_id, "occurred_at": occurred_at,
                "event_type": e.event_type.value, "subject_type": e.subject_type,
                "subject_key": e.subject_key, "old_value": e.old_value, "new_value": e.new_value,
                "detail": json.dumps(e.detail, sort_keys=True)} for e in events])

    def set_tags(self, host_id: str, tags: dict[str, str]) -> bool:
        with self._conn(write=True) as c:
            if c.execute(select(S.hosts.c.host_id).where(S.hosts.c.host_id == host_id)).first() is None:
                return False
            c.execute(delete(S.host_tags).where(S.host_tags.c.host_id == host_id))
            if tags:
                c.execute(insert(S.host_tags), [{"host_id": host_id, "key": k, "value": v}
                                                for k, v in tags.items()])
        return True

    def delete_host(self, host_id: str) -> bool:
        with self.transaction(), self._conn(write=True) as c:
            if c.execute(select(S.hosts.c.host_id).where(S.hosts.c.host_id == host_id)).first() is None:
                return False
            self._delete_host_rows(c, host_id)
        return True

    @staticmethod
    def _delete_host_rows(c: Connection, host_id: str) -> None:
        # FK 순서: events(→snapshots) → 나머지 자식 → snapshots → hosts
        for t in (S.change_events, S.host_tags, S.host_sources, S.installed_packages, S.host_addresses,
                  S.host_interfaces, S.host_ports, S.host_kernels, S.host_kernel_state, S.host_hardware, S.host_containers, S.host_k8s, S.snapshots):
            c.execute(delete(t).where(t.c.host_id == host_id))
        c.execute(delete(S.hosts).where(S.hosts.c.host_id == host_id))

    def prune(self, *, snapshots_before: str | None = None, events_before: str | None = None,
              hosts_before: str | None = None) -> dict[str, int]:
        out = {"snapshots": 0, "events": 0, "hosts": 0}
        e, s = S.change_events, S.snapshots
        with self.transaction(), self._conn(write=True) as c:
            if hosts_before:
                ids = [r[0] for r in c.execute(select(S.hosts.c.host_id).where(S.hosts.c.last_seen < hosts_before))]
                for host_id in ids:
                    self._delete_host_rows(c, host_id)
                out["hosts"] = len(ids)
            if events_before:
                out["events"] = c.execute(delete(e).where(e.c.occurred_at < events_before)).rowcount
            if snapshots_before:
                old = select(s.c.id).where(s.c.collected_at < snapshots_before)
                c.execute(update(e).where(e.c.snapshot_id.in_(old)).values(snapshot_id=None))
                out["snapshots"] = c.execute(delete(s).where(s.c.collected_at < snapshots_before)).rowcount
        return out

    def get_setting(self, key: str) -> str | None:
        with self._conn() as c:
            row = c.execute(select(S.app_settings.c.value).where(S.app_settings.c.key == key)).first()
        return row[0] if row else None

    def set_setting(self, key: str, value: str, at: str) -> None:
        t = S.app_settings
        with self._conn(write=True) as c:
            if c.execute(update(t).where(t.c.key == key).values(value=value, updated_at=at)).rowcount == 0:
                c.execute(insert(t).values(key=key, value=value, updated_at=at))

    def add_report(self, created_at: str, model: str, markdown: str, facts: dict[str, Any],
                   prompt_tokens: int | None, completion_tokens: int | None) -> int:
        with self._conn(write=True) as c:
            res = c.execute(insert(S.reports).values(
                created_at=created_at, model=model, markdown=markdown, facts=json.dumps(facts, ensure_ascii=False),
                prompt_tokens=prompt_tokens, completion_tokens=completion_tokens))
            return int(res.inserted_primary_key[0])

    def delete_report(self, report_id: int) -> bool:
        with self._conn(write=True) as c:
            return c.execute(delete(S.reports).where(S.reports.c.id == report_id)).rowcount > 0

    # --- 조회(읽기) -------------------------------------------------------
    @staticmethod
    def _tags_for(c: Connection, host_ids: list[str]) -> dict[str, dict[str, str]]:
        out: dict[str, dict[str, str]] = defaultdict(dict)
        if host_ids:
            for r in c.execute(select(S.host_tags).where(S.host_tags.c.host_id.in_(host_ids))):
                out[r.host_id][r.key] = r.value
        return out

    @staticmethod
    def _host_dict(row: Any) -> dict[str, Any]:
        d = dict(row)
        d["last_errors"] = json.loads(d["last_errors"])
        return d

    @staticmethod
    def _tag_filters(host_col: Any, tags: dict[str, str] | None) -> list[Any]:
        t = S.host_tags
        return [exists().where(and_(t.c.host_id == host_col, t.c.key == k, t.c.value == v))
                for k, v in (tags or {}).items()]

    def list_hosts(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        h, k = S.hosts, S.host_kernel_state
        stmt = (select(h, k.c.running, k.c.latest_installed, k.c.reboot_required)
                .select_from(h.outerjoin(k, k.c.host_id == h.c.host_id)).order_by(h.c.host_id))
        for cond in self._tag_filters(h.c.host_id, tags):
            stmt = stmt.where(cond)
        with self._conn() as c:
            rows = c.execute(stmt).mappings().all()
            tags = self._tags_for(c, [r["host_id"] for r in rows])
            ips: dict[str, set[str]] = defaultdict(set)
            for r in c.execute(select(S.host_addresses.c.host_id, S.host_addresses.c.ip)):
                ips[r.host_id].add(r.ip)
        out = []
        for r in rows:
            d = self._host_dict(r)
            d["tags"] = tags.get(d["host_id"], {})
            d["ips"] = sorted(ips.get(d["host_id"], ()), key=lambda ip: _ip_sort_key(ip))
            out.append(d)
        return out

    def host_detail(self, host_id: str) -> dict[str, Any] | None:
        with self._conn() as c:
            host = c.execute(select(S.hosts).where(S.hosts.c.host_id == host_id)).mappings().first()
            if host is None:
                return None
            ks = c.execute(select(S.host_kernel_state).where(S.host_kernel_state.c.host_id == host_id)).mappings().first()
            kernels = c.execute(select(S.host_kernels.c.version, S.host_kernels.c.is_running)
                                .where(S.host_kernels.c.host_id == host_id)).mappings().all()
            p = S.installed_packages
            pkgs = c.execute(select(p.c.source, p.c.name, p.c.version, p.c.arch)
                             .where(p.c.host_id == host_id).order_by(p.c.name, p.c.version)).mappings().all()
            tags = self._tags_for(c, [host_id]).get(host_id, {})
            events = self.list_events(host_id=host_id, limit=50)
        ifaces, ports = self.get_network(host_id)
        hardware = self.get_hardware(host_id)
        k8s = self.get_k8s(host_id)
        return {
            "hardware": hardware.to_dict() if hardware else None,
            "containers": [c.to_dict() for c in self.get_containers(host_id)],
            "k8s": k8s.to_dict() if k8s else None,
            "interfaces": [{"name": i.name, "mac": i.mac, "state": i.state, "addresses": list(i.addresses)} for i in ifaces],
            "ports": [p.to_dict() for p in ports],
            "host": self._host_dict(host),
            "kernel": ({"running": ks["running"], "latest_installed": ks["latest_installed"],
                        "reboot_required": bool(ks["reboot_required"])} if ks else None),
            "kernels": sorted(({"version": k["version"], "is_running": bool(k["is_running"])} for k in kernels),
                              key=lambda k: version_key(k["version"]), reverse=True),
            "packages": [dict(r) for r in pkgs],
            "tags": tags,
            "events": events,
        }

    def overview(self, stale_before: str) -> dict[str, Any]:
        h, k = S.hosts, S.host_kernel_state
        with self._conn() as c:
            total = c.execute(select(func.count()).select_from(h)).scalar_one()
            healthy = c.execute(select(func.count()).select_from(h).where(and_(
                h.c.last_errors == "{}", h.c.last_seen >= stale_before))).scalar_one()
            stale = c.execute(select(func.count()).select_from(h).where(h.c.last_seen < stale_before)).scalar_one()
            reboot = c.execute(select(func.count()).select_from(k).where(k.c.reboot_required.is_(True))).scalar_one()
        return {
            "host_count": total, "healthy_count": healthy,
            "stale_count": stale, "error_count": total - healthy - stale,  # error = 최근 수집됐지만 실패한 수집기가 있음
            "healthy_rate": (healthy / total) if total else 0.0,
            "reboot_required_count": reboot,
            "kernel_distribution": self.kernel_distribution(),
            "recent_events": self.list_events(limit=20),
        }

    def kernel_distribution(self) -> list[dict[str, Any]]:
        k = S.host_kernel_state
        with self._conn() as c:
            rows = c.execute(select(k.c.running, func.count().label("n")).group_by(k.c.running)).all()
        return [{"version": r.running, "host_count": r.n}
                for r in sorted(rows, key=lambda r: (-r.n, r.running))]

    def kernel_hosts(self, reboot_required: bool | None = None, running: str | None = None,
                     tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        h, k = S.hosts, S.host_kernel_state
        q = (select(h.c.host_id, h.c.hostname, h.c.os_family, k.c.running, k.c.latest_installed, k.c.reboot_required)
             .select_from(h.join(k, k.c.host_id == h.c.host_id)).order_by(h.c.host_id))
        if reboot_required is not None:
            q = q.where(k.c.reboot_required.is_(reboot_required))
        if running is not None:
            q = q.where(k.c.running == running)
        for cond in self._tag_filters(h.c.host_id, tags):
            q = q.where(cond)
        with self._conn() as c:
            rows = c.execute(q).mappings().all()
            host_tags = self._tags_for(c, [r["host_id"] for r in rows])
        return [{**dict(r), "reboot_required": bool(r["reboot_required"]),
                 "tags": host_tags.get(r["host_id"], {})} for r in rows]

    def software_search(self, q: str, limit: int = 100) -> list[dict[str, Any]]:
        p = S.installed_packages
        pattern = f"%{_escape_like(q.lower())}%"
        stmt = (select(p.c.name, func.count(distinct(p.c.host_id)).label("host_count"),
                       func.count(distinct(p.c.version)).label("version_count"))
                .where(func.lower(p.c.name).like(pattern, escape="\\"))
                .group_by(p.c.name).order_by(p.c.name).limit(limit))
        with self._conn() as c:
            return [dict(r) for r in c.execute(stmt).mappings()]

    def software_hosts(self, q: str = "", host_id: str | None = None) -> list[dict[str, Any]]:
        """서버별 설치 항목 수만 조회한다. 전체 패키지 본문은 펼친 서버에서만 가져온다."""
        p, h = S.installed_packages, S.hosts
        stmt = (select(p.c.host_id, h.c.hostname, func.count().label("package_count"))
                .select_from(p.join(h, h.c.host_id == p.c.host_id))
                .group_by(p.c.host_id, h.c.hostname).order_by(h.c.hostname, p.c.host_id))
        if q:
            stmt = stmt.where(func.lower(p.c.name).like(f"%{_escape_like(q.lower())}%", escape="\\"))
        if host_id is not None:
            stmt = stmt.where(p.c.host_id == host_id)
        with self._conn() as c:
            return [dict(r) for r in c.execute(stmt).mappings()]

    def software_detail(self, name: str) -> dict[str, Any] | None:
        p, h = S.installed_packages, S.hosts
        with self._conn() as c:
            hosts = c.execute(
                select(p.c.host_id, h.c.hostname, p.c.version, p.c.arch, p.c.source)
                .select_from(p.join(h, h.c.host_id == p.c.host_id))
                .where(p.c.name == name).order_by(p.c.host_id, p.c.version)).mappings().all()
        if not hosts:
            return None
        counts: dict[str, set[str]] = defaultdict(set)
        for r in hosts:
            counts[r["version"]].add(r["host_id"])
        versions = [{"version": v, "host_count": len(ids)}
                    for v, ids in sorted(counts.items(), key=lambda kv: version_key(kv[0]), reverse=True)]
        return {"name": name, "versions": versions, "hosts": [dict(r) for r in hosts]}

    def list_events(self, host_id: str | None = None, event_type: str | None = None,
                    since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        e, h = S.change_events, S.hosts
        q = (select(e, h.c.hostname).select_from(e.join(h, h.c.host_id == e.c.host_id))
             .order_by(e.c.id.desc()).limit(limit))
        if host_id:
            q = q.where(e.c.host_id == host_id)
        if event_type:
            q = q.where(e.c.event_type == event_type)
        if since:
            q = q.where(e.c.occurred_at >= since)
        with self._conn() as c:
            rows = c.execute(q).mappings().all()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"])
            out.append(d)
        return out

    def package_version_spread(self, min_versions: int = 3, limit: int = 20) -> list[dict[str, Any]]:
        p = S.installed_packages
        version_count = func.count(distinct(p.c.version))
        stmt = (select(p.c.name, version_count.label("version_count"), func.count(distinct(p.c.host_id)).label("host_count"))
                .group_by(p.c.name).having(version_count >= min_versions)
                .order_by(version_count.desc(), p.c.name).limit(limit))
        with self._conn() as c:
            return [dict(r) for r in c.execute(stmt).mappings()]

    def count_events_by_type(self, since: str) -> dict[str, int]:
        e = S.change_events
        with self._conn() as c:
            rows = c.execute(select(e.c.event_type, func.count()).where(e.c.occurred_at >= since).group_by(e.c.event_type))
            return {r[0]: r[1] for r in rows}

    def list_reports(self, limit: int = 50) -> list[dict[str, Any]]:
        r = S.reports
        with self._conn() as c:
            rows = c.execute(select(r.c.id, r.c.created_at, r.c.model, r.c.prompt_tokens, r.c.completion_tokens)
                             .order_by(r.c.id.desc()).limit(limit)).mappings().all()
        return [dict(x) for x in rows]

    def get_report(self, report_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(select(S.reports).where(S.reports.c.id == report_id)).mappings().first()
        if row is None:
            return None
        d = dict(row)
        d["facts"] = json.loads(d["facts"])
        return d

    def list_ips(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        a, i, h = S.host_addresses, S.host_interfaces, S.hosts
        stmt = (select(a.c.host_id, h.c.hostname, a.c.interface, i.c.mac, i.c.state, a.c.address, a.c.ip, a.c.family)
                .select_from(a.join(h, h.c.host_id == a.c.host_id)
                             .join(i, and_(i.c.host_id == a.c.host_id, i.c.name == a.c.interface))))
        for cond in self._tag_filters(h.c.host_id, tags):
            stmt = stmt.where(cond)
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(stmt).mappings()]
        return sorted(rows, key=lambda r: (r["family"], _ip_sort_key(r["ip"])[1], r["hostname"], r["host_id"]))

    def list_ports(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        p, h = S.host_ports, S.hosts
        stmt = select(p.c.host_id, h.c.hostname, p.c.proto, p.c.port, p.c.bind).select_from(p.join(h, h.c.host_id == p.c.host_id))
        for cond in self._tag_filters(h.c.host_id, tags):
            stmt = stmt.where(cond)
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(stmt).mappings()]
        return sorted(rows, key=lambda r: (r["proto"], r["port"], r["hostname"], _bind_key(r["bind"])))

    # --- 자산 대장 --------------------------------------------------------
    _ASSET_FIELDS = ("asset_no", "kind", "serial", "hostname", "domain", "ip", "parent_asset_id", "host_id", "note")

    def _asset_values(self, values: dict[str, Any]) -> dict[str, Any]:
        out = {k: values[k] for k in self._ASSET_FIELDS}
        out["asset_no_key"] = values["asset_no"].casefold()
        return out

    def list_assets(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [{k: v for k, v in r.items() if k != "asset_no_key"}
                    for r in c.execute(select(S.assets).order_by(S.assets.c.id)).mappings()]

    def get_asset(self, asset_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(select(S.assets).where(S.assets.c.id == asset_id)).mappings().first()
        return {k: v for k, v in row.items() if k != "asset_no_key"} if row else None

    def create_asset(self, values: dict[str, Any], at: str) -> int:
        with self.transaction(), self._conn(write=True) as c:
            res = c.execute(insert(S.assets).values(**self._asset_values(values), created_at=at, updated_at=at))
            return int(res.inserted_primary_key[0])

    def update_asset(self, asset_id: int, values: dict[str, Any], at: str) -> bool:
        with self.transaction(), self._conn(write=True) as c:
            res = c.execute(update(S.assets).where(S.assets.c.id == asset_id).values(**self._asset_values(values), updated_at=at))
            return res.rowcount > 0

    def delete_asset(self, asset_id: int) -> bool:
        with self.transaction(), self._conn(write=True) as c:
            return c.execute(delete(S.assets).where(S.assets.c.id == asset_id)).rowcount > 0


    @contextmanager
    def auth_lock(self):
        """계정 변경·최종 관리자 보호·세션 발급을 하나의 DB 직렬화 경계로 묶는다."""
        with self._auth_thread_lock, self.transaction():
            with self._conn(write=True) as c:
                c.execute(update(S.auth_guard).where(S.auth_guard.c.id == 1).values(revision=S.auth_guard.c.revision + 1))
            yield

    def get_user(self, key: str, *, by_name: bool = False) -> dict[str, Any] | None:
        col = S.users.c.username if by_name else S.users.c.id
        with self._conn() as c:
            row = c.execute(select(S.users).where(col == key)).mappings().first()
            return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            cols = [v for v in S.users.c if v.name not in {"password_hash", "failed_logins", "locked_until"}]
            return [dict(row) for row in c.execute(select(*cols).order_by(S.users.c.username)).mappings()]

    def create_user(self, values: dict[str, Any]) -> None:
        with self._conn(write=True) as c:
            c.execute(insert(S.users).values(**values))

    def update_user(self, user_id: str, values: dict[str, Any]) -> None:
        with self._conn(write=True) as c:
            c.execute(update(S.users).where(S.users.c.id == user_id).values(**values))

    def add_token(self, values: dict[str, Any]) -> None:
        with self._conn(write=True) as c:
            c.execute(insert(S.access_tokens).values(**values))

    def find_token(self, digest: str) -> dict[str, Any] | None:
        with self._conn() as c:
            # 계정의 세대·활성·역할도 동일한 SELECT 스냅샷에서 읽는다.
            t, u = S.access_tokens, S.users
            row = c.execute(select(t, u.c.active.label("user_active"), u.c.generation.label("user_generation"),
                u.c.role.label("user_role"), u.c.username).select_from(t.outerjoin(u, t.c.user_id == u.c.id))
                .where(t.c.token_hash == digest)).mappings().first()
            return dict(row) if row else None

    def list_tokens(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            cols = [v for v in S.access_tokens.c if v.name != "token_hash"]
            return [dict(row) for row in c.execute(select(*cols).where(S.access_tokens.c.kind == "api")
                .order_by(S.access_tokens.c.created_at.desc())).mappings()]

    def revoke_token(self, token_id: str) -> bool:
        with self._conn(write=True) as c:
            return c.execute(update(S.access_tokens).where(S.access_tokens.c.id == token_id).values(revoked=True)).rowcount > 0

    def login_attempt(self, key: str, now: int) -> int:
        """프록시 헤더 대신 연결 IP 의 해시로 15분 창을 센다. 만료 행은 같이 정리한다."""
        with self._conn(write=True) as c:
            c.execute(delete(S.login_attempts).where(S.login_attempts.c.started_at <= now - 900))
            row = c.execute(select(S.login_attempts).where(S.login_attempts.c.key == key)).mappings().first()
            if row:
                count = row["count"] + 1
                c.execute(update(S.login_attempts).where(S.login_attempts.c.key == key).values(count=count))
            else:
                count = 1
                c.execute(insert(S.login_attempts).values(key=key, started_at=now, count=count))
            return count
