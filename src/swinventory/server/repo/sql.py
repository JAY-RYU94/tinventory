"""SQLAlchemy Core 구현. 같은 코드가 SQLite(개발/테스트)와 PostgreSQL 에서 동작한다."""
from __future__ import annotations

import json
import threading
from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterable, Iterator

from sqlalchemy import (
    Connection, Engine, and_, case, cast, create_engine, delete, distinct, event, exists, func, insert, inspect, or_, select, text, update,
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
        # create_all 은 기존 테이블의 새 컬럼을 추가하지 않는다. 관리 자산 수정 잠금은 이전
        # SQLite/PostgreSQL 데이터베이스에도 기본 revision 1로 적용한다.
        with engine.begin() as c:
            if "assets" in inspect(c).get_table_names():
                columns = {column["name"] for column in inspect(c).get_columns("assets")}
                if "revision" not in columns:
                    c.execute(text("ALTER TABLE assets ADD COLUMN revision INTEGER NOT NULL DEFAULT 1"))
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

    def record_source_results(self, host_id: str, collected: Iterable[str], errors: dict[str, str], at: str) -> None:
        t = S.host_source_freshness
        if self._engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as dialect_insert
        else:
            from sqlalchemy.dialects.sqlite import insert as dialect_insert
        successes = set(collected)
        with self._conn(write=True) as c:
            for source in sorted(successes | set(errors)):
                if source in successes:
                    stmt = dialect_insert(t).values(host_id=host_id, source=source, last_success_at=at,
                        last_attempt_at=at, state="ok", last_error="")
                    updates = {"last_success_at": at, "last_attempt_at": at, "state": "ok", "last_error": ""}
                else:
                    stmt = dialect_insert(t).values(host_id=host_id, source=source, last_success_at=None,
                        last_attempt_at=at, state="failed", last_error=errors[source])
                    updates = {"last_attempt_at": at, "state": "failed", "last_error": errors[source]}
                c.execute(stmt.on_conflict_do_update(index_elements=[t.c.host_id, t.c.source], set_=updates))

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
        for t in (S.change_events, S.host_tags, S.host_sources, S.host_source_freshness, S.installed_packages, S.host_addresses,
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
            freshness = [dict(r) for r in c.execute(select(S.host_source_freshness).where(
                S.host_source_freshness.c.host_id == host_id).order_by(S.host_source_freshness.c.source)).mappings()]
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
            "source_freshness": freshness,
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
                    since: str | None = None, limit: int | None = 100, offset: int = 0) -> list[dict[str, Any]]:
        e, h = S.change_events, S.hosts
        q = select(e, h.c.hostname).select_from(e.join(h, h.c.host_id == e.c.host_id)).order_by(e.c.id.desc())
        if host_id:
            q = q.where(e.c.host_id == host_id)
        if event_type:
            q = q.where(e.c.event_type == event_type)
        if since:
            q = q.where(e.c.occurred_at >= since)
        if limit is not None:
            q = q.limit(limit)
        if offset:
            q = q.offset(offset)
        with self._conn() as c:
            rows = c.execute(q).mappings().all()
        out = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"])
            out.append(d)
        return out

    def count_events(self, host_id: str | None = None, event_type: str | None = None,
                     since: str | None = None) -> int:
        e = S.change_events
        stmt = select(func.count()).select_from(e)
        if host_id:
            stmt = stmt.where(e.c.host_id == host_id)
        if event_type:
            stmt = stmt.where(e.c.event_type == event_type)
        if since:
            stmt = stmt.where(e.c.occurred_at >= since)
        with self._conn() as c:
            return int(c.execute(stmt).scalar_one())

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

    def update_asset(self, asset_id: int, values: dict[str, Any], at: str, expected_revision: int | None = None) -> bool:
        with self.transaction(), self._conn(write=True) as c:
            where = S.assets.c.id == asset_id
            update_values = {**self._asset_values(values), "updated_at": at}
            if expected_revision is not None:
                where = and_(where, S.assets.c.revision == expected_revision)
                update_values["revision"] = expected_revision + 1
            else:  # 구형 클라이언트와의 호환 쓰기도 revision 을 증가시켜 열린 폼을 무효화한다.
                update_values["revision"] = S.assets.c.revision + 1
            res = c.execute(update(S.assets).where(where).values(**update_values))
            if res.rowcount == 0 and expected_revision is not None:
                if c.execute(select(S.assets.c.id).where(S.assets.c.id == asset_id)).first():
                    raise ConflictError("asset revision changed")
            return res.rowcount > 0

    def delete_asset(self, asset_id: int) -> bool:
        with self.transaction(), self._conn(write=True) as c:
            return c.execute(delete(S.assets).where(S.assets.c.id == asset_id)).rowcount > 0

    # --- 업무용 SW 분류·승인 요청 ---------------------------------------
    @staticmethod
    def _software_key(source: str, name: str, arch: str) -> Any:
        p, m = S.installed_packages, S.software_classifications
        return and_(m.c.source == p.c.source, m.c.name == p.c.name, m.c.arch == p.c.arch)

    def list_software_products(self, q: str = "", category: str | None = None,
                               offset: int = 0, limit: int = 100) -> tuple[int, list[dict[str, Any]]]:
        p, m = S.installed_packages, S.software_classifications
        join = p.outerjoin(m, and_(m.c.source == p.c.source, m.c.name == p.c.name, m.c.arch == p.c.arch))
        cat = func.coalesce(m.c.category, "needs_review")
        stmt = (select(p.c.source, p.c.name, p.c.arch, cat.label("category"),
                       func.coalesce(m.c.product_name, "").label("product_name"),
                       func.coalesce(m.c.publisher, "").label("publisher"),
                       func.coalesce(m.c.evidence, "").label("classification_evidence"),
                       m.c.updated_by, m.c.updated_at, m.c.revision,
                       func.count().label("install_count"), func.count(distinct(p.c.host_id)).label("host_count"),
                       func.count(distinct(p.c.version)).label("version_count"))
                .select_from(join).group_by(p.c.source, p.c.name, p.c.arch, cat, m.c.product_name,
                                           m.c.publisher, m.c.evidence, m.c.updated_by, m.c.updated_at, m.c.revision))
        if q:
            pattern = f"%{_escape_like(q.casefold())}%"
            stmt = stmt.where(func.lower(p.c.name).like(pattern, escape="\\"))
        if category:
            stmt = stmt.where(cat == category)
        subquery = stmt.subquery()
        with self._conn() as c:
            total = int(c.execute(select(func.count()).select_from(subquery)).scalar_one())
            rows = c.execute(stmt.order_by(p.c.name, p.c.source, p.c.arch).offset(offset).limit(limit)).mappings().all()
            return total, [dict(r) for r in rows]

    def get_software_classification(self, source: str, name: str, arch: str) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(select(S.software_classifications).where(and_(
                S.software_classifications.c.source == source, S.software_classifications.c.name == name,
                S.software_classifications.c.arch == arch))).mappings().first()
        return dict(row) if row else None

    def set_software_classification(self, source: str, name: str, arch: str, values: dict[str, Any],
                                    actor_id: str, at: str, expected_revision: int | None) -> dict[str, Any]:
        t, p, ev = S.software_classifications, S.installed_packages, S.software_classification_events
        with self.transaction(), self._conn(write=True) as c:
            if c.execute(select(p.c.host_id).where(and_(p.c.source == source, p.c.name == name,
                                                         p.c.arch == arch)).limit(1)).first() is None:
                raise KeyError("software product not found")
            current = c.execute(select(t).where(and_(t.c.source == source, t.c.name == name,
                                                      t.c.arch == arch))).mappings().first()
            if current is None:
                if expected_revision is not None:
                    raise ConflictError("software classification changed")
                revision = 1
                c.execute(insert(t).values(source=source, name=name, arch=arch, **values,
                                           updated_by=actor_id, updated_at=at, revision=revision))
                old_category = None
            else:
                if expected_revision is None or current["revision"] != expected_revision:
                    raise ConflictError("software classification changed")
                revision = expected_revision + 1
                result = c.execute(update(t).where(and_(t.c.source == source, t.c.name == name, t.c.arch == arch,
                                                        t.c.revision == expected_revision)).values(
                    **values, updated_by=actor_id, updated_at=at, revision=revision))
                if result.rowcount != 1:
                    raise ConflictError("software classification changed")
                old_category = current["category"]
            c.execute(insert(ev).values(source=source, name=name, arch=arch, old_category=old_category,
                new_category=values["category"], evidence=values["evidence"], changed_by=actor_id, changed_at=at))
            return {"source": source, "name": name, "arch": arch, **values,
                    "updated_by": actor_id, "updated_at": at, "revision": revision}

    def software_classification_history(self, source: str, name: str, arch: str) -> list[dict[str, Any]]:
        e, u = S.software_classification_events, S.users
        stmt = (select(e, u.c.username.label("changed_by_name")).select_from(e.join(u, e.c.changed_by == u.c.id))
                .where(and_(e.c.source == source, e.c.name == name, e.c.arch == arch)).order_by(e.c.id.desc()))
        with self._conn() as c:
            return [dict(r) for r in c.execute(stmt).mappings()]

    def get_software_request_scope(self, user_id: str) -> list[str]:
        t = S.software_request_host_scopes
        with self._conn() as c:
            return [r[0] for r in c.execute(select(t.c.host_id).where(t.c.user_id == user_id).order_by(t.c.host_id))]

    def replace_software_request_scope(self, user_id: str, host_ids: list[str], actor_id: str, at: str) -> None:
        t, events = S.software_request_host_scopes, S.software_request_scope_events
        with self.transaction(), self._conn(write=True) as c:
            old = [r[0] for r in c.execute(select(t.c.host_id).where(t.c.user_id == user_id).order_by(t.c.host_id))]
            c.execute(delete(t).where(t.c.user_id == user_id))
            if host_ids:
                c.execute(insert(t), [dict(user_id=user_id, host_id=h, granted_by=actor_id, granted_at=at) for h in host_ids])
            if old != sorted(host_ids):
                c.execute(insert(events).values(user_id=user_id, actor_id=actor_id,
                    old_host_ids=json.dumps(old), new_host_ids=json.dumps(sorted(host_ids)), occurred_at=at))

    def software_request_scope_history(self, user_id: str) -> list[dict[str, Any]]:
        e = S.software_request_scope_events
        actor = S.users.alias("actor")
        stmt = (select(e, actor.c.username.label("actor_name")).select_from(
            e.join(actor, actor.c.id == e.c.actor_id)).where(e.c.user_id == user_id).order_by(e.c.id.desc()))
        with self._conn() as c:
            rows = c.execute(stmt).mappings().all()
            return [{**dict(row), "old_host_ids": json.loads(row["old_host_ids"]),
                     "new_host_ids": json.loads(row["new_host_ids"])} for row in rows]

    def software_product_installed(self, source: str, name: str, arch: str, version: str, host_ids: list[str]) -> bool:
        if not host_ids:
            return False
        p = S.installed_packages
        with self._conn() as c:
            rows = c.execute(select(p.c.host_id).distinct().where(and_(p.c.source == source, p.c.name == name,
                p.c.arch == arch, p.c.version == version, p.c.host_id.in_(host_ids)))).all()
        return {r[0] for r in rows} == set(host_ids)

    def create_software_request(self, values: dict[str, Any], host_ids: list[str], actor_id: str, at: str) -> int:
        t, targets, events, a, p = (S.software_requests, S.software_request_hosts, S.software_request_events,
                                     S.software_approvals, S.installed_packages)
        statuses = ("submitted", "reviewing", "needs_changes")
        with self.transaction(), self._conn(write=True) as c:
            duplicate = c.execute(select(t.c.id).select_from(t.join(targets, targets.c.request_id == t.c.id)).where(and_(
                t.c.source == values["source"], t.c.name == values["name"], t.c.arch == values["arch"],
                t.c.version == values["version"], t.c.status.in_(statuses), targets.c.host_id.in_(host_ids))).limit(1)).first()
            if duplicate:
                raise ConflictError(f"overlapping request:{duplicate[0]}")
            approved = c.execute(select(a.c.id, a.c.request_id).where(and_(a.c.source == values["source"],
                a.c.name == values["name"], a.c.arch == values["arch"], a.c.version == values["version"],
                a.c.host_id.in_(host_ids), a.c.state == "active", a.c.valid_until >= at)).limit(1)).first()
            if approved:
                raise ConflictError(f"already approved:{approved[1]}")
            for host_id in host_ids:
                present = c.execute(select(p.c.host_id).where(and_(p.c.source == values["source"], p.c.name == values["name"],
                    p.c.arch == values["arch"], p.c.version == values["version"], p.c.host_id == host_id)).limit(1)).first()
                if not present:
                    raise ValueError(f"software not installed:{host_id}")
            res = c.execute(insert(t).values(**values, status="submitted", revision=1, created_at=at, updated_at=at))
            request_id = int(res.inserted_primary_key[0])
            c.execute(insert(targets), [{"request_id": request_id, "host_id": host_id} for host_id in host_ids])
            c.execute(insert(events).values(request_id=request_id, actor_id=actor_id, action="submit",
                from_status=None, to_status="submitted", reason="", detail=json.dumps({"host_ids": host_ids}, sort_keys=True),
                revision=1, occurred_at=at))
            return request_id

    def list_software_requests(self, *, requester_id: str | None = None, status: str | None = None, q: str = "",
                               unassigned: bool = False, overdue_before: str | None = None,
                               offset: int = 0, limit: int = 50) -> tuple[int, list[dict[str, Any]]]:
        t, u, assignee = S.software_requests, S.users.alias("requester"), S.users.alias("assignee")
        stmt = (select(t, u.c.username.label("requester_name"), assignee.c.username.label("assignee_name"))
                .select_from(t.join(u, t.c.requester_id == u.c.id).outerjoin(assignee, t.c.assignee_id == assignee.c.id)))
        if requester_id:
            stmt = stmt.where(t.c.requester_id == requester_id)
        if status:
            stmt = stmt.where(t.c.status == status)
        if unassigned:
            stmt = stmt.where(t.c.assignee_id.is_(None))
        if overdue_before:
            stmt = stmt.where(t.c.due_at.is_not(None), t.c.due_at < overdue_before,
                              t.c.status.in_(("submitted", "reviewing", "needs_changes")))
        needle = q.strip().casefold()
        if needle:
            stmt = stmt.where(or_(func.lower(t.c.name).like(f"%{_escape_like(needle)}%", escape="\\"),
                                  func.lower(t.c.product_name).like(f"%{_escape_like(needle)}%", escape="\\"),
                                  func.lower(u.c.username).like(f"%{_escape_like(needle)}%", escape="\\"),
                                  cast(t.c.id, String).like(f"%{_escape_like(needle.removeprefix('sw-'))}%", escape="\\")))
        subquery = stmt.with_only_columns(t.c.id).order_by(None).subquery()
        with self._conn() as c:
            total = int(c.execute(select(func.count()).select_from(subquery)).scalar_one())
            rows = c.execute(stmt.order_by(t.c.created_at.desc(), t.c.id.desc()).offset(offset).limit(limit)).mappings().all()
            result = []
            for row in rows:
                data = dict(row)
                data["request_no"] = f"SW-{data['id']:06d}"
                count = c.execute(select(func.count()).select_from(S.software_request_hosts).where(
                    S.software_request_hosts.c.request_id == data["id"])).scalar_one()
                data["host_count"] = int(count)
                result.append(data)
            return total, result

    def get_software_request(self, request_id: int) -> dict[str, Any] | None:
        t, requester, assignee = S.software_requests, S.users.alias("requester"), S.users.alias("assignee")
        stmt = (select(t, requester.c.username.label("requester_name"), assignee.c.username.label("assignee_name"))
                .select_from(t.join(requester, t.c.requester_id == requester.c.id)
                             .outerjoin(assignee, t.c.assignee_id == assignee.c.id)).where(t.c.id == request_id))
        with self._conn() as c:
            row = c.execute(stmt).mappings().first()
            if row is None:
                return None
            data = dict(row)
            data["request_no"] = f"SW-{data['id']:06d}"
            targets = c.execute(select(S.software_request_hosts.c.host_id, S.hosts.c.hostname)
                .select_from(S.software_request_hosts.join(S.hosts, S.hosts.c.host_id == S.software_request_hosts.c.host_id))
                .where(S.software_request_hosts.c.request_id == request_id).order_by(S.hosts.c.hostname)).mappings().all()
            data["hosts"] = [dict(h) for h in targets]
            events = c.execute(select(S.software_request_events, S.users.c.username.label("actor_name"))
                .select_from(S.software_request_events.join(S.users, S.users.c.id == S.software_request_events.c.actor_id))
                .where(S.software_request_events.c.request_id == request_id).order_by(S.software_request_events.c.id)).mappings().all()
            data["history"] = [{**dict(e), "detail": json.loads(e["detail"])} for e in events]
            approvals = c.execute(select(S.software_approvals, S.users.c.username.label("decided_by_name"))
                .select_from(S.software_approvals.join(S.users, S.users.c.id == S.software_approvals.c.decided_by))
                .where(S.software_approvals.c.request_id == request_id).order_by(S.software_approvals.c.id)).mappings().all()
            data["approvals"] = [dict(a) for a in approvals]
            return data

    def update_software_request(self, request_id: int, expected_revision: int, values: dict[str, Any],
                                actor_id: str, action: str, reason: str, detail: dict[str, Any],
                                at: str, approvals: list[dict[str, Any]] | None = None,
                                revoke_approvals: bool = False) -> None:
        t, events, a = S.software_requests, S.software_request_events, S.software_approvals
        with self.transaction(), self._conn(write=True) as c:
            before = c.execute(select(t.c.status).where(and_(t.c.id == request_id,
                t.c.revision == expected_revision))).first()
            if before is None:
                raise ConflictError("software request revision changed")
            result = c.execute(update(t).where(and_(t.c.id == request_id, t.c.revision == expected_revision)).values(
                **values, updated_at=at, revision=expected_revision + 1))
            if result.rowcount != 1:
                raise ConflictError("software request revision changed")
            after_status = values.get("status", before[0])
            c.execute(insert(events).values(request_id=request_id, actor_id=actor_id, action=action,
                from_status=before[0], to_status=after_status, reason=reason,
                detail=json.dumps(detail, sort_keys=True), revision=expected_revision + 1, occurred_at=at))
            if approvals:
                c.execute(insert(a), approvals)
            if revoke_approvals:
                c.execute(update(a).where(and_(a.c.request_id == request_id, a.c.state == "active")).values(
                    state="revoked", ended_at=at, end_reason=reason))

    # --- CVE / KEV -------------------------------------------------------
    def _vulnerability_query(self, q: str, kev_only: bool, impact_status: str | None, host_id: str | None = None):
        cve, kev = S.vulnerability_cves, S.kev_entries
        m, v, p = S.vulnerability_product_matches, S.vulnerability_match_versions, S.installed_packages
        mapped_installs = (select(p.c.host_id).select_from(m.join(p, and_(p.c.source == m.c.source,
                p.c.name == m.c.name, p.c.arch == m.c.arch)))
            .where(and_(m.c.cve_id == cve.c.cve_id, p.c.host_id == host_id))) if host_id else None
        has_mapped_install = exists(mapped_installs) if mapped_installs is not None else None
        confirmed = (select(p.c.host_id).select_from(m.join(v, and_(v.c.cve_id == m.c.cve_id,
                v.c.source == m.c.source, v.c.name == m.c.name, v.c.arch == m.c.arch))
                .join(p, and_(p.c.source == v.c.source, p.c.name == v.c.name, p.c.arch == v.c.arch,
                              p.c.version == v.c.version)))
            .where(and_(m.c.cve_id == cve.c.cve_id, m.c.status == "affected_confirmed",
                        *(([p.c.host_id == host_id]) if host_id else []))))
        has_confirmed = exists(confirmed)
        if host_id:
            host_mapping = m.join(p, and_(p.c.source == m.c.source, p.c.name == m.c.name, p.c.arch == m.c.arch))
            host_product = and_(m.c.cve_id == cve.c.cve_id, p.c.host_id == host_id)
            has_review = exists(select(m.c.cve_id).select_from(host_mapping).where(and_(host_product, m.c.status == "needs_review")))
            has_mapping = has_mapped_install
            has_non_negative_mapping = exists(select(m.c.cve_id).select_from(host_mapping).where(and_(host_product, m.c.status != "not_affected")))
        else:
            has_review = exists(select(m.c.cve_id).where(and_(m.c.cve_id == cve.c.cve_id, m.c.status == "needs_review")))
            has_mapping = exists(select(m.c.cve_id).where(m.c.cve_id == cve.c.cve_id))
            has_non_negative_mapping = exists(select(m.c.cve_id).where(and_(m.c.cve_id == cve.c.cve_id,
                m.c.status != "not_affected")))
        impact = case((has_confirmed, "confirmed"), (has_review, "needs_review"),
                      (and_(has_mapping, ~has_non_negative_mapping), "not_affected"),
                      (has_mapping, "no_observed_match"), else_="not_assessed").label("impact_status")
        host_count = (select(func.count(distinct(p.c.host_id))).select_from(m.join(v, and_(v.c.cve_id == m.c.cve_id,
                v.c.source == m.c.source, v.c.name == m.c.name, v.c.arch == m.c.arch))
                .join(p, and_(p.c.source == v.c.source, p.c.name == v.c.name, p.c.arch == v.c.arch,
                              p.c.version == v.c.version)))
            .where(and_(m.c.cve_id == cve.c.cve_id, m.c.status == "affected_confirmed")).scalar_subquery().label("host_count"))
        install_count = (select(func.count()).select_from(confirmed.subquery()).scalar_subquery().label("install_count"))
        stmt = select(cve.c.cve_id, cve.c.description, cve.c.published_at, cve.c.modified_at, cve.c.cvss_score,
                      cve.c.cvss_severity, cve.c.nvd_status, kev.c.vendor, kev.c.product, kev.c.date_added,
                      kev.c.due_date, kev.c.ransomware_use, kev.c.catalog_version, impact,
                      host_count, install_count).select_from(cve.outerjoin(kev, kev.c.cve_id == cve.c.cve_id)
                      )
        if q:
            pattern = f"%{_escape_like(q.casefold())}%"
            stmt = stmt.where(or_(func.lower(cve.c.cve_id).like(pattern, escape="\\"),
                                  func.lower(cve.c.description).like(pattern, escape="\\"),
                                  func.lower(kev.c.vendor).like(pattern, escape="\\"),
                                  func.lower(kev.c.product).like(pattern, escape="\\")))
        if kev_only:
            stmt = stmt.where(kev.c.cve_id.is_not(None))
        if has_mapped_install is not None:
            stmt = stmt.where(has_mapped_install)
        if impact_status:
            stmt = stmt.where(impact == impact_status)
        return stmt, cve, kev

    def list_vulnerabilities(self, *, q: str = "", kev_only: bool = False, impact_status: str | None = None,
                             offset: int = 0, limit: int = 50, host_id: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        stmt, cve, kev = self._vulnerability_query(q, kev_only, impact_status, host_id)
        total_query = stmt.with_only_columns(cve.c.cve_id).order_by(None).subquery()
        priority = case((kev.c.cve_id.is_not(None), 0), else_=1)
        with self._conn() as c:
            total = int(c.execute(select(func.count()).select_from(total_query)).scalar_one())
            rows = c.execute(stmt.order_by(priority, kev.c.date_added.desc(), cve.c.cvss_score.desc(),
                                           cve.c.cve_id).offset(offset).limit(limit)).mappings().all()
            return total, [dict(r) for r in rows]

    def vulnerability_detail(self, cve_id: str) -> dict[str, Any] | None:
        c, k, m, v, p, h = (S.vulnerability_cves, S.kev_entries, S.vulnerability_product_matches,
                            S.vulnerability_match_versions, S.installed_packages, S.hosts)
        with self._conn() as conn:
            row = conn.execute(select(c).where(c.c.cve_id == cve_id)).mappings().first()
            if row is None:
                return None
            data = dict(row)
            for key in ("cvss_metrics", "references", "configurations"):
                data[key] = json.loads(data[key] or ("{}" if key == "cvss_metrics" else "[]"))
            kev = conn.execute(select(k).where(k.c.cve_id == cve_id)).mappings().first()
            data["kev"] = dict(kev) if kev else None
            maps = conn.execute(select(m).where(m.c.cve_id == cve_id).order_by(m.c.name, m.c.source)).mappings().all()
            details = []
            for mapping in maps:
                item = dict(mapping)
                versions = [r[0] for r in conn.execute(select(v.c.version).where(and_(v.c.cve_id == cve_id,
                    v.c.source == item["source"], v.c.name == item["name"], v.c.arch == item["arch"])).order_by(v.c.version))]
                item["affected_versions"] = versions
                stmt = (select(p.c.host_id, h.c.hostname, p.c.source, p.c.name, p.c.arch, p.c.version,
                               S.assets.c.id.label("asset_id"), S.assets.c.asset_no.label("asset_no"))
                        .select_from(p.join(h, h.c.host_id == p.c.host_id).outerjoin(S.assets, S.assets.c.host_id == p.c.host_id))
                        .where(and_(p.c.source == item["source"], p.c.name == item["name"], p.c.arch == item["arch"])))
                if item["status"] == "affected_confirmed" and versions:
                    stmt = stmt.where(p.c.version.in_(versions))
                item["installations"] = [dict(r) for r in conn.execute(stmt.order_by(h.c.hostname, p.c.version)).mappings()]
                details.append(item)
            data["matches"] = details
            data["feed_status"] = [dict(r) for r in conn.execute(select(S.vulnerability_feed_status).order_by(
                S.vulnerability_feed_status.c.source)).mappings()]
            return data

    def update_vulnerability_match(self, cve_id: str, source: str, name: str, arch: str,
                                   values: dict[str, Any], actor_id: str, at: str,
                                   expected_revision: int | None) -> dict[str, Any]:
        m, ev, v, cve, p = (S.vulnerability_product_matches, S.vulnerability_match_events,
                            S.vulnerability_match_versions, S.vulnerability_cves, S.installed_packages)
        with self.transaction(), self._conn(write=True) as conn:
            if conn.execute(select(cve.c.cve_id).where(cve.c.cve_id == cve_id)).first() is None:
                raise KeyError("CVE not found")
            if conn.execute(select(p.c.host_id).where(and_(p.c.source == source, p.c.name == name,
                    p.c.arch == arch)).limit(1)).first() is None:
                raise KeyError("software product not found")
            current = conn.execute(select(m).where(and_(m.c.cve_id == cve_id, m.c.source == source,
                m.c.name == name, m.c.arch == arch))).mappings().first()
            if current is None:
                if expected_revision is not None:
                    raise ConflictError("vulnerability match changed")
                revision, old = 1, None
                conn.execute(insert(m).values(cve_id=cve_id, source=source, name=name, arch=arch,
                    **{k: value for k, value in values.items() if k != "affected_versions"},
                    updated_by=actor_id, updated_at=at, revision=revision))
            else:
                if expected_revision is None or current["revision"] != expected_revision:
                    raise ConflictError("vulnerability match changed")
                revision, old = expected_revision + 1, current["status"]
                result = conn.execute(update(m).where(and_(m.c.cve_id == cve_id, m.c.source == source,
                    m.c.name == name, m.c.arch == arch, m.c.revision == expected_revision)).values(
                    **{k: value for k, value in values.items() if k != "affected_versions"},
                    updated_by=actor_id, updated_at=at, revision=revision))
                if result.rowcount != 1:
                    raise ConflictError("vulnerability match changed")
            conn.execute(delete(v).where(and_(v.c.cve_id == cve_id, v.c.source == source,
                v.c.name == name, v.c.arch == arch)))
            versions = values.get("affected_versions", [])
            if versions:
                conn.execute(insert(v), [dict(cve_id=cve_id, source=source, name=name, arch=arch, version=version)
                                         for version in versions])
            conn.execute(insert(ev).values(cve_id=cve_id, source=source, name=name, arch=arch,
                old_status=old, new_status=values["status"], evidence=values["evidence"],
                changed_by=actor_id, changed_at=at))
            return {"cve_id": cve_id, "source": source, "name": name, "arch": arch, **values,
                    "updated_by": actor_id, "updated_at": at, "revision": revision}

    def vulnerability_feed_status(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(select(S.vulnerability_feed_status).order_by(
                S.vulnerability_feed_status.c.source)).mappings()]

    def replace_cisa_kev(self, values: list[dict[str, Any]], catalog_version: str, fetched_at: str) -> None:
        k, cve = S.kev_entries, S.vulnerability_cves
        with self.transaction(), self._conn(write=True) as conn:
            conn.execute(delete(k))
            for value in values:
                cid = value["cve_id"]
                current = conn.execute(select(cve.c.cve_id).where(cve.c.cve_id == cid)).first()
                if current:
                    conn.execute(update(cve).where(cve.c.cve_id == cid).values(
                        description=value["description"], modified_at=value.get("modified_at"),
                        references=json.dumps(value.get("references", []), sort_keys=True)))
                else:
                    conn.execute(insert(cve).values(cve_id=cid, description=value["description"], published_at=None,
                        modified_at=value.get("modified_at"), cvss_score=None, cvss_severity=None,
                        cvss_metrics="{}", nvd_status="", references=json.dumps(value.get("references", []), sort_keys=True),
                        configurations="[]", nvd_fetched_at=None))
                conn.execute(insert(k).values(cve_id=cid, vendor=value["vendor"], product=value["product"],
                    vulnerability_name=value["vulnerability_name"], date_added=value["date_added"], due_date=value["due_date"],
                    ransomware_use=value["ransomware_use"], required_action=value["required_action"], notes=value["notes"],
                    catalog_version=catalog_version, fetched_at=fetched_at))

    def upsert_nvd_vulnerabilities(self, values: list[dict[str, Any]], fetched_at: str) -> None:
        t = S.vulnerability_cves
        with self.transaction(), self._conn(write=True) as conn:
            for value in values:
                data = {**value, "cvss_metrics": json.dumps(value["cvss_metrics"], sort_keys=True),
                        "references": json.dumps(value["references"], sort_keys=True),
                        "configurations": json.dumps(value["configurations"], sort_keys=True),
                        "nvd_fetched_at": fetched_at}
                if conn.execute(select(t.c.cve_id).where(t.c.cve_id == value["cve_id"])).first():
                    conn.execute(update(t).where(t.c.cve_id == value["cve_id"]).values(**{k: v for k, v in data.items() if k != "cve_id"}))
                else:
                    conn.execute(insert(t).values(**data))

    def record_vulnerability_feed(self, source: str, state: str, attempted_at: str, succeeded_at: str | None,
                                  error: str, data_version: str, records: int) -> None:
        t = S.vulnerability_feed_status
        with self.transaction(), self._conn(write=True) as conn:
            current = conn.execute(select(t).where(t.c.source == source)).mappings().first()
            if current is None:
                values = dict(source=source, state=state, last_success_at=succeeded_at,
                    last_attempt_at=attempted_at, last_error=error, data_version=data_version, records=records)
                conn.execute(insert(t).values(**values))
            elif succeeded_at:
                conn.execute(update(t).where(t.c.source == source).values(state=state,
                    last_success_at=succeeded_at, last_attempt_at=attempted_at, last_error=error,
                    data_version=data_version, records=records))
            elif state == "partial":
                conn.execute(update(t).where(t.c.source == source).values(state=state,
                    last_attempt_at=attempted_at, last_error=error, data_version=data_version, records=records))
            else:
                # 실패 시 이전 성공 데이터와 버전은 보존한다.
                conn.execute(update(t).where(t.c.source == source).values(state="failed",
                    last_attempt_at=attempted_at, last_error=error))


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
