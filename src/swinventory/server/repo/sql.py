"""SQLAlchemy Core 구현. 같은 코드가 SQLite(개발/테스트)와 PostgreSQL 에서 동작한다."""
from __future__ import annotations

import json
import re
import threading
from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterable, Iterator

from sqlalchemy import (
    Connection, Engine, Float, Numeric, String, Text, and_, case, cast, create_engine, delete, distinct, event, exists, func, insert, inspect, or_, select, text, update,
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
        # create_all 은 기존 테이블의 새 컬럼을 추가하지 않는다. 관리 자산 잠금·담당자 열은
        # 이전 SQLite/PostgreSQL DB 에 값 보존하며 반복 안전하게 추가한다.
        with engine.begin() as c:
            self._migrate_assets(c)
            self._migrate_vulnerability_feed_data_version(c)
            self._migrate_removed_license_evidence(c)
        # 첫 행 생성도 여러 프로세스에서 멱등이다. 아래 UPDATE 가 DB 간 공통 쓰기 잠금이다.
        if engine.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as guard_insert
        else:
            from sqlalchemy.dialects.sqlite import insert as guard_insert
        with engine.begin() as c:
            c.execute(guard_insert(S.auth_guard).values(id=1, revision=0).on_conflict_do_nothing())

    @staticmethod
    def _migrate_assets(conn: Connection) -> None:
        """기존 자산 행을 유지하며 누락된 revision·담당자 컬럼을 추가한다."""
        inspector = inspect(conn)
        if "assets" not in inspector.get_table_names():
            return
        columns = {column["name"] for column in inspector.get_columns("assets")}
        if "revision" not in columns:
            conn.execute(text("ALTER TABLE assets ADD COLUMN revision INTEGER NOT NULL DEFAULT 1"))
        if "primary_owner" not in columns:
            conn.execute(text("ALTER TABLE assets ADD COLUMN primary_owner VARCHAR(128) NOT NULL DEFAULT ''"))
        if "secondary_owner" not in columns:
            conn.execute(text("ALTER TABLE assets ADD COLUMN secondary_owner VARCHAR(128) NOT NULL DEFAULT ''"))

    @staticmethod
    def _migrate_vulnerability_feed_data_version(conn: Connection) -> None:
        """기존 PostgreSQL 의 VARCHAR(64) 를 무손실 TEXT 로 넓힌다.

        SQLite 는 VARCHAR(n) 길이를 제한하지 않아 기존 파일도 긴 커서를 저장할 수
        있으므로 재작성하지 않는다. PostgreSQL 에서만 실제 bounded 컬럼일 때 ALTER 한다.
        """
        if conn.dialect.name != "postgresql":
            return
        inspector = inspect(conn)
        if "vulnerability_feed_status" not in inspector.get_table_names():
            return
        columns = {column["name"]: column for column in inspector.get_columns("vulnerability_feed_status")}
        column = columns.get("data_version")
        if column is None:
            return
        column_type = column["type"]
        if isinstance(column_type, String) and not isinstance(column_type, Text) and column_type.length is not None:
            conn.execute(text("ALTER TABLE vulnerability_feed_status ALTER COLUMN data_version TYPE TEXT"))

    @staticmethod
    def _migrate_removed_license_evidence(conn: Connection) -> None:
        """기존 두 요청 테이블에서 사용하지 않는 근거 열만 제거한다."""
        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        for table_name in ("software_requests", "software_request_batches"):
            if table_name not in tables:
                continue
            columns = {column["name"] for column in inspector.get_columns(table_name)}
            if "license_evidence" in columns:
                conn.execute(text(f"ALTER TABLE {table_name} DROP COLUMN license_evidence"))

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
    _ASSET_FIELDS = ("asset_no", "kind", "serial", "hostname", "domain", "ip", "parent_asset_id", "host_id", "note",
                     "primary_owner", "secondary_owner")

    def _asset_values(self, values: dict[str, Any]) -> dict[str, Any]:
        # 구형 저장소 호출자도 담당자 없이 자산을 저장할 수 있다.
        out = {k: values.get(k, "") if k in {"primary_owner", "secondary_owner"} else values[k] for k in self._ASSET_FIELDS}
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

    def host_software_summary(self, host_id: str, at: str, *, requester_id: str | None = None,
                              include_request_state: bool = False) -> list[dict[str, Any]]:
        """호스트의 현재 설치를 정확한 제품·버전 단위 승인/영향 상태로 투영한다."""
        p, m, v = S.installed_packages, S.vulnerability_product_matches, S.vulnerability_match_versions
        category = func.coalesce(S.software_classifications.c.category, "needs_review")
        confirmed_join = m.join(v, and_(v.c.cve_id == m.c.cve_id, v.c.source == m.c.source,
                                        v.c.name == m.c.name, v.c.arch == m.c.arch))
        confirmed = exists(select(v.c.cve_id).select_from(confirmed_join).where(and_(
            m.c.source == p.c.source, m.c.name == p.c.name, m.c.arch == p.c.arch,
            v.c.version == p.c.version, m.c.status == "affected_confirmed")))
        review = exists(select(m.c.cve_id).where(and_(m.c.source == p.c.source, m.c.name == p.c.name,
            m.c.arch == p.c.arch, m.c.status == "needs_review")))
        mapped = exists(select(m.c.cve_id).where(and_(m.c.source == p.c.source, m.c.name == p.c.name,
            m.c.arch == p.c.arch)))
        non_negative = exists(select(m.c.cve_id).where(and_(m.c.source == p.c.source, m.c.name == p.c.name,
            m.c.arch == p.c.arch, m.c.status != "not_affected")))
        impact = case((confirmed, "confirmed"), (review, "needs_review"),
                      (and_(mapped, ~non_negative), "not_affected"),
                      (mapped, "no_observed_match"), else_="not_assessed").label("impact_status")
        impact_count = (select(func.count(distinct(m.c.cve_id))).where(and_(
            m.c.source == p.c.source, m.c.name == p.c.name, m.c.arch == p.c.arch))
            .correlate(p).scalar_subquery().label("impact_cve_count"))
        approval = S.software_approvals
        active_approval = exists(select(approval.c.id).where(and_(
            approval.c.host_id == p.c.host_id, approval.c.source == p.c.source, approval.c.name == p.c.name,
            approval.c.arch == p.c.arch, approval.c.version == p.c.version, approval.c.state == "active",
            approval.c.valid_from <= at, approval.c.valid_until >= at, approval.c.ended_at.is_(None))))
        values = [p.c.source, p.c.name, p.c.arch, p.c.version, category.label("category"),
                  func.coalesce(S.software_classifications.c.product_name, "").label("product_name"),
                  func.coalesce(S.software_classifications.c.publisher, "").label("publisher"),
                  case((category == "business_app", case((active_approval, "active"), else_="not_active")),
                       (category.in_(("os_package", "development_dependency")), "not_required"),
                       else_="classification_required").label("approval_status"), impact, impact_count]
        from_clause = p.outerjoin(S.software_classifications, and_(
            S.software_classifications.c.source == p.c.source,
            S.software_classifications.c.name == p.c.name,
            S.software_classifications.c.arch == p.c.arch))
        if include_request_state:
            request, target = S.software_requests, S.software_request_hosts
            request_scope = request.join(target, target.c.request_id == request.c.id)
            request_predicates = [target.c.host_id == p.c.host_id, request.c.source == p.c.source,
                request.c.name == p.c.name, request.c.arch == p.c.arch, request.c.version == p.c.version]
            if requester_id is not None:
                request_predicates.append(request.c.requester_id == requester_id)
            latest_status = (select(request.c.status).select_from(request_scope).where(and_(*request_predicates))
                             .order_by(request.c.created_at.desc(), request.c.id.desc()).limit(1)
                             .correlate(p).scalar_subquery().label("request_status"))
            latest_id = (select(request.c.id).select_from(request_scope).where(and_(*request_predicates))
                         .order_by(request.c.created_at.desc(), request.c.id.desc()).limit(1)
                         .correlate(p).scalar_subquery().label("request_id"))
            batch_item = S.software_request_batch_items
            latest_batch_id = (select(batch_item.c.batch_id).where(batch_item.c.request_id == latest_id)
                              .limit(1).correlate(p).scalar_subquery().label("batch_id"))
            values.extend([latest_status, latest_id, latest_batch_id])
        stmt = select(*values).select_from(from_clause).where(p.c.host_id == host_id)
        with self._conn() as conn:
            rows = [dict(row) for row in conn.execute(stmt).mappings()]
        for row in rows:
            if "request_id" in row:
                row["request_no"] = f"SW-{row['request_id']:06d}" if row["request_id"] is not None else None
        rows.sort(key=lambda row: (row["name"].casefold(), row["source"], row["arch"], row["version"]))
        return rows

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
                raise ConflictError("overlapping request")
            approved = c.execute(select(a.c.id, a.c.request_id).where(and_(a.c.source == values["source"],
                a.c.name == values["name"], a.c.arch == values["arch"], a.c.version == values["version"],
                a.c.host_id.in_(host_ids), a.c.state == "active", a.c.valid_until >= at)).limit(1)).first()
            if approved:
                raise ConflictError("already approved")
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

    @staticmethod
    def _request_impact_expr(request):
        """요청의 정확한 제품·버전 키에 대한 CVE 영향 판정 SQL 식."""
        m, v = S.vulnerability_product_matches, S.vulnerability_match_versions
        mapped = select(m.c.cve_id).where(and_(m.c.source == request.c.source,
            m.c.name == request.c.name, m.c.arch == request.c.arch)).correlate(request)
        confirmed_from = m.join(v, and_(v.c.cve_id == m.c.cve_id, v.c.source == m.c.source,
            v.c.name == m.c.name, v.c.arch == m.c.arch))
        confirmed = exists(select(m.c.cve_id).select_from(confirmed_from).where(and_(
            m.c.source == request.c.source, m.c.name == request.c.name, m.c.arch == request.c.arch,
            m.c.status == "affected_confirmed", v.c.version == request.c.version)).correlate(request))
        review = exists(select(m.c.cve_id).where(and_(m.c.source == request.c.source,
            m.c.name == request.c.name, m.c.arch == request.c.arch, m.c.status == "needs_review")).correlate(request))
        all_not_affected = exists(select(m.c.cve_id).where(and_(m.c.source == request.c.source,
            m.c.name == request.c.name, m.c.arch == request.c.arch, m.c.status != "not_affected")).correlate(request))
        return case((confirmed, "confirmed"), (review, "needs_review"),
                    (~exists(mapped), "not_assessed"), (~all_not_affected, "not_affected"),
                    else_="no_observed_match")

    def create_software_request_batch(self, batch: dict[str, Any], items: list[dict[str, Any]],
                                      actor_id: str, at: str) -> int:
        """호스트 단위 child 요청들을 모두 검증한 뒤 하나의 트랜잭션으로 생성한다."""
        if not items or len(items) > 100:
            raise ValueError("요청 항목 수를 확인하세요.")
        keys = [(item["source"], item["name"], item["arch"], item["version"]) for item in items]
        if len(set(keys)) != len(keys):
            raise ValueError("중복 소프트웨어 항목이 있습니다.")
        t, targets, events = S.software_requests, S.software_request_hosts, S.software_request_events
        batches, batch_items = S.software_request_batches, S.software_request_batch_items
        classification, p, approval = S.software_classifications, S.installed_packages, S.software_approvals
        host_id = batch["host_id"]
        with self.transaction(), self._conn(write=True) as c:
            if c.execute(select(S.hosts.c.host_id).where(S.hosts.c.host_id == host_id)).first() is None:
                raise ValueError("등록된 호스트가 아닙니다.")
            # Check every selected product before inserting the batch, so a rejected selection
            # cannot leave a parent or an earlier child behind.
            for item in items:
                classified = c.execute(select(classification.c.category).where(and_(
                    classification.c.source == item["source"], classification.c.name == item["name"],
                    classification.c.arch == item["arch"]))).scalar_one_or_none()
                if classified != "business_app":
                    raise ValueError("업무용 앱으로 분류된 설치 소프트웨어만 선택할 수 있습니다.")
                present = c.execute(select(p.c.host_id).where(and_(p.c.host_id == host_id,
                    p.c.source == item["source"], p.c.name == item["name"], p.c.arch == item["arch"],
                    p.c.version == item["version"])).limit(1)).first()
                if not present:
                    raise ValueError("선택한 호스트에 지정 버전이 설치되어 있어야 합니다.")
                overlap = c.execute(select(t.c.id).select_from(t.join(targets,
                    targets.c.request_id == t.c.id)).where(and_(targets.c.host_id == host_id,
                        t.c.source == item["source"], t.c.name == item["name"], t.c.arch == item["arch"],
                        t.c.version == item["version"], t.c.status.in_(("submitted", "reviewing", "needs_changes"))))
                    .limit(1)).first()
                if overlap:
                    raise ConflictError("overlapping request")
                active = c.execute(select(approval.c.id).where(and_(approval.c.host_id == host_id,
                    approval.c.source == item["source"], approval.c.name == item["name"],
                    approval.c.arch == item["arch"], approval.c.version == item["version"],
                    approval.c.state == "active", approval.c.valid_from <= at, approval.c.valid_until >= at,
                    approval.c.ended_at.is_(None))).limit(1)).first()
                if active:
                    raise ConflictError("already approved")
            result = c.execute(insert(batches).values(requester_id=actor_id, host_id=host_id,
                purpose=batch["purpose"], created_at=at))
            batch_id = int(result.inserted_primary_key[0])
            for order, item in enumerate(items):
                product = c.execute(select(classification.c.product_name).where(and_(
                    classification.c.source == item["source"], classification.c.name == item["name"],
                    classification.c.arch == item["arch"]))).scalar_one()
                values = {"requester_id": actor_id, **item,
                    "product_name": product or item["name"], "purpose": batch["purpose"],
                    "assignee_id": None,
                    "due_at": None, "approval_until": None, "decision_reason": ""}
                inserted = c.execute(insert(t).values(**values, status="submitted", revision=1,
                    created_at=at, updated_at=at))
                request_id = int(inserted.inserted_primary_key[0])
                c.execute(insert(targets).values(request_id=request_id, host_id=host_id))
                c.execute(insert(events).values(request_id=request_id, actor_id=actor_id, action="submit",
                    from_status=None, to_status="submitted", reason="",
                    detail=json.dumps({"host_ids": [host_id], "batch_id": batch_id}, sort_keys=True),
                    revision=1, occurred_at=at))
                c.execute(insert(batch_items).values(batch_id=batch_id, request_id=request_id, item_order=order))
            return batch_id

    def _batch_impact_columns(self, request):
        return self._request_impact_expr(request).label("security_impact")

    def list_software_request_batches(self, *, requester_id: str | None, scope: str,
                                      status: str | None, host_id: str | None,
                                      security_impact: str | None, q: str,
                                      overdue_before: str | None, assignee_id: str | None,
                                      sort: str | None, direction: str,
                                      offset: int, limit: int) -> tuple[int, list[dict[str, Any]]]:
        b, bi, r = S.software_request_batches, S.software_request_batch_items, S.software_requests.alias("batch_request")
        requester, host = S.users.alias("batch_requester"), S.hosts.alias("batch_host")
        impact = self._batch_impact_columns(r)
        child = bi.join(r, r.c.id == bi.c.request_id)
        child_for_batch = lambda cond: exists(select(bi.c.request_id).select_from(child).where(
            and_(bi.c.batch_id == b.c.id, cond)).correlate(b))
        stmt = (select(b.c.id, b.c.host_id, host.c.hostname, host.c.last_seen,
                       b.c.requester_id, requester.c.username.label("requester_name"),
                       b.c.created_at, b.c.purpose)
                .select_from(b.join(requester, requester.c.id == b.c.requester_id)
                    .outerjoin(host, host.c.host_id == b.c.host_id)))
        if requester_id:
            stmt = stmt.where(b.c.requester_id == requester_id)
        if host_id:
            stmt = stmt.where(b.c.host_id == host_id)
        child_filters = []
        if status:
            child_filters.append(r.c.status == status)
        if security_impact:
            child_filters.append(impact == security_impact)
        if scope == "pending":
            child_filters.append(r.c.status.in_(("submitted", "reviewing")))
        elif scope == "assigned":
            child_filters.append(r.c.assignee_id == assignee_id if assignee_id else r.c.assignee_id.is_not(None))
        elif scope == "overdue" and overdue_before:
            child_filters.extend((r.c.due_at.is_not(None), r.c.due_at < overdue_before,
                r.c.status.in_(("submitted", "reviewing", "needs_changes"))))
        if child_filters:
            stmt = stmt.where(child_for_batch(and_(*child_filters)))
        needle = q.strip().casefold()
        if needle:
            batch_number = re.fullmatch(r"swb-([0-9]{1,20})", needle)
            if batch_number:
                number = int(batch_number.group(1))
                stmt = stmt.where(b.c.id == number if number <= 2_147_483_647 else b.c.id == -1)
            else:
                pattern = f"%{_escape_like(needle)}%"
                stmt = stmt.where(or_(func.lower(host.c.hostname).like(pattern, escape="\\"),
                    func.lower(requester.c.username).like(pattern, escape="\\"),
                    child_for_batch(and_(*(child_filters + [or_(func.lower(r.c.name).like(pattern, escape="\\"),
                        func.lower(r.c.product_name).like(pattern, escape="\\"))])))))

        # Correlated status/security counts provide sortable aggregate columns before LIMIT/OFFSET.
        status_values = ("submitted", "reviewing", "needs_changes", "approved", "rejected", "withdrawn")
        status_counts = {state: (select(func.count()).select_from(child).where(and_(
            bi.c.batch_id == b.c.id, r.c.status == state)).correlate(b).scalar_subquery()) for state in status_values}
        impact_states = ("confirmed", "needs_review", "not_affected", "no_observed_match", "not_assessed")
        impact_counts = {state: (select(func.count()).select_from(child).where(and_(
            bi.c.batch_id == b.c.id, impact == state)).correlate(b).scalar_subquery()) for state in impact_states}
        item_count = (select(func.count()).select_from(bi).where(bi.c.batch_id == b.c.id)
                      .correlate(b).scalar_subquery())
        pending_count = status_counts["submitted"] + status_counts["reviewing"]
        open_count = pending_count + status_counts["needs_changes"]
        terminal_count = status_counts["approved"] + status_counts["rejected"] + status_counts["withdrawn"]
        due_at = (select(func.min(r.c.due_at)).select_from(child).where(and_(bi.c.batch_id == b.c.id,
            r.c.due_at.is_not(None), r.c.status.in_(("submitted", "reviewing", "needs_changes"))))
            .correlate(b).scalar_subquery())
        batch_status = case(*( (status_counts[state] == item_count, state) for state in status_values), else_="mixed")
        impact_status_expr = case(*( (impact_counts[state] == item_count, state) for state in impact_states), else_="mixed")
        stmt = stmt.add_columns(item_count.label("item_count"), pending_count.label("pending_count"),
            open_count.label("open_count"), terminal_count.label("terminal_count"), due_at.label("due_at"),
            batch_status.label("status"), impact_status_expr.label("security_impact"),
            *[status_counts[state].label(f"status_{state}") for state in status_values],
            *[impact_counts[state].label(f"impact_{state}") for state in impact_states])
        count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
        pending_order = case((pending_count > 0, 0), else_=1)
        if sort is None:
            ordering = [pending_order.asc(), due_at.asc().nulls_last(), b.c.created_at.desc(), b.c.id.desc()]
        else:
            keys = {"host": func.lower(host.c.hostname), "requester": func.lower(requester.c.username),
                    "status": batch_status, "due": due_at, "batch_no": b.c.id}
            key = keys[sort]
            ordered = key.asc() if direction == "asc" else key.desc()
            ordering = [pending_order.asc(), ordered.nulls_last(), b.c.created_at.desc(), b.c.id.desc()]
        with self._conn() as c:
            total = int(c.execute(count_stmt).scalar_one())
            rows = c.execute(stmt.order_by(*ordering).offset(offset).limit(limit)).mappings().all()
            ids = [row["id"] for row in rows]
            child_assignees: dict[int, set[str]] = defaultdict(set)
            if ids:
                assignee = S.users.alias("batch_assignee")
                assignee_rows = c.execute(select(bi.c.batch_id, assignee.c.username).select_from(
                    bi.join(S.software_requests, S.software_requests.c.id == bi.c.request_id)
                    .join(assignee, assignee.c.id == S.software_requests.c.assignee_id))
                    .where(bi.c.batch_id.in_(ids))).all()
                for bid, name in assignee_rows:
                    child_assignees[bid].add(name)
        result = []
        for row in rows:
            data = dict(row)
            data["batch_no"] = f"SWB-{data['id']:06d}"
            batch_host_id = data["host_id"]
            data["host"] = {"host_id": batch_host_id, "hostname": data.pop("hostname") or "",
                            "last_seen": data.pop("last_seen")}
            data["status_counts"] = {state: data.pop(f"status_{state}") for state in status_values}
            data["security_impact_counts"] = {state: data.pop(f"impact_{state}") for state in impact_states}
            data["assignees"] = sorted(child_assignees.get(data["id"], ()))
            result.append(data)
        return total, result

    def get_software_request_batch(self, batch_id: int, at: str) -> dict[str, Any] | None:
        b, host = S.software_request_batches, S.hosts
        requester = S.users.alias("batch_requester")
        with self._conn() as c:
            row = c.execute(select(b, requester.c.username.label("requester_name"),
                host.c.hostname, host.c.last_seen).select_from(b.join(requester, requester.c.id == b.c.requester_id)
                    .outerjoin(host, host.c.host_id == b.c.host_id)).where(b.c.id == batch_id)).mappings().first()
            if row is None:
                return None
            batch = dict(row)
            children = c.execute(select(S.software_request_batch_items.c.request_id).where(
                S.software_request_batch_items.c.batch_id == batch_id)
                .order_by(S.software_request_batch_items.c.item_order)).all()
        items = []
        for (request_id,) in children:
            item = self.get_software_request(int(request_id))
            if item is None:
                continue
            item["batch_id"] = batch_id
            item["host_ids"] = [batch["host_id"]]
            item["current_installed"] = self.software_product_installed(item["source"], item["name"],
                item["arch"], item["version"], [batch["host_id"]])
            item["impact_cves"] = self._software_request_cves(item)
            item["security_impact"] = {"status": self._software_request_impact(item),
                                         "cve_count": len(item["impact_cves"])}
            with self._conn() as c:
                active_approvals = c.execute(select(S.software_approvals.c.valid_until).where(and_(
                    S.software_approvals.c.host_id == batch["host_id"],
                    S.software_approvals.c.source == item["source"], S.software_approvals.c.name == item["name"],
                    S.software_approvals.c.arch == item["arch"], S.software_approvals.c.version == item["version"],
                    S.software_approvals.c.state == "active", S.software_approvals.c.valid_from <= at,
                    S.software_approvals.c.valid_until >= at, S.software_approvals.c.ended_at.is_(None)))).all()
            approvals = [row[0] for row in active_approvals]
            item["approval_status"] = "active" if approvals else "not_active"
            item["current_approval_until"] = max(approvals, default=None)
            items.append(item)
        status_values = ("submitted", "reviewing", "needs_changes", "approved", "rejected", "withdrawn")
        impact_states = ("confirmed", "needs_review", "not_affected", "no_observed_match", "not_assessed")
        status_counts = {state: sum(i["status"] == state for i in items) for state in status_values}
        impact_counts = {state: sum(i["security_impact"]["status"] == state for i in items)
                         for state in impact_states}
        item_count = len(items)
        status = next((state for state in status_values if status_counts[state] == item_count), "mixed")
        security = next((state for state in impact_states if impact_counts[state] == item_count), "mixed")
        pending = status_counts["submitted"] + status_counts["reviewing"]
        opened = pending + status_counts["needs_changes"]
        terminal = status_counts["approved"] + status_counts["rejected"] + status_counts["withdrawn"]
        due = min((i["due_at"] for i in items if i["due_at"] and i["status"] in
                   {"submitted", "reviewing", "needs_changes"}), default=None)
        batch.update(id=batch_id, batch_no=f"SWB-{batch_id:06d}", host_id=batch["host_id"],
            host={"host_id": batch["host_id"], "hostname": batch.pop("hostname") or "",
                  "last_seen": batch.pop("last_seen")}, items=items, item_count=item_count,
            status=status, status_counts=status_counts, pending_count=pending, open_count=opened,
            terminal_count=terminal, security_impact=security, security_impact_counts=impact_counts,
            assignees=sorted({i["assignee_name"] for i in items if i["assignee_name"]}), due_at=due)
        return batch

    def _software_request_cves(self, item: dict[str, Any]) -> list[dict[str, Any]]:
        m, v, kev = S.vulnerability_product_matches, S.vulnerability_match_versions, S.kev_entries
        version_exact = exists(select(v.c.version).where(and_(v.c.cve_id == m.c.cve_id,
            v.c.source == m.c.source, v.c.name == m.c.name, v.c.arch == m.c.arch,
            v.c.version == item["version"])))
        stmt = select(m.c.cve_id, m.c.status, version_exact.label("version_exact"),
            kev.c.cve_id.is_not(None).label("is_kev")).select_from(m.outerjoin(kev, kev.c.cve_id == m.c.cve_id)).where(and_(
                m.c.source == item["source"], m.c.name == item["name"], m.c.arch == item["arch"]))
        with self._conn() as c:
            rows = c.execute(stmt.order_by(m.c.cve_id)).mappings().all()
        result = []
        for row in rows:
            status = row["status"]
            if status == "affected_confirmed":
                impact = "confirmed" if row["version_exact"] else "no_observed_match"
            else:
                impact = status
            result.append({"cve_id": row["cve_id"], "is_kev": bool(row["is_kev"]), "impact_status": impact})
        return result

    def _software_request_impact(self, item: dict[str, Any]) -> str:
        states = {row["impact_status"] for row in self._software_request_cves(item)}
        if "confirmed" in states:
            return "confirmed"
        if "needs_review" in states:
            return "needs_review"
        if not states:
            return "not_assessed"
        if states == {"not_affected"}:
            return "not_affected"
        return "no_observed_match"

    def update_software_request_batch(self, batch_id: int, actions: list[dict[str, Any]],
                                      actor_id: str, at: str) -> None:
        if not actions or len({a["request_id"] for a in actions}) != len(actions):
            raise ValueError("요청 항목을 확인하세요.")
        b, bi, t = S.software_request_batches, S.software_request_batch_items, S.software_requests
        p, classification, targets = S.installed_packages, S.software_classifications, S.software_request_hosts
        a, events, approvals = S.software_approvals, S.software_request_events, S.software_approvals
        with self.transaction(), self._conn(write=True) as c:
            batch = c.execute(select(b.c.host_id).where(b.c.id == batch_id)).scalar_one_or_none()
            if batch is None:
                raise KeyError("request batch not found")
            request_ids = [action["request_id"] for action in actions]
            memberships = c.execute(select(bi.c.request_id, t.c.revision, t.c.status, t.c.source,
                t.c.name, t.c.arch, t.c.version).select_from(bi.join(t, t.c.id == bi.c.request_id))
                .where(and_(bi.c.batch_id == batch_id, bi.c.request_id.in_(request_ids)))).mappings().all()
            if len(memberships) != len(actions):
                raise ValueError("묶음에 포함된 요청 항목만 처리할 수 있습니다.")
            by_id = {row["request_id"]: row for row in memberships}
            host_rows = c.execute(select(targets.c.request_id, targets.c.host_id).where(
                targets.c.request_id.in_(request_ids))).all()
            child_hosts: dict[int, set[str]] = defaultdict(set)
            for request_id, host_id in host_rows:
                child_hosts[request_id].add(host_id)
            for action in actions:
                current = by_id.get(action["request_id"])
                if current is None or current["revision"] != action["expected_revision"]:
                    raise ConflictError("software request batch revision changed")
                if action.get("values", {}).get("status") == "approved":
                    if child_hosts.get(action["request_id"]) != {batch}:
                        raise ConflictError("batch child host scope changed")
                    classified = c.execute(select(classification.c.category).where(and_(
                        classification.c.source == current["source"], classification.c.name == current["name"],
                        classification.c.arch == current["arch"])).with_for_update()).scalar_one_or_none()
                    present = c.execute(select(p.c.host_id).where(and_(p.c.host_id == batch,
                        p.c.source == current["source"], p.c.name == current["name"],
                        p.c.arch == current["arch"], p.c.version == current["version"])).limit(1)
                        .with_for_update()).first()
                    if classified != "business_app" or not present:
                        raise ConflictError("exact installed business application changed")
                    active = c.execute(select(a.c.id).where(and_(a.c.host_id == batch,
                        a.c.source == current["source"], a.c.name == current["name"],
                        a.c.arch == current["arch"], a.c.version == current["version"],
                        a.c.state == "active", a.c.valid_from <= at, a.c.valid_until >= at,
                        a.c.ended_at.is_(None))).limit(1)).first()
                    if active:
                        raise ConflictError("exact software approval already exists")
                    for approval in action.get("approvals") or []:
                        if (approval["host_id"] != batch or approval["source"] != current["source"] or
                                approval["name"] != current["name"] or approval["arch"] != current["arch"] or
                                approval["version"] != current["version"]):
                            raise ConflictError("batch approval scope changed")
            for action in actions:
                rid, expected = action["request_id"], action["expected_revision"]
                current = by_id[rid]
                values = action["values"]
                result = c.execute(update(t).where(and_(t.c.id == rid, t.c.revision == expected)).values(
                    **values, updated_at=at, revision=expected + 1))
                if result.rowcount != 1:
                    raise ConflictError("software request batch revision changed")
                next_status = values.get("status", current["status"])
                c.execute(insert(events).values(request_id=rid, actor_id=actor_id, action=action["action"],
                    from_status=current["status"], to_status=next_status, reason=action["reason"],
                    detail=json.dumps(action["detail"], sort_keys=True), revision=expected + 1, occurred_at=at))
                if action.get("approvals"):
                    c.execute(insert(approvals), action["approvals"])
                if action.get("revoke_approvals"):
                    c.execute(update(a).where(and_(a.c.request_id == rid, a.c.state == "active")).values(
                        state="revoked", ended_at=at, end_reason=action["reason"]))

    def list_software_requests(self, *, requester_id: str | None = None, status: str | None = None, q: str = "",
                               unassigned: bool = False, overdue_before: str | None = None,
                               offset: int = 0, limit: int = 50, assignee_id: str | None = None,
                               pending: bool = False, sort: str | None = None,
                               direction: str = "asc",
                               security_impact: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        t, u, assignee = S.software_requests, S.users.alias("requester"), S.users.alias("assignee")
        targets, p = S.software_request_hosts, S.installed_packages
        m, v = S.vulnerability_product_matches, S.vulnerability_match_versions
        target_packages = targets.join(p, and_(p.c.host_id == targets.c.host_id,
            p.c.source == t.c.source, p.c.name == t.c.name, p.c.arch == t.c.arch, p.c.version == t.c.version))
        mapped_from = target_packages.join(m, and_(m.c.source == t.c.source, m.c.name == t.c.name,
            m.c.arch == t.c.arch)).outerjoin(v, and_(v.c.cve_id == m.c.cve_id, v.c.source == m.c.source,
            v.c.name == m.c.name, v.c.arch == m.c.arch, v.c.version == p.c.version))
        confirmed_count = (select(func.count(distinct(m.c.cve_id))).select_from(mapped_from).where(and_(
            targets.c.request_id == t.c.id, m.c.status == "affected_confirmed", v.c.cve_id.is_not(None)))
            .correlate(t).scalar_subquery())
        review_count = (select(func.count(distinct(m.c.cve_id))).select_from(mapped_from).where(and_(
            targets.c.request_id == t.c.id, m.c.status == "needs_review"))
            .correlate(t).scalar_subquery())
        mapped_count = (select(func.count(distinct(m.c.cve_id))).select_from(mapped_from).where(
            targets.c.request_id == t.c.id).correlate(t).scalar_subquery())
        non_negative_count = (select(func.count(distinct(m.c.cve_id))).select_from(mapped_from).where(and_(
            targets.c.request_id == t.c.id, m.c.status != "not_affected"))
            .correlate(t).scalar_subquery())
        security = case((confirmed_count > 0, "confirmed"), (review_count > 0, "needs_review"),
                        (mapped_count == 0, "not_assessed"), (non_negative_count == 0, "not_affected"),
                        else_="no_observed_match").label("security_impact")
        host_count = (select(func.count()).select_from(targets).where(targets.c.request_id == t.c.id)
                      .correlate(t).scalar_subquery().label("host_count"))
        stmt = (select(t, u.c.username.label("requester_name"), assignee.c.username.label("assignee_name"),
                       host_count, security, mapped_count.label("security_cve_count"))
                .select_from(t.join(u, t.c.requester_id == u.c.id).outerjoin(assignee, t.c.assignee_id == assignee.c.id)))
        if requester_id:
            stmt = stmt.where(t.c.requester_id == requester_id)
        if assignee_id:
            stmt = stmt.where(t.c.assignee_id == assignee_id)
        if status:
            stmt = stmt.where(t.c.status == status)
        if pending:
            stmt = stmt.where(t.c.status.in_(("submitted", "reviewing")))
        if security_impact:
            stmt = stmt.where(security == security_impact)
        if unassigned:
            stmt = stmt.where(t.c.assignee_id.is_(None))
        if overdue_before:
            stmt = stmt.where(t.c.due_at.is_not(None), t.c.due_at < overdue_before,
                              t.c.status.in_(("submitted", "reviewing", "needs_changes")))
        needle = q.strip().casefold()
        if needle:
            request_no = re.fullmatch(r"sw-([0-9]{1,20})", needle)
            if request_no:
                request_number = int(request_no.group(1))
                request_id_match = t.c.id == request_number if request_number <= 2_147_483_647 else t.c.id == -1
            else:
                request_id_match = cast(t.c.id, String).like(
                    f"%{_escape_like(needle.removeprefix('sw-'))}%", escape="\\")
            stmt = stmt.where(or_(func.lower(t.c.name).like(f"%{_escape_like(needle)}%", escape="\\"),
                                  func.lower(t.c.product_name).like(f"%{_escape_like(needle)}%", escape="\\"),
                                  func.lower(u.c.username).like(f"%{_escape_like(needle)}%", escape="\\"),
                                  request_id_match))
        subquery = stmt.with_only_columns(t.c.id).order_by(None).subquery()
        pending_order = case((t.c.status.in_(("submitted", "reviewing")), 0), else_=1)
        if sort is None:
            ordering = [pending_order.asc(), t.c.due_at.asc().nulls_last(), t.c.updated_at.desc(), t.c.id.desc()]
        else:
            if sort not in {"product", "status", "security", "targets", "requester", "assignee", "due", "request_no"}:
                raise ValueError("unsupported software request sort")
            if direction not in {"asc", "desc"}:
                raise ValueError("unsupported software request sort direction")
            security_rank = case((security == "confirmed", 0), (security == "needs_review", 1),
                (security == "not_assessed", 2), (security == "no_observed_match", 3),
                (security == "not_affected", 4), else_=5)
            key = {"product": func.lower(t.c.product_name + " " + t.c.name), "status": t.c.status,
                   "security": security_rank, "targets": host_count, "requester": func.lower(u.c.username),
                   "assignee": func.lower(assignee.c.username), "due": t.c.due_at,
                   "request_no": t.c.id}[sort]
            ordered_key = key.asc() if direction == "asc" else key.desc()
            ordering = [pending_order.asc(), ordered_key.nulls_last(), t.c.updated_at.desc(), t.c.id.desc()]
        with self._conn() as c:
            total = int(c.execute(select(func.count()).select_from(subquery)).scalar_one())
            rows = c.execute(stmt.order_by(*ordering).offset(offset).limit(limit)).mappings().all()
            result = []
            for row in rows:
                data = dict(row)
                data["request_no"] = f"SW-{data['id']:06d}"
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
            batch_id = c.execute(select(S.software_request_batch_items.c.batch_id).where(
                S.software_request_batch_items.c.request_id == request_id)).scalar_one_or_none()
            data["batch_id"] = batch_id
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
    def _vulnerability_query(self, q: str, kev_only: bool, impact_status: str | None,
                             host_id: str | None = None, product_source: str | None = None,
                             product_name: str | None = None, product_arch: str | None = None,
                             product_version: str | None = None):
        cve, kev = S.vulnerability_cves, S.kev_entries
        m, v, p = S.vulnerability_product_matches, S.vulnerability_match_versions, S.installed_packages

        def product_filters(mapping, package, *, include_host: bool = True):
            conditions = [mapping.c.cve_id == cve.c.cve_id,
                package.c.source == mapping.c.source, package.c.name == mapping.c.name,
                package.c.arch == mapping.c.arch]
            for column, value in ((mapping.c.source, product_source), (mapping.c.name, product_name),
                                  (mapping.c.arch, product_arch), (package.c.version, product_version)):
                if value is not None:
                    conditions.append(column == value)
            if include_host and host_id is not None:
                conditions.append(package.c.host_id == host_id)
            return conditions

        mapped_from = m.join(p, and_(p.c.source == m.c.source, p.c.name == m.c.name,
                                     p.c.arch == m.c.arch))
        scoped_product = host_id is not None or any(value is not None for value in
            (product_source, product_name, product_arch, product_version))
        if scoped_product:
            mapped_conditions = product_filters(m, p)
            has_mapping = exists(select(m.c.cve_id).select_from(mapped_from).where(and_(*mapped_conditions)))
            has_review = exists(select(m.c.cve_id).select_from(mapped_from).where(and_(
                *mapped_conditions, m.c.status == "needs_review")))
            has_non_negative = exists(select(m.c.cve_id).select_from(mapped_from).where(and_(
                *mapped_conditions, m.c.status != "not_affected")))
        else:
            has_mapping = exists(select(m.c.cve_id).where(m.c.cve_id == cve.c.cve_id))
            has_review = exists(select(m.c.cve_id).where(and_(m.c.cve_id == cve.c.cve_id,
                m.c.status == "needs_review")))
            has_non_negative = exists(select(m.c.cve_id).where(and_(m.c.cve_id == cve.c.cve_id,
                m.c.status != "not_affected")))

        confirmed_from = m.join(v, and_(v.c.cve_id == m.c.cve_id, v.c.source == m.c.source,
            v.c.name == m.c.name, v.c.arch == m.c.arch)).join(p, and_(p.c.source == v.c.source,
            p.c.name == v.c.name, p.c.arch == v.c.arch, p.c.version == v.c.version))
        confirmed_conditions = product_filters(m, p)
        has_confirmed = exists(select(m.c.cve_id).select_from(confirmed_from).where(and_(
            *confirmed_conditions, m.c.status == "affected_confirmed")))
        impact = case((has_confirmed, "confirmed"), (has_review, "needs_review"),
                      (and_(has_mapping, ~has_non_negative), "not_affected"),
                      (has_mapping, "no_observed_match"), else_="not_assessed").label("impact_status")

        all_confirmed_from = m.join(v, and_(v.c.cve_id == m.c.cve_id, v.c.source == m.c.source,
            v.c.name == m.c.name, v.c.arch == m.c.arch)).join(p, and_(p.c.source == v.c.source,
            p.c.name == v.c.name, p.c.arch == v.c.arch, p.c.version == v.c.version))
        legacy_conditions = product_filters(m, p, include_host=False)
        confirmed_host_count = (select(func.count(distinct(p.c.host_id))).select_from(all_confirmed_from)
            .where(and_(*legacy_conditions, m.c.status == "affected_confirmed"))
            .correlate(cve).scalar_subquery().label("host_count"))
        filtered_confirmed_host_count = (select(func.count(distinct(p.c.host_id))).select_from(all_confirmed_from)
            .where(and_(*product_filters(m, p), m.c.status == "affected_confirmed"))
            .correlate(cve).scalar_subquery().label("confirmed_host_count"))
        install_count = (select(func.count()).select_from(all_confirmed_from)
            .where(and_(*product_filters(m, p), m.c.status == "affected_confirmed"))
            .correlate(cve).scalar_subquery().label("install_count"))

        def mapped_host_count(status: str, *, unmatched: bool = False, label: str):
            conditions = product_filters(m, p)
            conditions.append(m.c.status == status)
            if unmatched:
                has_exact_version = exists(select(v.c.version).where(and_(v.c.cve_id == m.c.cve_id,
                    v.c.source == m.c.source, v.c.name == m.c.name, v.c.arch == m.c.arch,
                    v.c.version == p.c.version)))
                conditions.append(~has_exact_version)
            return (select(func.count(distinct(p.c.host_id))).select_from(mapped_from)
                    .where(and_(*conditions)).correlate(cve).scalar_subquery().label(label))

        review_host_count = mapped_host_count("needs_review", label="needs_review_host_count")
        not_affected_host_count = mapped_host_count("not_affected", label="not_affected_host_count")
        unmatched_host_count = mapped_host_count("affected_confirmed", unmatched=True,
                                                  label="no_observed_match_host_count")
        stmt = select(cve.c.cve_id, cve.c.description, cve.c.published_at, cve.c.modified_at, cve.c.cvss_score,
                      cve.c.cvss_severity, cve.c.nvd_status, kev.c.vendor, kev.c.product, kev.c.date_added,
                      kev.c.due_date, kev.c.ransomware_use, kev.c.catalog_version, impact,
                      confirmed_host_count, filtered_confirmed_host_count, review_host_count,
                      not_affected_host_count, unmatched_host_count, install_count).select_from(
                          cve.outerjoin(kev, kev.c.cve_id == cve.c.cve_id))
        if q:
            pattern = f"%{_escape_like(q.casefold())}%"
            stmt = stmt.where(or_(func.lower(cve.c.cve_id).like(pattern, escape="\\"),
                                  func.lower(cve.c.description).like(pattern, escape="\\"),
                                  func.lower(kev.c.vendor).like(pattern, escape="\\"),
                                  func.lower(kev.c.product).like(pattern, escape="\\")))
        if kev_only:
            stmt = stmt.where(kev.c.cve_id.is_not(None))
        if scoped_product:
            stmt = stmt.where(has_mapping)
        if impact_status:
            stmt = stmt.where(impact == impact_status)
        return stmt, cve, kev

    def list_vulnerabilities(self, *, q: str = "", kev_only: bool = False, impact_status: str | None = None,
                             offset: int = 0, limit: int = 50, host_id: str | None = None,
                             product_source: str | None = None, product_name: str | None = None,
                             product_arch: str | None = None, product_version: str | None = None) -> tuple[int, list[dict[str, Any]]]:
        stmt, cve, kev = self._vulnerability_query(q, kev_only, impact_status, host_id, product_source,
            product_name, product_arch, product_version)
        total_query = stmt.with_only_columns(cve.c.cve_id).order_by(None).subquery()
        priority = case((kev.c.cve_id.is_not(None), 0), else_=1)
        if self._engine.dialect.name == "postgresql":
            valid_score = cve.c.cvss_score.op("~")(r"^[0-9]+(\.[0-9]+)?$")
            numeric_score = case((valid_score, cast(cve.c.cvss_score, Numeric())), else_=None)
        else:
            score_text = cve.c.cvss_score
            valid_score = and_(score_text.is_not(None), score_text != "",
                score_text.op("NOT GLOB")("*[^0-9.]*"),
                func.length(score_text) - func.length(func.replace(score_text, ".", "")) <= 1,
                func.replace(score_text, ".", "") != "")
            numeric_score = case((valid_score, cast(score_text, Float())), else_=None)

        with self._conn() as c:
            total = int(c.execute(select(func.count()).select_from(total_query)).scalar_one())
            rows = c.execute(stmt.order_by(priority, kev.c.date_added.desc(), numeric_score.desc().nulls_last(),
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
                stmt = (select(p.c.host_id, h.c.hostname, h.c.last_seen, p.c.source, p.c.name, p.c.arch, p.c.version)
                        .select_from(p.join(h, h.c.host_id == p.c.host_id))
                        .where(and_(p.c.source == item["source"], p.c.name == item["name"], p.c.arch == item["arch"]))
                        .order_by(h.c.hostname, p.c.version))
                observed = [dict(r) for r in conn.execute(stmt).mappings()]
                for installation in observed:
                    installation["impact_status"] = (
                        "confirmed" if item["status"] == "affected_confirmed" and installation["version"] in versions
                        else "no_observed_match" if item["status"] == "affected_confirmed"
                        else item["status"])
                item["observed_installations"] = observed
                item["installations"] = ([row.copy() for row in observed if row["impact_status"] == "confirmed"]
                    if item["status"] == "affected_confirmed" and versions else [row.copy() for row in observed])
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
