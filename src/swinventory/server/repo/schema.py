"""테이블 정의(SQLite/PostgreSQL 공용). 시각은 고정 폭 UTC 문자열(timeutil.normalize_ts)."""
from __future__ import annotations

from sqlalchemy import (
    Boolean, Column, ForeignKey, Index, Integer, MetaData, PrimaryKeyConstraint,
    String, Table, Text, UniqueConstraint,
)

metadata = MetaData()
_TS = String(32)

hosts = Table(
    "hosts", metadata,
    Column("host_id", String(128), primary_key=True),
    Column("hostname", String(255), nullable=False),
    Column("os_family", String(32), nullable=False, default=""),
    Column("os_name", String(255), nullable=False, default=""),
    Column("os_version", String(64), nullable=False, default=""),
    Column("agent_version", String(32), nullable=False, default=""),
    Column("first_seen", _TS, nullable=False),
    Column("last_seen", _TS, nullable=False),
    Column("last_snapshot_at", _TS, nullable=False),
    Column("last_errors", Text, nullable=False, default="{}"),  # 마지막 수집의 errors(JSON)
)

host_tags = Table(
    "host_tags", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("key", String(64), nullable=False),
    Column("value", String(255), nullable=False),
    PrimaryKeyConstraint("host_id", "key"),
)

# source 별로 "이 호스트에서 한 번이라도 동기화됐는가" — 처음 성공한 source 는 기준선 취급
host_sources = Table(
    "host_sources", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("source", String(64), nullable=False),
    Column("first_synced_at", _TS, nullable=False),
    PrimaryKeyConstraint("host_id", "source"),
)

snapshots = Table(
    "snapshots", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("collected_at", _TS, nullable=False),
    Column("received_at", _TS, nullable=False),
    Column("collected", Text, nullable=False, default="[]"),
    Column("errors", Text, nullable=False, default="{}"),
    UniqueConstraint("host_id", "collected_at", name="uq_snapshot_host_collected_at"),
)

host_kernel_state = Table(
    "host_kernel_state", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), primary_key=True),
    Column("running", String(128), nullable=False),
    Column("latest_installed", String(128), nullable=False),
    Column("reboot_required", Boolean, nullable=False),
    Column("updated_at", _TS, nullable=False),
)
Index("ix_kernel_state_running", host_kernel_state.c.running)

host_kernels = Table(
    "host_kernels", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("version", String(128), nullable=False),
    Column("is_running", Boolean, nullable=False),
    PrimaryKeyConstraint("host_id", "version"),
)

# 키에 version 을 포함한다 — kernel-core 처럼 같은 (source,name,arch) 다중 버전을 보존
installed_packages = Table(
    "installed_packages", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("source", String(64), nullable=False),
    Column("name", String(512), nullable=False),
    Column("arch", String(32), nullable=False, default=""),
    Column("version", String(256), nullable=False, default=""),
    PrimaryKeyConstraint("host_id", "source", "name", "arch", "version"),
)
Index("ix_packages_name_version", installed_packages.c.name, installed_packages.c.version)

change_events = Table(
    "change_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("snapshot_id", Integer, ForeignKey("snapshots.id"), nullable=True),
    Column("occurred_at", _TS, nullable=False),
    Column("event_type", String(48), nullable=False),
    Column("subject_type", String(32), nullable=False),
    Column("subject_key", String(512), nullable=False),
    Column("old_value", Text, nullable=True),
    Column("new_value", Text, nullable=True),
    Column("detail", Text, nullable=False, default="{}"),
)
Index("ix_events_host_time", change_events.c.host_id, change_events.c.occurred_at)
Index("ix_events_type_time", change_events.c.event_type, change_events.c.occurred_at)
Index("ix_events_subject", change_events.c.subject_key)

# 관리자가 화면에서 바꾸는 설정(커널 하한선, AI 연결 등). 비밀은 SecretBox 로 암호화한 값만 저장한다.
app_settings = Table(
    "app_settings", metadata,
    Column("key", String(64), primary_key=True),
    Column("value", Text, nullable=False),
    Column("updated_at", _TS, nullable=False),
)

reports = Table(
    "reports", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("created_at", _TS, nullable=False),
    Column("model", String(128), nullable=False),
    Column("markdown", Text, nullable=False),
    Column("facts", Text, nullable=False),  # 리포트 작성 근거가 된 집계(JSON) — 나중에 검증할 수 있게 보관
    Column("prompt_tokens", Integer, nullable=True),
    Column("completion_tokens", Integer, nullable=True),
)
Index("ix_reports_created", reports.c.created_at)

# 네트워크: 호스트별 현재 상태(전체 교체). 변경은 change_events 에 이력으로 남는다.
host_interfaces = Table(
    "host_interfaces", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("name", String(64), nullable=False),
    Column("mac", String(17), nullable=False, default=""),
    Column("state", String(16), nullable=False, default="unknown"),
    PrimaryKeyConstraint("host_id", "name"),
)

host_addresses = Table(
    "host_addresses", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("interface", String(64), nullable=False),
    Column("address", String(64), nullable=False),   # CIDR (10.0.0.5/24)
    Column("ip", String(45), nullable=False),        # 접두사 없는 주소 — 'IP 가 누구 것인가' 조회·충돌 탐지용
    Column("family", Integer, nullable=False),       # 4 | 6
    PrimaryKeyConstraint("host_id", "interface", "address"),
)
Index("ix_addresses_ip", host_addresses.c.ip)

host_ports = Table(
    "host_ports", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("proto", String(8), nullable=False),
    Column("port", Integer, nullable=False),
    Column("bind", String(64), nullable=False),
    PrimaryKeyConstraint("host_id", "proto", "port", "bind"),
)
Index("ix_ports_port", host_ports.c.port)

# 장비 정보: 에이전트가 수집한 현재 상태(전체 교체). kind: physical|virtual|container|unknown
host_hardware = Table(
    "host_hardware", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), primary_key=True),
    Column("kind", String(16), nullable=False, default="unknown"),
    Column("virt", String(64), nullable=False, default=""),
    Column("vendor", String(255), nullable=False, default=""),
    Column("model", String(255), nullable=False, default=""),
    Column("serial", String(128), nullable=False, default=""),
    Column("fqdn", String(255), nullable=False, default=""),
    Column("domain", String(255), nullable=False, default=""),
    Column("updated_at", _TS, nullable=False),
)

# 자산 대장: 관리자가 웹에서 입력한다. 수집 호스트와의 연결은 저장하지 않고 읽을 때 계산한다(assetview).
# host_id 는 관리자가 '이 호스트다'라고 고정한 명시 연결(FK 없음 — 호스트가 삭제돼도 대장은 남고, 다시 수집되면 이어진다).
assets = Table(
    "assets", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("asset_no", String(64), nullable=False),
    Column("asset_no_key", String(64), nullable=False, unique=True),      # 대소문자 무시 유일성
    Column("kind", String(16), nullable=False),                           # physical | virtual
    Column("serial", String(128), nullable=False, default=""),
    Column("hostname", String(255), nullable=False, default=""),
    Column("domain", String(255), nullable=False, default=""),
    Column("ip", String(45), nullable=False, default=""),
    Column("parent_asset_id", Integer, ForeignKey("assets.id"), nullable=True),   # VM → 올라간 물리 장비
    Column("host_id", String(128), nullable=True, unique=True),
    Column("note", String(500), nullable=False, default=""),
    Column("created_at", _TS, nullable=False),
    Column("updated_at", _TS, nullable=False),
)
Index("ix_assets_parent", assets.c.parent_asset_id)

# 컨테이너: 호스트별 현재 상태(전체 교체). 이미지 단위 변경은 change_events 에 남는다. 라벨·환경변수는 저장하지 않는다.
host_containers = Table(
    "host_containers", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("container_id", String(64), nullable=False),
    Column("runtime", String(32), nullable=False, default=""),
    Column("name", String(255), nullable=False, default=""),
    Column("image", String(512), nullable=False, default=""),
    Column("image_id", String(80), nullable=False, default=""),
    Column("image_digest", String(80), nullable=False, default=""),
    Column("state", String(16), nullable=False, default="unknown"),
    Column("created_at", _TS, nullable=False, default=""),
    Column("pod", String(255), nullable=False, default=""),
    Column("namespace", String(255), nullable=False, default=""),
    PrimaryKeyConstraint("host_id", "container_id"),
)
Index("ix_containers_image", host_containers.c.image)

# 이 호스트가 쿠버네티스 노드일 때의 식별 정보. cluster_id = 클러스터 CA 인증서 해시(비어 있으면 '클러스터 미확인').
host_k8s = Table(
    "host_k8s", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), primary_key=True),
    Column("cluster_id", String(64), nullable=False, default=""),
    Column("api_server", String(255), nullable=False, default=""),
    Column("version", String(64), nullable=False, default=""),
    Column("runtime", String(32), nullable=False, default=""),
    Column("updated_at", _TS, nullable=False),
)
Index("ix_host_k8s_cluster", host_k8s.c.cluster_id)


# 사용자 비밀번호는 단방향 해시, 발급 JWT 는 원문 없이 SHA-256 과 회수 상태만 보관한다.
auth_guard = Table("auth_guard", metadata, Column("id", Integer, primary_key=True), Column("revision", Integer, nullable=False))
users = Table("users", metadata,
    Column("id", String(32), primary_key=True), Column("username", String(64), nullable=False, unique=True),
    Column("password_hash", Text, nullable=False), Column("role", String(16), nullable=False),
    Column("active", Boolean, nullable=False), Column("generation", Integer, nullable=False),
    Column("failed_logins", Integer, nullable=False), Column("locked_until", Integer, nullable=False),
    Column("created_at", _TS, nullable=False))
access_tokens = Table("access_tokens", metadata,
    Column("id", String(32), primary_key=True), Column("token_hash", String(64), nullable=False, unique=True),
    Column("user_id", String(32), ForeignKey("users.id"), nullable=True),
    Column("generation", Integer, nullable=False), Column("name", String(100), nullable=False),
    Column("role", String(16), nullable=False), Column("kind", String(16), nullable=False),
    Column("created_at", _TS, nullable=False), Column("expires_at", Integer, nullable=False),
    Column("revoked", Boolean, nullable=False))
login_attempts = Table("login_attempts", metadata,
    Column("key", String(64), primary_key=True), Column("started_at", Integer, nullable=False), Column("count", Integer, nullable=False))
