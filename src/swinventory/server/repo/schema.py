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

# collector 단위 수집 신선도. 실패 시 last_success_at 과 현재 설치 인벤토리는 유지한다.
host_source_freshness = Table(
    "host_source_freshness", metadata,
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("source", String(64), nullable=False),
    Column("last_success_at", _TS, nullable=True),
    Column("last_attempt_at", _TS, nullable=False),
    Column("state", String(16), nullable=False),
    Column("last_error", Text, nullable=False, default=""),
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
    Column("primary_owner", String(128), nullable=False, default="", server_default=""),
    Column("secondary_owner", String(128), nullable=False, default="", server_default=""),
    Column("created_at", _TS, nullable=False),
    Column("updated_at", _TS, nullable=False),
    Column("revision", Integer, nullable=False, server_default="1"),
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

# 업무용 소프트웨어 분류는 수집 source 로 추측하지 않는다. 미분류 제품은 needs_review 로 남긴다.
software_classifications = Table("software_classifications", metadata,
    Column("source", String(64), nullable=False), Column("name", String(512), nullable=False),
    Column("arch", String(32), nullable=False), Column("category", String(32), nullable=False),
    Column("product_name", String(512), nullable=False, default=""),
    Column("publisher", String(255), nullable=False, default=""),
    Column("evidence", String(1000), nullable=False), Column("updated_by", String(32), ForeignKey("users.id"), nullable=False),
    Column("updated_at", _TS, nullable=False), Column("revision", Integer, nullable=False, default=1),
    PrimaryKeyConstraint("source", "name", "arch"),
)
software_classification_events = Table("software_classification_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("source", String(64), nullable=False), Column("name", String(512), nullable=False),
    Column("arch", String(32), nullable=False), Column("old_category", String(32), nullable=True),
    Column("new_category", String(32), nullable=False), Column("evidence", String(1000), nullable=False),
    Column("changed_by", String(32), ForeignKey("users.id"), nullable=False), Column("changed_at", _TS, nullable=False),
)
Index("ix_software_class_events", software_classification_events.c.source,
      software_classification_events.c.name, software_classification_events.c.arch, software_classification_events.c.id)

# 요청 역할은 관리자가 직접 사용자에게 부여한다. 각 사용자의 요청 가능 호스트도 별도로 지정한다.
software_request_host_scopes = Table("software_request_host_scopes", metadata,
    Column("user_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("granted_by", String(32), ForeignKey("users.id"), nullable=False), Column("granted_at", _TS, nullable=False),
    PrimaryKeyConstraint("user_id", "host_id"),
)
software_request_scope_events = Table("software_request_scope_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("actor_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("old_host_ids", Text, nullable=False), Column("new_host_ids", Text, nullable=False),
    Column("occurred_at", _TS, nullable=False),
)
Index("ix_software_request_scope_events", software_request_scope_events.c.user_id,
      software_request_scope_events.c.id)
software_requests = Table("software_requests", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("requester_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("source", String(64), nullable=False), Column("name", String(512), nullable=False),
    Column("arch", String(32), nullable=False), Column("product_name", String(512), nullable=False),
    Column("version", String(256), nullable=False), Column("purpose", String(2000), nullable=False),
    Column("license_evidence", String(2000), nullable=False),
    Column("status", String(32), nullable=False), Column("assignee_id", String(32), ForeignKey("users.id"), nullable=True),
    Column("due_at", _TS, nullable=True), Column("approval_until", _TS, nullable=True),
    Column("decision_reason", String(2000), nullable=False, default=""),
    Column("revision", Integer, nullable=False, default=1),
    Column("created_at", _TS, nullable=False), Column("updated_at", _TS, nullable=False),
)
Index("ix_software_requests_status", software_requests.c.status, software_requests.c.due_at)
Index("ix_software_requests_owner", software_requests.c.requester_id, software_requests.c.created_at)
# A batch groups independent one-host request rows. Legacy multi-host requests remain unlinked.
software_request_batches = Table("software_request_batches", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("requester_id", String(32), ForeignKey("users.id"), nullable=False),
    # No host FK: host identity is also recorded on each child request and this must not add
    # another host-deletion dependency to the existing request/approval history.
    Column("host_id", String(128), nullable=False),
    Column("purpose", String(2000), nullable=False),
    Column("license_evidence", String(2000), nullable=False),
    Column("created_at", _TS, nullable=False),
)
Index("ix_software_request_batches_owner", software_request_batches.c.requester_id,
      software_request_batches.c.created_at)
software_request_hosts = Table("software_request_hosts", metadata,
    Column("request_id", Integer, ForeignKey("software_requests.id"), nullable=False),
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    PrimaryKeyConstraint("request_id", "host_id"),
)
software_request_events = Table("software_request_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("request_id", Integer, ForeignKey("software_requests.id"), nullable=False),
    Column("actor_id", String(32), ForeignKey("users.id"), nullable=False),
    Column("action", String(32), nullable=False), Column("from_status", String(32), nullable=True),
    Column("to_status", String(32), nullable=False), Column("reason", String(2000), nullable=False, default=""),
    Column("detail", Text, nullable=False, default="{}"), Column("revision", Integer, nullable=False),
    Column("occurred_at", _TS, nullable=False),
)
Index("ix_software_request_events", software_request_events.c.request_id, software_request_events.c.id)
software_request_batch_items = Table("software_request_batch_items", metadata,
    Column("batch_id", Integer, ForeignKey("software_request_batches.id"), nullable=False),
    Column("request_id", Integer, ForeignKey("software_requests.id"), nullable=False),
    Column("item_order", Integer, nullable=False),
    PrimaryKeyConstraint("batch_id", "request_id"),
    UniqueConstraint("request_id", name="uq_software_request_batch_item_request"),
)
Index("ix_software_request_batch_items_order", software_request_batch_items.c.batch_id,
      software_request_batch_items.c.item_order)
software_approvals = Table("software_approvals", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("request_id", Integer, ForeignKey("software_requests.id"), nullable=False),
    Column("source", String(64), nullable=False), Column("name", String(512), nullable=False),
    Column("arch", String(32), nullable=False), Column("version", String(256), nullable=False),
    Column("host_id", String(128), ForeignKey("hosts.host_id"), nullable=False),
    Column("state", String(16), nullable=False), Column("valid_from", _TS, nullable=False),
    Column("valid_until", _TS, nullable=False), Column("decided_by", String(32), ForeignKey("users.id"), nullable=False),
    Column("reason", String(2000), nullable=False), Column("ended_at", _TS, nullable=True),
    Column("end_reason", String(2000), nullable=False, default=""),
)
Index("ix_software_approval_scope", software_approvals.c.source, software_approvals.c.name,
      software_approvals.c.arch, software_approvals.c.version, software_approvals.c.host_id, software_approvals.c.state)

# CVE 원자료, CISA KEV 기준일, 신선도 상태, 제품별 근거 평가를 인벤토리와 분리해 보관한다.
vulnerability_cves = Table("vulnerability_cves", metadata,
    Column("cve_id", String(32), primary_key=True), Column("description", Text, nullable=False, default=""),
    Column("published_at", _TS, nullable=True), Column("modified_at", _TS, nullable=True),
    Column("cvss_score", String(16), nullable=True), Column("cvss_severity", String(24), nullable=True),
    Column("cvss_metrics", Text, nullable=False, default="{}"), Column("nvd_status", String(32), nullable=False, default=""),
    Column("references", Text, nullable=False, default="[]"),
    Column("configurations", Text, nullable=False, default="[]"), Column("nvd_fetched_at", _TS, nullable=True),
)
kev_entries = Table("kev_entries", metadata,
    Column("cve_id", String(32), ForeignKey("vulnerability_cves.cve_id"), primary_key=True),
    Column("vendor", String(255), nullable=False), Column("product", String(512), nullable=False),
    Column("vulnerability_name", String(512), nullable=False), Column("date_added", String(10), nullable=False),
    Column("due_date", String(10), nullable=False), Column("ransomware_use", String(16), nullable=False),
    Column("required_action", Text, nullable=False), Column("notes", Text, nullable=False, default=""),
    Column("catalog_version", String(32), nullable=False), Column("fetched_at", _TS, nullable=False),
)
vulnerability_feed_status = Table("vulnerability_feed_status", metadata,
    Column("source", String(16), primary_key=True), Column("state", String(16), nullable=False),
    Column("last_success_at", _TS, nullable=True), Column("last_attempt_at", _TS, nullable=True),
    Column("last_error", String(500), nullable=False, default=""), Column("data_version", Text, nullable=False, default=""),
    Column("records", Integer, nullable=False, default=0),
)
vulnerability_product_matches = Table("vulnerability_product_matches", metadata,
    Column("cve_id", String(32), ForeignKey("vulnerability_cves.cve_id"), nullable=False),
    Column("source", String(64), nullable=False), Column("name", String(512), nullable=False),
    Column("arch", String(32), nullable=False), Column("status", String(24), nullable=False),
    Column("evidence", String(2000), nullable=False), Column("conditions", String(1000), nullable=False, default=""),
    Column("affected_versions", Text, nullable=False, default="[]"),
    Column("updated_by", String(32), ForeignKey("users.id"), nullable=False), Column("updated_at", _TS, nullable=False),
    Column("revision", Integer, nullable=False, default=1),
    PrimaryKeyConstraint("cve_id", "source", "name", "arch"),
)
vulnerability_match_events = Table("vulnerability_match_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True), Column("cve_id", String(32), nullable=False),
    Column("source", String(64), nullable=False), Column("name", String(512), nullable=False), Column("arch", String(32), nullable=False),
    Column("old_status", String(24), nullable=True), Column("new_status", String(24), nullable=False),
    Column("evidence", String(2000), nullable=False), Column("changed_by", String(32), ForeignKey("users.id"), nullable=False),
    Column("changed_at", _TS, nullable=False),
)
vulnerability_match_versions = Table("vulnerability_match_versions", metadata,
    Column("cve_id", String(32), nullable=False), Column("source", String(64), nullable=False),
    Column("name", String(512), nullable=False), Column("arch", String(32), nullable=False),
    Column("version", String(256), nullable=False),
    PrimaryKeyConstraint("cve_id", "source", "name", "arch", "version"),
)
