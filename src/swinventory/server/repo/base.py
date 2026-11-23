from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ContextManager, Iterable

from swinventory.common.models import ContainerRecord, HardwareInfo, K8sNodeInfo, KernelInfo, ListeningPort, NetworkInterface, PackageRecord
from swinventory.server.domain import ChangeEvent, HostRecord, KernelState


class ConflictError(RuntimeError):
    """동시 요청이 같은 행을 먼저 만들었다(유니크 제약 위반). 트랜잭션은 롤백된 상태다."""


class InventoryRepository(ABC):
    """저장소 추상화. 쓰기 메서드는 transaction() 안에서 호출한다(Unit of Work)."""

    # --- 트랜잭션 ---------------------------------------------------------
    @abstractmethod
    def transaction(self) -> ContextManager[None]:
        """중첩 호출은 바깥 트랜잭션에 합류한다. 예외 시 전체 롤백."""

    @abstractmethod
    def ping(self) -> None:
        """DB 연결 확인(헬스체크). 실패하면 예외."""

    # --- 적재(쓰기) -------------------------------------------------------
    @abstractmethod
    def get_host(self, host_id: str) -> HostRecord | None: ...

    @abstractmethod
    def upsert_host(self, host: HostRecord) -> None: ...

    @abstractmethod
    def snapshot_exists(self, host_id: str, collected_at: str) -> bool: ...

    @abstractmethod
    def insert_snapshot(self, host_id: str, collected_at: str, received_at: str,
                        collected: list[str], errors: dict[str, str]) -> int: ...

    @abstractmethod
    def record_source_results(self, host_id: str, collected: Iterable[str], errors: dict[str, str], at: str) -> None: ...

    @abstractmethod
    def synced_sources(self, host_id: str) -> set[str]: ...

    @abstractmethod
    def mark_sources_synced(self, host_id: str, sources: Iterable[str], at: str) -> None: ...

    @abstractmethod
    def load_packages(self, host_id: str, sources: Iterable[str]) -> list[PackageRecord]: ...

    @abstractmethod
    def apply_package_changes(self, host_id: str, installed: list[PackageRecord],
                              removed: list[PackageRecord]) -> None: ...

    @abstractmethod
    def get_kernel_state(self, host_id: str) -> KernelState | None: ...

    @abstractmethod
    def save_kernel_state(self, host_id: str, kernel: KernelInfo, latest_installed: str, at: str) -> None: ...

    @abstractmethod
    def get_network(self, host_id: str) -> tuple[list[NetworkInterface], list[ListeningPort]]: ...

    @abstractmethod
    def replace_interfaces(self, host_id: str, interfaces: list[NetworkInterface]) -> None: ...

    @abstractmethod
    def replace_ports(self, host_id: str, ports: list[ListeningPort]) -> None: ...

    @abstractmethod
    def save_hardware(self, host_id: str, hardware: HardwareInfo, at: str) -> None: ...

    @abstractmethod
    def get_hardware(self, host_id: str) -> HardwareInfo | None: ...

    @abstractmethod
    def list_hardware(self) -> dict[str, HardwareInfo]: ...

    @abstractmethod
    def get_containers(self, host_id: str) -> list[ContainerRecord]: ...

    @abstractmethod
    def replace_containers(self, host_id: str, containers: list[ContainerRecord]) -> None: ...

    @abstractmethod
    def get_k8s(self, host_id: str) -> K8sNodeInfo | None: ...

    @abstractmethod
    def save_k8s(self, host_id: str, k8s: K8sNodeInfo | None, at: str) -> None:
        """None 이면 이 호스트는 더 이상 쿠버네티스 노드가 아니다(행 삭제)."""

    @abstractmethod
    def list_containers(self) -> list[dict[str, Any]]:
        """호스트×컨테이너 행: host_id, hostname + ContainerRecord 필드."""

    @abstractmethod
    def list_k8s_nodes(self) -> list[dict[str, Any]]:
        """쿠버네티스 노드 행: host_id, hostname, cluster_id, api_server, version, runtime."""

    @abstractmethod
    def add_events(self, host_id: str, snapshot_id: int | None, occurred_at: str,
                   events: list[ChangeEvent]) -> None: ...

    @abstractmethod
    def set_tags(self, host_id: str, tags: dict[str, str]) -> bool:
        """호스트가 없으면 False. 태그는 전체 교체."""

    @abstractmethod
    def delete_host(self, host_id: str) -> bool:
        """폐기된 호스트와 그 이력을 모두 지운다. 없으면 False."""

    @abstractmethod
    def prune(self, *, snapshots_before: str | None = None, events_before: str | None = None,
              hosts_before: str | None = None) -> dict[str, int]:
        """보존 기간을 넘긴 행을 지운다. 인자가 None 인 항목은 건드리지 않는다. 지운 건수를 돌려준다."""

    @abstractmethod
    def get_setting(self, key: str) -> str | None: ...

    @abstractmethod
    def set_setting(self, key: str, value: str, at: str) -> None: ...

    @abstractmethod
    def add_report(self, created_at: str, model: str, markdown: str, facts: dict[str, Any],
                   prompt_tokens: int | None, completion_tokens: int | None) -> int: ...

    @abstractmethod
    def delete_report(self, report_id: int) -> bool: ...

    # --- 조회(읽기) -------------------------------------------------------
    @abstractmethod
    def list_hosts(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def host_detail(self, host_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def overview(self, stale_before: str) -> dict[str, Any]: ...

    @abstractmethod
    def kernel_distribution(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def kernel_hosts(self, reboot_required: bool | None = None, running: str | None = None,
                     tags: dict[str, str] | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def software_search(self, q: str, limit: int = 100) -> list[dict[str, Any]]: ...

    @abstractmethod
    def software_hosts(self, q: str = "", host_id: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def software_detail(self, name: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def list_events(self, host_id: str | None = None, event_type: str | None = None,
                    since: str | None = None, limit: int | None = 100, offset: int = 0) -> list[dict[str, Any]]: ...

    @abstractmethod
    def count_events(self, host_id: str | None = None, event_type: str | None = None,
                     since: str | None = None) -> int: ...

    @abstractmethod
    def package_version_spread(self, min_versions: int = 3, limit: int = 20) -> list[dict[str, Any]]:
        """버전이 min_versions 개 이상으로 갈라진 패키지(파편화). 많이 갈라진 순."""

    @abstractmethod
    def count_events_by_type(self, since: str) -> dict[str, int]: ...

    @abstractmethod
    def list_reports(self, limit: int = 50) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_report(self, report_id: int) -> dict[str, Any] | None: ...

    @abstractmethod
    def list_ips(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """호스트×주소 행: host_id, hostname, interface, mac, state, address(CIDR), ip, family."""

    @abstractmethod
    def list_ports(self, tags: dict[str, str] | None = None) -> list[dict[str, Any]]:
        """호스트×리슨 포트 행: host_id, hostname, proto, port, bind."""

    # --- 자산 대장 --------------------------------------------------------
    @abstractmethod
    def list_assets(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_asset(self, asset_id: int) -> dict[str, Any] | None: ...

    @abstractmethod
    def create_asset(self, values: dict[str, Any], at: str) -> int:
        """자산번호(대소문자 무시)·명시 연결 host_id 가 이미 있으면 ConflictError."""

    @abstractmethod
    def update_asset(self, asset_id: int, values: dict[str, Any], at: str, expected_revision: int | None = None) -> bool:
        """전체 교체. 없으면 False. stale revision·유일 제약 위반은 ConflictError."""

    @abstractmethod
    def delete_asset(self, asset_id: int) -> bool: ...

    # --- 업무용 SW 분류·승인 요청 ---------------------------------------
    @abstractmethod
    def list_software_products(self, q: str, category: str | None, offset: int, limit: int) -> tuple[int, list[dict[str, Any]]]: ...

    @abstractmethod
    def get_software_classification(self, source: str, name: str, arch: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def set_software_classification(self, source: str, name: str, arch: str, values: dict[str, Any],
                                    actor_id: str, at: str, expected_revision: int | None) -> dict[str, Any]: ...

    @abstractmethod
    def software_classification_history(self, source: str, name: str, arch: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_software_request_scope(self, user_id: str) -> list[str]: ...

    @abstractmethod
    def replace_software_request_scope(self, user_id: str, host_ids: list[str], actor_id: str, at: str) -> None: ...

    @abstractmethod
    def software_request_scope_history(self, user_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def software_product_installed(self, source: str, name: str, arch: str, version: str, host_ids: list[str]) -> bool: ...

    @abstractmethod
    def create_software_request(self, values: dict[str, Any], host_ids: list[str], actor_id: str, at: str) -> int: ...

    @abstractmethod
    def list_software_requests(self, *, requester_id: str | None, status: str | None, q: str,
                               unassigned: bool, overdue_before: str | None, offset: int, limit: int) -> tuple[int, list[dict[str, Any]]]: ...

    @abstractmethod
    def get_software_request(self, request_id: int) -> dict[str, Any] | None: ...

    @abstractmethod
    def update_software_request(self, request_id: int, expected_revision: int, values: dict[str, Any],
                                actor_id: str, action: str, reason: str, detail: dict[str, Any],
                                at: str, approvals: list[dict[str, Any]] | None = None,
                                revoke_approvals: bool = False) -> None: ...

    @abstractmethod
    def list_vulnerabilities(self, *, q: str, kev_only: bool, impact_status: str | None,
                             offset: int, limit: int, host_id: str | None = None) -> tuple[int, list[dict[str, Any]]]: ...

    @abstractmethod
    def vulnerability_detail(self, cve_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def update_vulnerability_match(self, cve_id: str, source: str, name: str, arch: str, values: dict[str, Any],
                                   actor_id: str, at: str, expected_revision: int | None) -> dict[str, Any]: ...

    @abstractmethod
    def vulnerability_feed_status(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def replace_cisa_kev(self, values: list[dict[str, Any]], catalog_version: str, fetched_at: str) -> None: ...

    @abstractmethod
    def upsert_nvd_vulnerabilities(self, values: list[dict[str, Any]], fetched_at: str) -> None: ...

    @abstractmethod
    def record_vulnerability_feed(self, source: str, state: str, attempted_at: str, succeeded_at: str | None,
                                  error: str, data_version: str, records: int) -> None: ...


    # --- 사용자·JWT: 상태 변경은 auth_lock 안에서 직렬화한다 ---
    @abstractmethod
    def auth_lock(self): ...

    @abstractmethod
    def get_user(self, key: str, *, by_name: bool = False) -> dict[str, Any] | None: ...

    @abstractmethod
    def list_users(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def create_user(self, values: dict[str, Any]) -> None: ...

    @abstractmethod
    def update_user(self, user_id: str, values: dict[str, Any]) -> None: ...

    @abstractmethod
    def add_token(self, values: dict[str, Any]) -> None: ...

    @abstractmethod
    def find_token(self, digest: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def list_tokens(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def revoke_token(self, token_id: str) -> bool: ...

    @abstractmethod
    def login_attempt(self, key: str, now: int) -> int: ...
