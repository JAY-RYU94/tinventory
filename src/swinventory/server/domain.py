from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    PACKAGE_INSTALLED = "package_installed"
    PACKAGE_REMOVED = "package_removed"
    PACKAGE_VERSION_CHANGED = "package_version_changed"
    KERNEL_CHANGED = "kernel_changed"
    OS_CHANGED = "os_changed"
    IP_ADDED = "ip_added"
    IP_REMOVED = "ip_removed"
    MAC_CHANGED = "mac_changed"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    CONTAINER_IMAGE_ADDED = "container_image_added"
    CONTAINER_IMAGE_REMOVED = "container_image_removed"
    CONTAINER_IMAGE_CHANGED = "container_image_changed"


@dataclass(frozen=True)
class ChangeEvent:
    """변경 1건. subject_type/subject_key 로 일반화해 CVE·컨테이너 같은 새 대상도 같은 테이블에 담는다."""

    event_type: EventType
    subject_type: str  # package | kernel | os | ...
    subject_key: str
    old_value: str | None = None
    new_value: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class HostRecord:
    host_id: str
    hostname: str
    agent_version: str
    first_seen: str
    last_seen: str
    last_snapshot_at: str
    os_family: str = ""
    os_name: str = ""
    os_version: str = ""
    last_errors: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class KernelState:
    running: str
    latest_installed: str
    reboot_required: bool
