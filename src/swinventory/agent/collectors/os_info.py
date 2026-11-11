from __future__ import annotations

from abc import ABC
from typing import Any

from swinventory.agent.collectors.base import BaseCollector
from swinventory.agent.runtime.fs import FileReader
from swinventory.common.models import OsInfo

OS_RELEASE_PATH = "/etc/os-release"

_FAMILY_BY_ID = {
    "debian": "debian", "ubuntu": "debian",
    "rhel": "rhel", "centos": "rhel", "fedora": "rhel", "rocky": "rhel",
    "almalinux": "rhel", "ol": "rhel",
}


def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def linux_family(info: dict[str, str]) -> str | None:
    """ID 와 ID_LIKE 를 차례로 보고 지원하는 계열을 돌려준다. 모르면 None."""
    for token in [info.get("ID", ""), *info.get("ID_LIKE", "").split()]:
        family = _FAMILY_BY_ID.get(token.lower())
        if family:
            return family
    return None


class OsCollector(BaseCollector[OsInfo], ABC):
    @property
    def name(self) -> str:
        return "os"


class LinuxOsCollector(OsCollector):
    def __init__(self, fs: FileReader):
        self._fs = fs

    def _run(self) -> str:
        return self._fs.read_text(OS_RELEASE_PATH)

    def _parse(self, raw: Any) -> OsInfo:
        info = parse_os_release(raw)
        family = linux_family(info) or info.get("ID", "linux")
        return OsInfo(family=family,
                      name=info.get("PRETTY_NAME") or info.get("NAME", family),
                      version=info.get("VERSION_ID", ""))
