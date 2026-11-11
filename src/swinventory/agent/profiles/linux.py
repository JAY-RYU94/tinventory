from __future__ import annotations

from abc import ABC

from swinventory.agent.collectors.base import BaseCollector
from swinventory.agent.collectors.debian import DebianKernel, DpkgSoftware
from swinventory.agent.collectors.containers import HelperContainers
from swinventory.agent.collectors.hardware import LinuxHardware
from swinventory.agent.collectors.linux_network import IpAddrInterfaces, ProcNetPorts
from swinventory.agent.collectors.os_info import LinuxOsCollector
from swinventory.agent.collectors.rhel import RhelKernel, RpmSoftware
from swinventory.agent.profiles.base import PlatformProfile
from swinventory.agent.runtime.command import CommandRunner
from swinventory.agent.runtime.fs import FileReader

MACHINE_ID_PATHS = ("/etc/machine-id", "/var/lib/dbus/machine-id")


class LinuxProfile(PlatformProfile, ABC):
    def __init__(self, fs: FileReader, runner: CommandRunner):
        self._fs = fs
        self._runner = runner

    def host_id(self) -> str:
        for path in MACHINE_ID_PATHS:
            try:
                host_id = self._fs.read_text(path).strip()
            except FileNotFoundError:
                continue
            if host_id:
                return host_id
        # 복제된 이미지·컨테이너에서는 비어 있을 수 있다. 안정적인 식별자를 임의로 만들어낼 수는 없다.
        raise RuntimeError(
            f"machine-id 를 찾지 못했다({', '.join(MACHINE_ID_PATHS)}). "
            "`systemd-machine-id-setup` 으로 생성한 뒤 다시 실행한다")


class DebianProfile(LinuxProfile):
    family = "debian"

    def collectors(self) -> list[BaseCollector]:
        return [LinuxOsCollector(self._fs), DebianKernel(self._runner), DpkgSoftware(self._runner),
                IpAddrInterfaces(self._runner), ProcNetPorts(self._fs), LinuxHardware(self._fs, self._runner), HelperContainers(self._fs)]


class RhelProfile(LinuxProfile):
    family = "rhel"

    def collectors(self) -> list[BaseCollector]:
        return [LinuxOsCollector(self._fs), RhelKernel(self._runner), RpmSoftware(self._runner),
                IpAddrInterfaces(self._runner), ProcNetPorts(self._fs), LinuxHardware(self._fs, self._runner), HelperContainers(self._fs)]
