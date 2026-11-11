from __future__ import annotations

from swinventory.agent.collectors.base import BaseCollector
from swinventory.agent.collectors.windows import (
    WinHardware, WinHotfixSoftware, WinInterfaces, WinKernel, WinOs, WinPorts, WinRegistrySoftware,
)
from swinventory.agent.profiles.base import PlatformProfile
from swinventory.agent.runtime.command import CommandRunner
from swinventory.agent.runtime.registry import HKLM, RegistryReader

CRYPTOGRAPHY_KEY = r"SOFTWARE\Microsoft\Cryptography"


class WindowsProfile(PlatformProfile):
    family = "windows"

    def __init__(self, runner: CommandRunner, registry: RegistryReader):
        self._runner = runner
        self._reg = registry

    def host_id(self) -> str:
        vals = self._reg.values(HKLM, CRYPTOGRAPHY_KEY, 64) or {}
        guid = str(vals.get("MachineGuid", "")).strip()
        if not guid:
            raise RuntimeError("MachineGuid 를 읽지 못했다")
        return guid

    def collectors(self) -> list[BaseCollector]:
        return [
            WinOs(self._reg), WinKernel(self._reg),
            WinRegistrySoftware(self._reg), WinHotfixSoftware(self._runner),
            WinInterfaces(self._runner), WinPorts(self._runner), WinHardware(self._runner),
        ]
