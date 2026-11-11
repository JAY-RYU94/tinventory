"""장비 정보 수집(VM/물리, 제조사·모델·시리얼, FQDN·도메인). 비특권(root 아님)으로 동작한다.

DMI(/sys/class/dmi/id)는 sys_vendor·product_name 은 누구나 읽지만 product_serial 은 보통 root 만 읽는다 —
읽지 못하면 시리얼만 비우고 수집은 성공으로 본다(자산 대장의 시리얼로 보완).
"""
from __future__ import annotations

from abc import ABC
from typing import Any

from swinventory.agent.collectors.base import BaseCollector
from swinventory.agent.runtime.command import CommandRunner
from swinventory.agent.runtime.fs import FileReader
from swinventory.common.hardware import classify_virtualization, clean_serial, clean_text, domain_of
from swinventory.common.models import HardwareInfo

DMI_DIR = "/sys/class/dmi/id"
CPUINFO_PATH = "/proc/cpuinfo"
# product_serial 은 root 만 읽는 경우가 많다 — 설치 스크립트(root)가 설치 때 한 번 읽어 이 파일에 저장해 둔다(없으면 건너뜀)
SERIAL_FALLBACK_PATH = "/etc/swinventory/dmi_serial"
# systemd-detect-virt 가 없는 최소 이미지에서 컨테이너를 알아보는 표식 파일
CONTAINER_MARKERS = (("/.dockerenv", "docker"), ("/run/.containerenv", "podman"))
VIRT_VM_CMD = ("systemd-detect-virt", "--vm")
VIRT_CONTAINER_CMD = ("systemd-detect-virt", "--container")
HOSTNAME_F_CMD = ("hostname", "-f")


class HardwareCollector(BaseCollector[HardwareInfo], ABC):
    @property
    def name(self) -> str:
        return "hardware"


class LinuxHardware(HardwareCollector):
    def __init__(self, fs: FileReader, runner: CommandRunner):
        self._fs = fs
        self._runner = runner

    def _read(self, name: str) -> str:
        try:
            return clean_text(self._fs.read_text(f"{DMI_DIR}/{name}"))
        except OSError:  # 없음(FileNotFoundError)·권한 없음(PermissionError)
            return ""

    def _serial(self) -> str:
        """DMI 를 직접 읽을 수 있으면 그 값, 아니면 설치 때 저장해 둔 값. 자리표시자는 어느 쪽이든 비운다."""
        direct = clean_serial(self._read("product_serial"))
        if direct:
            return direct
        try:
            lines = self._fs.read_text(SERIAL_FALLBACK_PATH).splitlines()
        except OSError:
            return ""
        return clean_serial(lines[0]) if lines else ""

    def _detect(self, cmd: tuple[str, ...]) -> str | None:
        """systemd-detect-virt: 가상화면 이름을 출력(종료 0), 아니면 'none'(종료 1). 도구가 없으면 None(DMI 로 추정)."""
        try:
            res = self._runner.run(cmd, timeout=10.0)
        except (FileNotFoundError, OSError):
            return None
        out = res.stdout.strip().splitlines()[0].strip() if res.stdout.strip() else ""
        return out if res.returncode == 0 and out else "none"

    def _detect_container(self) -> str | None:
        """감지 도구의 답이 우선이다. 도구가 없을 때(None)만 표식 파일을 본다."""
        detected = self._detect(VIRT_CONTAINER_CMD)
        return self._container_marker() if detected is None else detected

    def _container_marker(self) -> str | None:
        return next((name for path, name in CONTAINER_MARKERS if self._fs.exists(path)), None)

    def _hypervisor_flag(self) -> bool:
        try:
            text = self._fs.read_text(CPUINFO_PATH)
        except OSError:
            return False
        return any(line.startswith("flags") and " hypervisor" in line for line in text.splitlines())

    def _fqdn(self) -> str:
        try:
            res = self._runner.run(HOSTNAME_F_CMD, timeout=10.0)
        except (FileNotFoundError, OSError):
            return ""
        return clean_text(res.stdout.splitlines()[0]) if res.returncode == 0 and res.stdout.strip() else ""

    def _run(self) -> dict[str, Any]:
        return {
            "vendor": self._read("sys_vendor"), "model": self._read("product_name"), "serial": self._serial(),
            "bios_vendor": self._read("bios_vendor"),
            "vm": self._detect(VIRT_VM_CMD), "container": self._detect_container(),
            "flag": self._hypervisor_flag(), "fqdn": self._fqdn(),
        }

    def _parse(self, raw: Any) -> HardwareInfo:
        kind, virt = classify_virtualization(vendor=raw["vendor"], model=raw["model"], bios_vendor=raw["bios_vendor"],
                                             hypervisor_flag=raw["flag"], detected=raw["vm"], container=raw["container"])
        fqdn = raw["fqdn"]
        return HardwareInfo(kind, virt, raw["vendor"], raw["model"], clean_serial(raw["serial"]), fqdn, domain_of(fqdn))
