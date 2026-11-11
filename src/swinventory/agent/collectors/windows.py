from __future__ import annotations

import json
import re
from typing import Any

from swinventory.agent.collectors.hardware import HardwareCollector
from swinventory.agent.collectors.kernel import KernelCollector
from swinventory.agent.collectors.network import InterfaceCollector, PortCollector
from swinventory.agent.collectors.os_info import OsCollector
from swinventory.agent.collectors.software import SoftwareCollector
from swinventory.agent.runtime.command import CommandRunner, run_checked
from swinventory.agent.runtime.registry import HKLM, RegistryReader
from swinventory.common.hardware import classify_virtualization, clean_serial, clean_text, domain_of
from swinventory.common.models import HardwareInfo, KernelInfo, ListeningPort, NetworkInterface, OsInfo, PackageRecord

UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
CURRENT_VERSION_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
REBOOT_PENDING_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
REBOOT_REQUIRED_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

# Win32_Product(WMI)는 느리고 MSI 복구를 유발하므로 쓰지 않는다.
HOTFIX_CMD = (
    "powershell", "-NoProfile", "-NonInteractive", "-Command",
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-HotFix | Select-Object HotFixID | ConvertTo-Json -Compress",
)

def _ps(script: str) -> tuple[str, ...]:
    return ("powershell", "-NoProfile", "-NonInteractive", "-Command",
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script + " | ConvertTo-Json -Compress")


ADAPTERS_CMD = _ps("Get-NetAdapter | Select-Object Name,MacAddress,Status")
ADDRS_CMD = _ps("Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength")
TCP_LISTEN_CMD = _ps("Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort")
UDP_ENDPOINT_CMD = _ps("Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort")
# Win32_BIOS.SerialNumber 는 관리자 권한 없이 조회된다(실제 Windows 에서 LOCAL SERVICE 로 검증하지 못함 — README 한계 참고).
# HypervisorPresent 는 Hyper-V 역할이 있는 물리 서버에서도 참이라 쓰지 않는다 — 제조사·모델 문자열로만 판정한다.
WIN_SYSTEM_CMD = _ps("Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,Domain,PartOfDomain,DNSHostName")
WIN_BIOS_CMD = _ps("Get-CimInstance Win32_BIOS | Select-Object SerialNumber")
WIN_EPHEMERAL_START = 49152  # Windows 기본 동적 포트 범위(49152-65535)


def _ps_json_list(text: str) -> list[dict]:
    """PowerShell 은 1건이면 객체, 여러 건이면 배열, 0건이면 빈 출력을 낸다."""
    text = text.strip()
    if not text:
        return []
    data = json.loads(text)
    return [data] if isinstance(data, dict) else data


_UPDATE_RELEASE_TYPES = {"update", "hotfix", "security update", "update rollup", "service pack", "critical update"}
_KB_KEY = re.compile(r"^KB\d+$", re.IGNORECASE)


class WinRegistrySoftware(SoftwareCollector):
    source = "win_registry"
    _VIEWS = ((64, "x64"), (32, "x86"))

    def __init__(self, registry: RegistryReader):
        self._reg = registry

    def _run(self) -> list[tuple[str, str, dict[str, Any]]]:
        entries = []
        for view, arch in self._VIEWS:
            for sub in self._reg.subkeys(HKLM, UNINSTALL_KEY, view):
                vals = self._reg.values(HKLM, f"{UNINSTALL_KEY}\\{sub}", view)
                if vals is not None:
                    entries.append((arch, sub, vals))
        return entries

    def _parse(self, raw: Any) -> list[PackageRecord]:
        seen: dict[tuple[str, str, str], PackageRecord] = {}
        for arch, sub, vals in raw:
            name = str(vals.get("DisplayName") or "").strip()
            if not name:
                continue
            if vals.get("SystemComponent") == 1 or vals.get("ParentKeyName"):
                continue
            if str(vals.get("ReleaseType", "")).lower() in _UPDATE_RELEASE_TYPES or _KB_KEY.match(sub):
                continue
            version = str(vals.get("DisplayVersion") or "").strip()
            seen.setdefault((name, version, arch), PackageRecord(self.source, name, version, arch))
        return list(seen.values())


class WinHotfixSoftware(SoftwareCollector):
    source = "win_hotfix"

    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def _run(self) -> str:
        return run_checked(self._runner, HOTFIX_CMD, timeout=120.0).stdout

    def _parse(self, raw: Any) -> list[PackageRecord]:
        text = raw.strip()
        if not text:
            return []
        data = json.loads(text)
        if isinstance(data, dict):  # PowerShell 은 1건이면 객체, 여러 건이면 배열
            data = [data]
        ids = dict.fromkeys(str(item["HotFixID"]).strip() for item in data if item.get("HotFixID"))
        return [PackageRecord(self.source, kb, "", "") for kb in ids]


class WinKernel(KernelCollector):
    def __init__(self, registry: RegistryReader):
        self._reg = registry

    def _run(self) -> tuple[dict[str, Any] | None, bool]:
        vals = self._reg.values(HKLM, CURRENT_VERSION_KEY)
        reboot = any(self._reg.key_exists(HKLM, k) for k in (REBOOT_PENDING_KEY, REBOOT_REQUIRED_KEY))
        return vals, reboot

    def _parse(self, raw: Any) -> KernelInfo:
        vals, reboot = raw
        if not vals or "CurrentBuildNumber" not in vals:
            raise LookupError(f"{CURRENT_VERSION_KEY} 에서 CurrentBuildNumber 를 읽지 못했다")
        running = f"10.0.{vals['CurrentBuildNumber']}.{vals.get('UBR', 0)}"
        return KernelInfo(running=running, installed=(running,), reboot_required=reboot)


class WinOs(OsCollector):
    def __init__(self, registry: RegistryReader):
        self._reg = registry

    def _run(self) -> dict[str, Any] | None:
        return self._reg.values(HKLM, CURRENT_VERSION_KEY)

    def _parse(self, raw: Any) -> OsInfo:
        if not raw:
            raise LookupError(f"{CURRENT_VERSION_KEY} 를 읽지 못했다")
        version = raw.get("DisplayVersion") or raw.get("ReleaseId") or str(raw.get("CurrentBuildNumber", ""))
        return OsInfo(family="windows", name=str(raw.get("ProductName", "Windows")), version=str(version))


class WinInterfaces(InterfaceCollector):
    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def _run(self) -> tuple[str, str]:
        return (run_checked(self._runner, ADAPTERS_CMD, timeout=120.0).stdout,
                run_checked(self._runner, ADDRS_CMD, timeout=120.0).stdout)

    def _parse(self, raw: Any) -> list[NetworkInterface]:
        import ipaddress  # noqa: PLC0415

        adapters, addrs = _ps_json_list(raw[0]), _ps_json_list(raw[1])
        by_alias: dict[str, list[str]] = {}
        for a in addrs:
            ip = ipaddress.ip_address(str(a["IPAddress"]).split("%", 1)[0])
            if ip.is_loopback or ip.is_link_local:
                continue
            by_alias.setdefault(a["InterfaceAlias"], []).append(f"{ip}/{int(a['PrefixLength'])}")
        out = []
        for ad in adapters:
            mac = str(ad.get("MacAddress") or "").lower().replace("-", ":")
            out.append(NetworkInterface(ad["Name"], mac, "up" if str(ad.get("Status", "")).lower() == "up" else "down",
                                        tuple(sorted(by_alias.get(ad["Name"], [])))))
        return sorted(out, key=lambda i: i.name)


class WinPorts(PortCollector):
    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def _run(self) -> tuple[str, str]:
        return (run_checked(self._runner, TCP_LISTEN_CMD, timeout=120.0).stdout,
                run_checked(self._runner, UDP_ENDPOINT_CMD, timeout=120.0).stdout)

    def _parse(self, raw: Any) -> list[ListeningPort]:
        found = {ListeningPort("tcp", int(r["LocalPort"]), str(r["LocalAddress"]).split("%", 1)[0]) for r in _ps_json_list(raw[0])}
        found |= {ListeningPort("udp", int(r["LocalPort"]), str(r["LocalAddress"]).split("%", 1)[0])
                  for r in _ps_json_list(raw[1]) if int(r["LocalPort"]) < WIN_EPHEMERAL_START}  # 동적 포트는 클라이언트 소켓
        return sorted(found, key=lambda p: (p.proto, p.port, p.bind))


class WinHardware(HardwareCollector):
    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def _run(self) -> tuple[str, str]:
        system = run_checked(self._runner, WIN_SYSTEM_CMD, timeout=60.0).stdout
        try:  # 시리얼만 못 얻어도 나머지 장비 정보는 남긴다
            bios = run_checked(self._runner, WIN_BIOS_CMD, timeout=60.0).stdout
        except Exception:  # noqa: BLE001
            bios = ""
        return system, bios

    def _parse(self, raw: Any) -> HardwareInfo:
        systems, bioses = _ps_json_list(raw[0]), _ps_json_list(raw[1]) if raw[1].strip() else []
        sys_ = systems[0] if systems else {}
        vendor, model = clean_text(sys_.get("Manufacturer")), clean_text(sys_.get("Model"))
        kind, virt = classify_virtualization(vendor=vendor, model=model)
        host = clean_text(sys_.get("DNSHostName"))
        joined = bool(sys_.get("PartOfDomain"))
        domain = clean_text(sys_.get("Domain")).lower() if joined else ""   # 워크그룹명은 도메인이 아니다
        fqdn = f"{host}.{domain}" if host and domain else host
        serial = clean_serial((bioses[0] if bioses else {}).get("SerialNumber"))
        return HardwareInfo(kind, virt, vendor, model, serial, fqdn, domain_of(fqdn) or domain)
