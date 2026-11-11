import json

import pytest

from swinventory.agent.collectors.hardware import (
    DMI_DIR, HOSTNAME_F_CMD, SERIAL_FALLBACK_PATH, VIRT_CONTAINER_CMD, VIRT_VM_CMD, LinuxHardware,
)
from swinventory.agent.collectors.windows import WIN_BIOS_CMD, WIN_SYSTEM_CMD, WinHardware
from swinventory.agent.runtime.command import CommandResult
from swinventory.common.models import HardwareInfo
from tests.fakes import FakeCommandRunner, FakeFileReader


def dmi(vendor="Dell Inc.", product="PowerEdge R740", serial="ABC1234", extra=None):
    files = {f"{DMI_DIR}/sys_vendor": vendor + "\n", f"{DMI_DIR}/product_name": product + "\n"}
    if serial is not None:
        files[f"{DMI_DIR}/product_serial"] = serial + "\n"
    return {**files, **(extra or {})}


def runner(vm="none", container="none", fqdn="web01.corp.example.com"):
    resp = {}
    if vm is not None:
        resp[VIRT_VM_CMD] = CommandResult(0 if vm != "none" else 1, vm + "\n")
    if container is not None:
        resp[VIRT_CONTAINER_CMD] = CommandResult(0 if container != "none" else 1, container + "\n")
    if fqdn is not None:
        resp[HOSTNAME_F_CMD] = CommandResult(0, fqdn + "\n")
    return FakeCommandRunner(resp)


def test_physical_server_with_readable_serial_and_domain():
    res = LinuxHardware(FakeFileReader(dmi()), runner()).collect()
    assert res.ok and res.name == "hardware"
    assert res.value == HardwareInfo("physical", "", "Dell Inc.", "PowerEdge R740", "ABC1234", "web01.corp.example.com", "corp.example.com")


def test_vm_detected_by_systemd_detect_virt():
    res = LinuxHardware(FakeFileReader(dmi("VMware, Inc.", "VMware7,1", "VMware-56 4d")), runner(vm="vmware")).collect()
    assert (res.value.kind, res.value.virt, res.value.serial) == ("virtual", "vmware", "VMware-56 4d")


def test_container_wins_over_vm():
    res = LinuxHardware(FakeFileReader(dmi("QEMU", "KVM")), runner(vm="kvm", container="docker")).collect()
    assert (res.value.kind, res.value.virt) == ("container", "docker")


def test_container_marker_files_are_used_when_systemd_detect_virt_is_missing():
    """컨테이너는 호스트의 DMI 를 그대로 읽는다 — 감지 도구가 없어도 표식 파일로 컨테이너임을 알아야 물리·VM 으로 오판하지 않는다."""
    r = runner(vm=None, container=None)
    docker = LinuxHardware(FakeFileReader(dmi("Dell Inc.", "PowerEdge R740", extra={"/.dockerenv": ""})), r).collect().value
    assert (docker.kind, docker.virt) == ("container", "docker")
    podman = LinuxHardware(FakeFileReader(dmi(extra={"/run/.containerenv": ""})), r).collect().value
    assert (podman.kind, podman.virt) == ("container", "podman")


def test_marker_files_do_not_override_the_detection_tool():
    """도구가 '컨테이너 아님'이라고 답했으면 표식 파일은 보지 않는다(도구가 더 정확하다)."""
    res = LinuxHardware(FakeFileReader(dmi(extra={"/.dockerenv": ""})), runner(vm="none", container="none")).collect().value
    assert res.kind == "physical"


def test_unreadable_serial_is_not_an_error():
    """product_serial 은 대개 root 만 읽는다. 에이전트는 root 없이 도므로 시리얼만 비고 수집은 성공해야 한다."""
    class Denied(FakeFileReader):
        def read_text(self, path):
            if path.endswith("product_serial"):
                raise PermissionError(path)
            return super().read_text(path)
    res = LinuxHardware(Denied(dmi(serial=None)), runner()).collect()
    assert res.ok and res.value.serial == "" and res.value.kind == "physical"


class _DmiSerialDenied(FakeFileReader):
    def read_text(self, path):
        if path.endswith("product_serial"):
            raise PermissionError(path)
        return super().read_text(path)


def test_serial_falls_back_to_the_file_the_installer_captured_as_root():
    """비특권 에이전트는 product_serial 을 못 읽는다 — 설치 스크립트(root)가 한 번 읽어 둔 값을 쓴다."""
    files = dmi(serial=None, extra={SERIAL_FALLBACK_PATH: "ABC1234\n"})
    assert LinuxHardware(_DmiSerialDenied(files), runner()).collect().value.serial == "ABC1234"


def test_direct_dmi_serial_wins_over_the_fallback_file():
    files = dmi(serial="LIVE-SN", extra={SERIAL_FALLBACK_PATH: "OLD-SN\n"})
    assert LinuxHardware(FakeFileReader(files), runner()).collect().value.serial == "LIVE-SN"


def test_placeholder_in_the_fallback_file_is_dropped_and_missing_file_is_fine():
    assert LinuxHardware(_DmiSerialDenied(dmi(serial=None, extra={SERIAL_FALLBACK_PATH: "To Be Filled By O.E.M.\n"})), runner()).collect().value.serial == ""
    assert LinuxHardware(_DmiSerialDenied(dmi(serial=None)), runner()).collect().value.serial == ""


def test_placeholder_serial_is_dropped():
    res = LinuxHardware(FakeFileReader(dmi(serial="To Be Filled By O.E.M.")), runner()).collect()
    assert res.value.serial == ""


def test_without_systemd_detect_virt_falls_back_to_dmi_and_cpu_flag():
    r = runner(vm=None, container=None)
    assert LinuxHardware(FakeFileReader(dmi("QEMU", "Standard PC (Q35 + ICH9, 2009)")), r).collect().value.virt == "kvm"
    cpu = {"/proc/cpuinfo": "flags\t\t: fpu vme hypervisor lm\n"}
    res = LinuxHardware(FakeFileReader(dmi("", "", None, cpu)), r).collect()
    assert (res.value.kind, res.value.virt) == ("virtual", "unknown")


def test_no_dmi_at_all_is_unknown_not_physical():
    res = LinuxHardware(FakeFileReader({}), runner(vm=None, container=None, fqdn=None)).collect()
    assert res.ok and res.value.kind == "unknown" and res.value.fqdn == "" and res.value.domain == ""


def test_hostname_without_domain():
    res = LinuxHardware(FakeFileReader(dmi()), runner(fqdn="web01")).collect()
    assert res.value.fqdn == "web01" and res.value.domain == ""


def test_hostname_f_failure_does_not_fail_collection():
    r = FakeCommandRunner({VIRT_VM_CMD: CommandResult(1, "none\n"), VIRT_CONTAINER_CMD: CommandResult(1, "none\n"),
                           HOSTNAME_F_CMD: CommandResult(1, "", "hostname: Name or service not known")})
    res = LinuxHardware(FakeFileReader(dmi()), r).collect()
    assert res.ok and res.value.fqdn == "" and res.value.kind == "physical"


def test_control_characters_in_dmi_strings_are_stripped():
    res = LinuxHardware(FakeFileReader(dmi("Dell\x00 Inc.", "R740\x1b[31m", "SN\x001")), runner()).collect()
    assert "\x00" not in res.value.vendor + res.value.serial and "\x1b" not in res.value.model


# --- Windows (참조 구현: C# 에이전트와 같은 규칙) ---
def win_runner(system, bios):
    return FakeCommandRunner({WIN_SYSTEM_CMD: CommandResult(0, json.dumps(system)), WIN_BIOS_CMD: CommandResult(0, json.dumps(bios))})


def test_windows_domain_joined_physical():
    r = win_runner({"Manufacturer": "Dell Inc.", "Model": "PowerEdge R640", "Domain": "corp.example.com", "PartOfDomain": True, "DNSHostName": "WIN-APP01"},
                   {"SerialNumber": "7XK2M3"})
    v = WinHardware(r).collect().value
    assert v == HardwareInfo("physical", "", "Dell Inc.", "PowerEdge R640", "7XK2M3", "WIN-APP01.corp.example.com", "corp.example.com")


def test_windows_workgroup_has_no_domain_and_hyperv_vm():
    r = win_runner({"Manufacturer": "Microsoft Corporation", "Model": "Virtual Machine", "Domain": "WORKGROUP", "PartOfDomain": False, "DNSHostName": "WIN-VM1"},
                   {"SerialNumber": "1234-5678-9012"})
    v = WinHardware(r).collect().value
    assert (v.kind, v.virt, v.domain, v.fqdn) == ("virtual", "hyperv", "", "WIN-VM1")      # 워크그룹명은 도메인이 아니다


def test_windows_bios_failure_keeps_system_info():
    r = FakeCommandRunner({WIN_SYSTEM_CMD: CommandResult(0, json.dumps({"Manufacturer": "VMware, Inc.", "Model": "VMware7,1", "Domain": "x", "PartOfDomain": False, "DNSHostName": "h"})),
                           WIN_BIOS_CMD: CommandResult(1, "", "access denied")})
    res = WinHardware(r).collect()
    assert res.ok and res.value.serial == "" and res.value.virt == "vmware"


def test_windows_system_failure_fails_collection():
    r = FakeCommandRunner({WIN_SYSTEM_CMD: CommandResult(1, "", "boom"), WIN_BIOS_CMD: CommandResult(0, "{}")})
    assert not WinHardware(r).collect().ok
