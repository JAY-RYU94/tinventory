from swinventory.agent.collectors.windows import (
    CURRENT_VERSION_KEY, HOTFIX_CMD, REBOOT_PENDING_KEY, REBOOT_REQUIRED_KEY,
    UNINSTALL_KEY, WinHotfixSoftware, WinKernel, WinOs, WinRegistrySoftware,
)
from swinventory.agent.runtime.command import CommandResult
from tests.fakes import FakeCommandRunner, FakeRegistry

HKLM = "HKLM"


def _uninstall_registry() -> FakeRegistry:
    base = UNINSTALL_KEY
    return FakeRegistry({
        (HKLM, base, 64): {},
        (HKLM, base + r"\{A}", 64): {"DisplayName": "Git", "DisplayVersion": "2.45.0"},
        (HKLM, base + r"\{B}", 64): {"DisplayName": "Hidden Comp", "SystemComponent": 1},
        (HKLM, base + r"\{C}", 64): {"DisplayName": "OS Part", "ParentKeyName": "OperatingSystem"},
        (HKLM, base + r"\KB5034441", 64): {
            "DisplayName": "Security Update for Windows (KB5034441)", "ReleaseType": "Security Update"},
        (HKLM, base + r"\{E}", 64): {"DisplayVersion": "1.0"},  # DisplayName 없음
        (HKLM, base, 32): {},
        (HKLM, base + r"\{D}", 32): {"DisplayName": "Legacy Tool", "DisplayVersion": "1.0"},
        (HKLM, base + r"\{A2}", 32): {"DisplayName": "Git", "DisplayVersion": "2.45.0"},
    })


def test_registry_software_filters_and_tags_arch():
    c = WinRegistrySoftware(_uninstall_registry())
    res = c.collect()
    assert c.name == "software.win_registry"
    assert res.ok
    got = sorted((p.name, p.version, p.arch) for p in res.value)
    # 같은 이름이라도 64/32비트 arch 가 다르면 별개 항목
    assert got == [("Git", "2.45.0", "x64"), ("Git", "2.45.0", "x86"), ("Legacy Tool", "1.0", "x86")]


def test_hotfix_single_object_json():
    out = '{"HotFixID":"KB5034441","InstalledOn":null}'
    res = WinHotfixSoftware(FakeCommandRunner({HOTFIX_CMD: CommandResult(0, out)})).collect()
    assert res.ok
    assert [(p.source, p.name) for p in res.value] == [("win_hotfix", "KB5034441")]


def test_hotfix_array_json_and_empty_output():
    arr = '[{"HotFixID":"KB1"},{"HotFixID":"KB2"}]'
    res = WinHotfixSoftware(FakeCommandRunner({HOTFIX_CMD: CommandResult(0, arr)})).collect()
    assert [p.name for p in res.value] == ["KB1", "KB2"]
    empty = WinHotfixSoftware(FakeCommandRunner({HOTFIX_CMD: CommandResult(0, "  \n")})).collect()
    assert empty.ok and empty.value == []


def test_hotfix_powershell_failure():
    res = WinHotfixSoftware(FakeCommandRunner({HOTFIX_CMD: CommandResult(1, "", "denied")})).collect()
    assert not res.ok


def _cv(**extra) -> dict:
    return {"CurrentBuildNumber": "22631", "UBR": 3085, **extra}


def test_kernel_version_is_10_0_build_ubr():
    reg = FakeRegistry({(HKLM, CURRENT_VERSION_KEY, 64): _cv()})
    k = WinKernel(reg).collect().value
    assert k.running == "10.0.22631.3085"
    assert k.installed == ("10.0.22631.3085",)
    assert k.reboot_required is False


def test_reboot_pending_keys():
    for key in (REBOOT_PENDING_KEY, REBOOT_REQUIRED_KEY):
        reg = FakeRegistry({(HKLM, CURRENT_VERSION_KEY, 64): _cv(), (HKLM, key, 64): {}})
        assert WinKernel(reg).collect().value.reboot_required is True


def test_kernel_failure_when_version_key_missing():
    assert not WinKernel(FakeRegistry()).collect().ok


def test_win_os_info():
    reg = FakeRegistry({(HKLM, CURRENT_VERSION_KEY, 64): _cv(
        ProductName="Windows Server 2022 Standard", DisplayVersion="21H2")})
    os_ = WinOs(reg).collect().value
    assert (os_.family, os_.name, os_.version) == ("windows", "Windows Server 2022 Standard", "21H2")
