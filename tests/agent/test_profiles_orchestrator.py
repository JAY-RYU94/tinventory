from datetime import datetime, timezone

import pytest

from swinventory.agent.collectors.base import BaseCollector
from swinventory.agent.collectors.debian import DPKG_KERNEL_CMD, DPKG_LIST_CMD
from swinventory.agent.collectors.kernel import KernelCollector
from swinventory.agent.collectors.software import SoftwareCollector
from swinventory.agent.collectors.windows import CURRENT_VERSION_KEY
from swinventory.agent.orchestrator import SnapshotOrchestrator
from swinventory.agent.profiles import (
    DebianProfile, PlatformProfile, RhelProfile, UnsupportedPlatformError,
    WindowsProfile, detect_profile,
)
from swinventory.agent.runtime.command import CommandResult
from swinventory.common.models import KernelInfo, PackageRecord
from swinventory.agent.collectors.linux_network import IP_ADDR_CMD
from tests.fakes import IP_JSON_SIMPLE, PROC_NET_FILES, FakeCommandRunner, FakeFileReader, FakeRegistry

NOW = datetime(2026, 11, 5, 1, 2, 3, tzinfo=timezone.utc)


def _osrel(**kv) -> str:
    return "\n".join(f'{k}="{v}"' for k, v in kv.items()) + "\n"


def test_detect_debian_family():
    fs = FakeFileReader({"/etc/os-release": _osrel(ID="ubuntu", ID_LIKE="debian", VERSION_ID="22.04")})
    assert isinstance(detect_profile(fs=fs, runner=FakeCommandRunner()), DebianProfile)


def test_detect_rhel_family_via_id_like():
    fs = FakeFileReader({"/etc/os-release": _osrel(ID="rocky", ID_LIKE="rhel centos fedora")})
    assert isinstance(detect_profile(fs=fs, runner=FakeCommandRunner()), RhelProfile)


def test_detect_windows():
    p = detect_profile(fs=FakeFileReader(), runner=FakeCommandRunner(),
                       registry=FakeRegistry(), system="Windows")
    assert isinstance(p, WindowsProfile)


def test_detect_unsupported():
    fs = FakeFileReader({"/etc/os-release": _osrel(ID="arch")})
    with pytest.raises(UnsupportedPlatformError):
        detect_profile(fs=fs, runner=FakeCommandRunner())


def test_linux_host_id_from_machine_id():
    fs = FakeFileReader({"/etc/os-release": _osrel(ID="debian"), "/etc/machine-id": "abcd1234\n"})
    assert detect_profile(fs=fs, runner=FakeCommandRunner()).host_id() == "abcd1234"


def _linux(files):
    return detect_profile(fs=FakeFileReader({"/etc/os-release": _osrel(ID="debian"), **files}),
                          runner=FakeCommandRunner())


def test_host_id_falls_back_to_dbus_machine_id_when_etc_is_empty_or_missing():
    """실제 컨테이너/최소 설치: /etc/machine-id 가 비었거나 없다."""
    assert _linux({"/etc/machine-id": "\n", "/var/lib/dbus/machine-id": "dbus-id\n"}).host_id() == "dbus-id"
    assert _linux({"/var/lib/dbus/machine-id": "dbus-id\n"}).host_id() == "dbus-id"


def test_host_id_failure_message_says_how_to_fix():
    for files in ({}, {"/etc/machine-id": "  \n"}):
        with pytest.raises(RuntimeError, match="systemd-machine-id-setup"):
            _linux(files).host_id()


def test_windows_host_id_from_machine_guid():
    reg = FakeRegistry({("HKLM", r"SOFTWARE\Microsoft\Cryptography", 64): {"MachineGuid": "GUID-1"}})
    p = detect_profile(fs=FakeFileReader(), runner=FakeCommandRunner(), registry=reg, system="Windows")
    assert p.host_id() == "GUID-1"


def test_collector_naming_contract():
    fs = FakeFileReader({"/etc/os-release": _osrel(ID="debian")})
    names = [c.name for c in detect_profile(fs=fs, runner=FakeCommandRunner()).collectors()]
    assert "kernel" in names and "os" in names
    assert all(n.startswith(("software.", "network.")) for n in names if n not in ("kernel", "os", "hardware", "containers"))
    assert {"network.interfaces", "network.ports", "hardware"} <= set(names)


# --- 오케스트레이터 -------------------------------------------------------

class _OkSoftware(SoftwareCollector):
    source = "fake_ok"

    def _run(self):
        return "x"

    def _parse(self, raw):
        return [PackageRecord(self.source, "pkg", "1", "all")]


class _BadSoftware(SoftwareCollector):
    source = "fake_bad"

    def _run(self):
        raise RuntimeError("boom")

    def _parse(self, raw):  # pragma: no cover
        return []


class _OkKernel(KernelCollector):
    def _run(self):
        return "k"

    def _parse(self, raw):
        return KernelInfo("1.0", ("1.0",), False)


class _FakeProfile(PlatformProfile):
    family = "fake"

    def __init__(self, collectors: list[BaseCollector]):
        self._c = collectors

    def host_id(self) -> str:
        return "host-1"

    def collectors(self):
        return self._c


def _orch(profile):
    return SnapshotOrchestrator(profile, clock=lambda: NOW, hostname_fn=lambda: "web01", agent_version="9.9")


def test_failure_isolated_and_recorded_in_errors():
    snap = _orch(_FakeProfile([_BadSoftware(), _OkSoftware(), _OkKernel()])).collect()
    assert snap.host_id == "host-1" and snap.hostname == "web01" and snap.agent_version == "9.9"
    assert snap.collected_at == "2026-11-05T01:02:03+00:00"
    assert snap.errors == {"software.fake_bad": "RuntimeError: boom"}
    assert snap.collected == ["software.fake_ok", "kernel"]
    assert [p.name for p in snap.packages] == ["pkg"]
    assert snap.kernel is not None and snap.os is None


def test_full_debian_profile_partial_failure():
    """dpkg 만 실패(바이너리 없음)해도 커널·OS 는 수집되고 errors 에 source 만 남는다."""
    fs = FakeFileReader({
        "/etc/os-release": _osrel(ID="ubuntu", ID_LIKE="debian", VERSION_ID="22.04", PRETTY_NAME="Ubuntu 22.04"),
        "/etc/machine-id": "mid\n", **PROC_NET_FILES,
    })
    runner = FakeCommandRunner({
        ("uname", "-r"): CommandResult(0, "5.15.0-91-generic\n"),
        DPKG_KERNEL_CMD: CommandResult(1, "", "dpkg-query: no packages found matching linux-image-*"),
        IP_ADDR_CMD: CommandResult(0, IP_JSON_SIMPLE),
    })
    assert DPKG_LIST_CMD not in runner.responses
    snap = _orch(detect_profile(fs=fs, runner=runner)).collect()
    assert set(snap.errors) == {"software.dpkg"}
    assert snap.os.family == "debian" and snap.os.name == "Ubuntu 22.04"
    assert snap.kernel.running == "5.15.0-91-generic"
    assert set(snap.collected) == {"os", "kernel", "network.interfaces", "network.ports", "hardware"}
    assert [(i.name, i.mac, i.addresses) for i in snap.interfaces] == [("eth0", "02:42:ac:11:00:02", ("10.0.0.5/24",))]
    assert [(p.proto, p.port, p.bind) for p in snap.ports] == [("tcp", 22, "0.0.0.0")]
    assert snap.hardware is not None and snap.hardware.kind == "unknown"          # DMI·감지 도구가 없으면 추측하지 않는다


def test_hardware_reaches_the_snapshot_for_linux_and_windows():
    """수집기가 성공해도 오케스트레이터가 snap.hardware 에 담지 않으면 서버는 영영 장비 정보를 받지 못한다(부작위 결함)."""
    from swinventory.agent.collectors.hardware import DMI_DIR, HOSTNAME_F_CMD, VIRT_CONTAINER_CMD, VIRT_VM_CMD

    fs = FakeFileReader({
        "/etc/os-release": _osrel(ID="ubuntu", ID_LIKE="debian", VERSION_ID="22.04", PRETTY_NAME="Ubuntu 22.04"),
        "/etc/machine-id": "mid\n", f"{DMI_DIR}/sys_vendor": "Dell Inc.\n", f"{DMI_DIR}/product_name": "PowerEdge R740\n",
        f"{DMI_DIR}/product_serial": "ABC1234\n", **PROC_NET_FILES,
    })
    runner = FakeCommandRunner({
        ("uname", "-r"): CommandResult(0, "5.15.0-91-generic\n"), IP_ADDR_CMD: CommandResult(0, IP_JSON_SIMPLE),
        VIRT_VM_CMD: CommandResult(1, "none\n"), VIRT_CONTAINER_CMD: CommandResult(1, "none\n"),
        HOSTNAME_F_CMD: CommandResult(0, "web01.corp.example.com\n"),
    })
    hw = _orch(detect_profile(fs=fs, runner=runner)).collect().hardware
    assert (hw.kind, hw.vendor, hw.serial, hw.fqdn, hw.domain) == ("physical", "Dell Inc.", "ABC1234", "web01.corp.example.com", "corp.example.com")


def test_container_collector_not_applicable_is_silent_and_values_reach_the_snapshot():
    """헬퍼가 없는 호스트는 collected 에도 errors 에도 containers 가 나타나면 안 된다(서버가 '전부 삭제'로 오해하거나 수집 오류가 쏟아진다).
    값이 있으면 오케스트레이터가 스냅샷에 담아야 한다(담지 않으면 서버는 영영 못 받는다 — 부작위 결함)."""
    from datetime import datetime, timezone

    from swinventory.agent.collectors.containers import HELPER_DIR, HelperContainers

    now = lambda: datetime.fromtimestamp(1700000200, timezone.utc)  # noqa: E731
    silent = _orch(_FakeProfile([_OkKernel(), HelperContainers(FakeFileReader({}), now)])).collect()
    assert "containers" not in silent.collected and "containers" not in silent.errors and silent.containers == [] and silent.k8s is None
    files = {f"{HELPER_DIR}/collected_at.txt": "1700000100\n", f"{HELPER_DIR}/k8s_version.txt": "Kubernetes v1.29.3\n",
             f"{HELPER_DIR}/docker_ps.jsonl": '{"id":"' + "a" * 64 + '","name":"web","image":"nginx:1.25","state":"running","created":"2026-11-06 10:34:18 +0000 UTC"}\n'}
    snap = _orch(_FakeProfile([HelperContainers(FakeFileReader(files), now)])).collect()
    assert snap.collected == ["containers"] and [(c.name, c.image, c.state) for c in snap.containers] == [("web", "nginx:1.25", "running")]
    assert snap.k8s is not None and snap.k8s.version == "v1.29.3"


def test_both_linux_profiles_include_the_container_collector():
    """헬퍼가 없는 호스트에서는 조용히 건너뛰므로 수집 결과만으로는 프로필 누락을 알 수 없다 — 구성 자체를 확인한다."""
    from swinventory.agent.collectors.containers import HelperContainers

    for os_id, like in (("ubuntu", "debian"), ("rocky", "rhel fedora")):
        fs = FakeFileReader({"/etc/os-release": _osrel(ID=os_id, ID_LIKE=like, VERSION_ID="1", PRETTY_NAME="x"), "/etc/machine-id": "m\n"})
        profile = detect_profile(fs=fs, runner=FakeCommandRunner({}))
        assert any(isinstance(c, HelperContainers) for c in profile.collectors()), os_id
