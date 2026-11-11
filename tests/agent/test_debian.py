from swinventory.agent.collectors.debian import (
    DPKG_KERNEL_CMD, DPKG_LIST_CMD, DebianKernel, DpkgSoftware,
)
from swinventory.agent.runtime.command import CommandResult
from tests.fakes import FakeCommandRunner

UNAME = ("uname", "-r")


def test_dpkg_collects_only_installed_state_ii():
    out = (
        "bash\t5.1-6ubuntu1\tamd64\tii \n"
        "libc6\t2.35-0ubuntu3.6\tamd64\tii \n"
        "oldpkg\t1.0\tall\trc \n"
        "half\t2.0\tall\thi \n"
    )
    c = DpkgSoftware(FakeCommandRunner({DPKG_LIST_CMD: CommandResult(0, out)}))
    res = c.collect()
    assert c.name == "software.dpkg"
    assert res.ok
    assert [(p.name, p.version, p.arch, p.source) for p in res.value] == [
        ("bash", "5.1-6ubuntu1", "amd64", "dpkg"),
        ("libc6", "2.35-0ubuntu3.6", "amd64", "dpkg"),
    ]


def test_dpkg_failure_is_reported_not_raised():
    res = DpkgSoftware(FakeCommandRunner({})).collect()  # dpkg-query 없음
    assert not res.ok and res.value is None and res.error


def test_kernel_reboot_required_when_newer_installed():
    out = (
        "linux-image-5.15.0-91-generic\t5.15.0-91.101\tii \n"
        "linux-image-5.15.0-100-generic\t5.15.0-100.110\tii \n"
        "linux-image-generic\t5.15.0.100.98\tii \n"  # 메타 패키지 제외
        "linux-image-5.4.0-1-generic\t5.4.0-1.1\trc \n"  # 제거된 잔여 설정 제외
    )
    c = DebianKernel(FakeCommandRunner({
        UNAME: CommandResult(0, "5.15.0-91-generic\n"),
        DPKG_KERNEL_CMD: CommandResult(0, out),
    }))
    res = c.collect()
    assert res.ok
    k = res.value
    assert k.running == "5.15.0-91-generic"
    assert set(k.installed) == {"5.15.0-91-generic", "5.15.0-100-generic"}
    assert k.reboot_required is True


def test_kernel_running_is_latest_means_no_reboot():
    out = (
        "linux-image-5.15.0-91-generic\t5.15.0-91.101\tii \n"
        "linux-image-5.15.0-100-generic\t5.15.0-100.110\tii \n"
    )
    c = DebianKernel(FakeCommandRunner({
        UNAME: CommandResult(0, "5.15.0-100-generic\n"),
        DPKG_KERNEL_CMD: CommandResult(0, out),
    }))
    assert c.collect().value.reboot_required is False


def test_container_without_linux_image_reports_running_kernel_only():
    """컨테이너: dpkg-query 가 exit 1 + 'no packages found' → 실패가 아니라 실행 중 커널만 보고."""
    c = DebianKernel(FakeCommandRunner({
        UNAME: CommandResult(0, "6.5.0-1-generic\n"),
        DPKG_KERNEL_CMD: CommandResult(1, "", "dpkg-query: no packages found matching linux-image-*\n"),
    }))
    res = c.collect()
    assert res.ok
    assert res.value.running == "6.5.0-1-generic"
    assert res.value.installed == ("6.5.0-1-generic",)
    assert res.value.reboot_required is False


def test_other_dpkg_failure_is_a_real_failure():
    c = DebianKernel(FakeCommandRunner({
        UNAME: CommandResult(0, "6.5.0-1-generic\n"),
        DPKG_KERNEL_CMD: CommandResult(2, "", "dpkg-query: database corrupted"),
    }))
    res = c.collect()
    assert not res.ok and "corrupted" in res.error
