from swinventory.agent.collectors.rhel import (
    RPM_LIST_CMD, RhelKernel, RpmSoftware, rpm_kernel_cmd,
)
from swinventory.agent.runtime.command import CommandResult
from tests.fakes import FakeCommandRunner

UNAME = ("uname", "-r")
OLD, NEW = "5.14.0-362.8.1.el9_3", "5.14.0-427.13.1.el9_4"


def test_rpm_excludes_gpg_pubkey_and_keeps_multi_version_kernel():
    out = (
        "bash\t5.1.8-6.el9_1\tx86_64\n"
        f"kernel-core\t{OLD}\tx86_64\n"
        f"kernel-core\t{NEW}\tx86_64\n"
        "gpg-pubkey\t5a6340b3-6229229e\t(none)\n"
    )
    res = RpmSoftware(FakeCommandRunner({RPM_LIST_CMD: CommandResult(0, out)})).collect()
    assert res.ok
    names = [(p.name, p.version) for p in res.value]
    assert names == [("bash", "5.1.8-6.el9_1"), ("kernel-core", OLD), ("kernel-core", NEW)]
    assert RpmSoftware(FakeCommandRunner()).name == "software.rpm"


def test_kernel_core_multi_version_with_reboot():
    out = f"kernel-core\t{OLD}\tx86_64\nkernel-core\t{NEW}\tx86_64\n"
    c = RhelKernel(FakeCommandRunner({
        UNAME: CommandResult(0, f"{OLD}.x86_64\n"),
        rpm_kernel_cmd("kernel-core"): CommandResult(0, out),
    }))
    k = c.collect().value
    assert k.running == f"{OLD}.x86_64"
    assert set(k.installed) == {f"{OLD}.x86_64", f"{NEW}.x86_64"}
    assert k.reboot_required is True


def test_falls_back_to_kernel_package_when_no_kernel_core():
    c = RhelKernel(FakeCommandRunner({
        UNAME: CommandResult(0, "3.10.0-1160.el7.x86_64\n"),
        rpm_kernel_cmd("kernel-core"): CommandResult(1, "package kernel-core is not installed\n"),
        rpm_kernel_cmd("kernel"): CommandResult(0, "kernel\t3.10.0-1160.el7\tx86_64\n"),
    }))
    k = c.collect().value
    assert k.installed == ("3.10.0-1160.el7.x86_64",)
    assert k.reboot_required is False


def test_no_kernel_package_reports_running_only():
    c = RhelKernel(FakeCommandRunner({
        UNAME: CommandResult(0, "5.14.0-1.el9.x86_64\n"),
        rpm_kernel_cmd("kernel-core"): CommandResult(1, "package kernel-core is not installed\n"),
        rpm_kernel_cmd("kernel"): CommandResult(1, "package kernel is not installed\n"),
    }))
    res = c.collect()
    assert res.ok and res.value.installed == ("5.14.0-1.el9.x86_64",)


def test_rpm_real_error_is_failure():
    c = RhelKernel(FakeCommandRunner({
        UNAME: CommandResult(0, "5.14.0-1.el9.x86_64\n"),
        rpm_kernel_cmd("kernel-core"): CommandResult(1, "error: cannot open Packages database\n"),
    }))
    assert not c.collect().ok
