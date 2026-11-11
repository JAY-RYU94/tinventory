from swinventory.common.models import KernelInfo, OsInfo, PackageRecord
from swinventory.server.diff import KernelDiffer, OsDiffer, PackageDiffer
from swinventory.server.domain import EventType


def rpm(name, version, arch="x86_64"):
    return PackageRecord("rpm", name, version, arch)


def kinds(events):
    return sorted((e.event_type, e.subject_key, e.old_value, e.new_value) for e in events)


def test_install_remove_and_version_change():
    prev = [rpm("bash", "1"), rpm("vim", "1")]
    curr = [rpm("bash", "2"), rpm("git", "1")]
    assert kinds(PackageDiffer().diff(prev, curr)) == [
        (EventType.PACKAGE_INSTALLED, "git", None, "1"),
        (EventType.PACKAGE_REMOVED, "vim", "1", None),
        (EventType.PACKAGE_VERSION_CHANGED, "bash", "1", "2"),
    ]


def test_no_change_no_events():
    pkgs = [rpm("bash", "1")]
    assert PackageDiffer().diff(pkgs, list(pkgs)) == []


def test_stable_multi_version_package_produces_no_events():
    """kernel-core 가 2개 버전으로 계속 공존하면 수집 순서가 바뀌어도 이벤트가 없어야 한다."""
    a, b = rpm("kernel-core", "5.14-362"), rpm("kernel-core", "5.14-427")
    assert PackageDiffer().diff([a, b], [b, a]) == []


def test_kernel_core_upgrade_is_install_then_later_remove_not_version_changed():
    a, b, c = (rpm("kernel-core", v) for v in ("1", "2", "3"))
    step1 = PackageDiffer().diff([a], [a, b])
    assert kinds(step1) == [(EventType.PACKAGE_INSTALLED, "kernel-core", None, "2")]
    step2 = PackageDiffer().diff([a, b], [b])
    assert kinds(step2) == [(EventType.PACKAGE_REMOVED, "kernel-core", "1", None)]
    step3 = PackageDiffer().diff([a, b], [b, c])
    assert kinds(step3) == [
        (EventType.PACKAGE_INSTALLED, "kernel-core", None, "3"),
        (EventType.PACKAGE_REMOVED, "kernel-core", "1", None),
    ]


def test_arch_is_part_of_identity():
    prev = [rpm("glibc", "1", "x86_64"), rpm("glibc", "1", "i686")]
    curr = [rpm("glibc", "1", "x86_64")]
    ev = PackageDiffer().diff(prev, curr)
    assert kinds(ev) == [(EventType.PACKAGE_REMOVED, "glibc", "1", None)]
    assert ev[0].detail["arch"] == "i686"


def test_kernel_changed_only_when_running_differs_and_prev_exists():
    k1 = KernelInfo("5.15-91", ("5.15-91",), False)
    k2 = KernelInfo("5.15-100", ("5.15-100",), False)
    assert KernelDiffer().diff(None, k1) == []
    assert KernelDiffer().diff("5.15-91", k1) == []
    ev = KernelDiffer().diff("5.15-91", k2)
    assert [(e.event_type, e.old_value, e.new_value) for e in ev] == [
        (EventType.KERNEL_CHANGED, "5.15-91", "5.15-100")]


def test_os_changed():
    a = OsInfo("debian", "Ubuntu 22.04", "22.04")
    b = OsInfo("debian", "Ubuntu 24.04", "24.04")
    assert OsDiffer().diff(None, a) == []
    assert OsDiffer().diff(a, a) == []
    ev = OsDiffer().diff(a, b)
    assert [(e.event_type, e.old_value, e.new_value) for e in ev] == [
        (EventType.OS_CHANGED, "Ubuntu 22.04 (22.04)", "Ubuntu 24.04 (24.04)")]
