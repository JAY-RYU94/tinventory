from datetime import timedelta

from swinventory.server.domain import EventType
from tests.server.conftest import T0, dpkg, make_snapshot, rpm


def event_types(repo, host="h1"):
    return sorted(e["event_type"] for e in repo.list_events(host_id=host, limit=1000))


def test_first_snapshot_is_baseline_without_events(service, repo):
    res = service.ingest(make_snapshot(packages=[dpkg("bash", "5.1"), dpkg("vim", "9")]))
    assert res.status == "baseline" and res.event_count == 0
    assert repo.list_events(limit=100) == []
    detail = repo.host_detail("h1")
    assert [p["name"] for p in detail["packages"]] == ["bash", "vim"]
    assert detail["kernel"]["running"] == "5.15-91"
    assert detail["host"]["os_name"] == "Ubuntu 22.04"


def test_unchanged_snapshot_produces_no_events(service, repo):
    snap = dict(packages=[dpkg("bash", "5.1")])
    service.ingest(make_snapshot(**snap))
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=1), **snap))
    assert res.status == "applied" and res.event_count == 0


def test_install_remove_version_change_and_kernel_change(service, repo):
    service.ingest(make_snapshot(packages=[dpkg("bash", "5.1"), dpkg("vim", "9")]))
    res = service.ingest(make_snapshot(
        at=T0 + timedelta(hours=1), kernel="5.15-100",
        packages=[dpkg("bash", "5.2"), dpkg("git", "2")]))
    assert res.event_count == 4
    assert event_types(repo) == sorted([
        EventType.PACKAGE_INSTALLED, EventType.PACKAGE_REMOVED,
        EventType.PACKAGE_VERSION_CHANGED, EventType.KERNEL_CHANGED])
    pkgs = {p["name"]: p["version"] for p in repo.host_detail("h1")["packages"]}
    assert pkgs == {"bash": "5.2", "git": "2"}


def test_failed_source_is_not_synced_and_emits_no_removals(service, repo):
    """일시 오류로 software.dpkg 가 실패한 회차에 '전부 삭제됨' 이벤트가 나오면 안 된다."""
    service.ingest(make_snapshot(packages=[dpkg("bash", "5.1"), dpkg("vim", "9")]))
    res = service.ingest(make_snapshot(
        at=T0 + timedelta(hours=1), packages=[], collected=["os", "kernel"],
        errors={"software.dpkg": "CommandError: boom"}))
    assert res.event_count == 0
    assert len(repo.host_detail("h1")["packages"]) == 2
    assert repo.host_detail("h1")["host"]["last_errors"] == {"software.dpkg": "CommandError: boom"}


def test_source_synced_for_first_time_later_is_baseline_for_that_source(service, repo):
    """첫 회차에 dpkg 가 실패했다면 두 번째 회차의 dpkg 전체가 '설치됨' 이벤트가 되면 안 된다."""
    service.ingest(make_snapshot(packages=[], collected=["os", "kernel"],
                                 errors={"software.dpkg": "x"}))
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=1),
                                       packages=[dpkg("bash", "5.1"), dpkg("vim", "9")]))
    assert res.event_count == 0
    assert len(repo.host_detail("h1")["packages"]) == 2
    # 이후부터는 정상적으로 diff 한다
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=2), packages=[dpkg("bash", "5.1")]))
    assert event_types(repo) == [EventType.PACKAGE_REMOVED]


def test_successful_empty_source_means_everything_removed(service, repo):
    service.ingest(make_snapshot(packages=[dpkg("bash", "5.1")]))
    res = service.ingest(make_snapshot(at=T0 + timedelta(hours=1), packages=[]))
    assert res.event_count == 1
    assert repo.host_detail("h1")["packages"] == []


def test_packages_of_uncollected_sources_are_ignored(service, repo):
    service.ingest(make_snapshot(packages=[dpkg("bash", "5.1")]))
    res = service.ingest(make_snapshot(
        at=T0 + timedelta(hours=1), collected=["os", "kernel"], packages=[dpkg("evil", "1")]))
    assert res.event_count == 0
    assert [p["name"] for p in repo.host_detail("h1")["packages"]] == ["bash"]


def test_duplicate_snapshot_is_ignored(service, repo):
    service.ingest(make_snapshot(packages=[dpkg("bash", "5.1")]))
    res = service.ingest(make_snapshot(packages=[dpkg("bash", "9.9")]))  # 같은 collected_at
    assert res.status == "duplicate"
    assert repo.host_detail("h1")["packages"][0]["version"] == "5.1"


def test_stale_snapshot_is_recorded_but_does_not_touch_state(service, repo):
    service.ingest(make_snapshot(at=T0 + timedelta(hours=2), packages=[dpkg("bash", "5.1")]))
    res = service.ingest(make_snapshot(at=T0, packages=[dpkg("bash", "1.0")]))
    assert res.status == "stale" and res.event_count == 0
    assert repo.host_detail("h1")["packages"][0]["version"] == "5.1"


def test_multi_version_kernel_core_stays_quiet_across_snapshots(service, repo):
    pk = [rpm("kernel-core", "5.14-362"), rpm("kernel-core", "5.14-427"), rpm("bash", "1")]
    service.ingest(make_snapshot(sources=("rpm",), packages=pk, kernel="5.14-362",
                                 installed=["5.14-362", "5.14-427"], reboot=True))
    for i in (1, 2, 3):
        res = service.ingest(make_snapshot(
            at=T0 + timedelta(hours=i), sources=("rpm",), packages=list(reversed(pk)),
            kernel="5.14-362", installed=["5.14-362", "5.14-427"], reboot=True))
        assert res.event_count == 0
    assert len(repo.host_detail("h1")["packages"]) == 3


def test_kernel_state_tracks_latest_installed_and_reboot(service, repo):
    service.ingest(make_snapshot(kernel="5.15-91", installed=["5.15-91", "5.15-100"], reboot=True))
    k = repo.host_detail("h1")["kernel"]
    assert (k["running"], k["latest_installed"], k["reboot_required"]) == ("5.15-91", "5.15-100", True)
    assert [x["version"] for x in repo.host_detail("h1")["kernels"]] == ["5.15-100", "5.15-91"]


def test_ingest_normalizes_timestamps_and_updates_host(service, repo, clock):
    service.ingest(make_snapshot(hostname="old"))
    clock.advance(hours=3)
    service.ingest(make_snapshot(at=T0 + timedelta(hours=3), hostname="new"))
    h = repo.host_detail("h1")["host"]
    assert h["hostname"] == "new"
    assert h["first_seen"] < h["last_seen"]
