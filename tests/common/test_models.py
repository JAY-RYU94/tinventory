from swinventory.common.models import (
    KernelInfo, OsInfo, PackageRecord, Snapshot, group_versions,
)


def _kernel_core(version: str) -> PackageRecord:
    return PackageRecord(source="rpm", name="kernel-core", version=version, arch="x86_64")


def test_multi_version_package_keeps_every_version():
    """rpm kernel-core 처럼 (source,name,arch) 가 같은 다중 버전은 키 충돌 없이 모두 보존돼야 한다."""
    pkgs = [_kernel_core("5.14.0-362"), _kernel_core("5.14.0-427")]
    grouped = group_versions(pkgs)
    assert grouped == {("rpm", "kernel-core", "x86_64"): frozenset({"5.14.0-362", "5.14.0-427"})}


def test_identity_excludes_version_instance_key_includes_it():
    p = _kernel_core("1")
    assert p.identity == ("rpm", "kernel-core", "x86_64")
    assert p.instance_key == ("rpm", "kernel-core", "x86_64", "1")


def test_snapshot_json_roundtrip():
    snap = Snapshot(
        host_id="abc", hostname="web01", collected_at="2026-11-05T00:00:00+00:00",
        agent_version="0.1.0",
        os=OsInfo(family="debian", name="Ubuntu 22.04", version="22.04"),
        kernel=KernelInfo(running="5.15.0-91-generic",
                          installed=("5.15.0-91-generic", "5.15.0-100-generic"),
                          reboot_required=True),
        packages=[PackageRecord("dpkg", "bash", "5.1", "amd64")],
        collected=["os", "kernel", "software.dpkg"],
        errors={"software.rpm": "boom"},
    )
    assert Snapshot.from_dict(snap.to_dict()) == snap


def test_snapshot_roundtrip_with_missing_sections():
    snap = Snapshot(host_id="h", hostname="n", collected_at="t", agent_version="v")
    assert Snapshot.from_dict(snap.to_dict()) == snap
    assert snap.os is None and snap.kernel is None


# --- 네트워크 ---------------------------------------------------------------

def test_network_models_roundtrip_and_old_snapshots_without_them_still_load():
    from swinventory.common.models import ListeningPort, NetworkInterface

    snap = Snapshot(host_id="h", hostname="n", collected_at="t", agent_version="v",
                    interfaces=[NetworkInterface("eth0", "02:42:ac:11:00:02", "up", ("10.0.0.5/24", "2001:db8::5/64"))],
                    ports=[ListeningPort("tcp", 22, "0.0.0.0"), ListeningPort("udp", 123, "::")],
                    collected=["network.interfaces", "network.ports"])
    assert Snapshot.from_dict(snap.to_dict()) == snap
    old = Snapshot.from_dict({"host_id": "h", "hostname": "n", "collected_at": "t", "agent_version": "v"})
    assert old.interfaces == [] and old.ports == []      # 구버전 에이전트(네트워크 수집 없음)와의 호환


def test_bind_exposure_and_ip_helpers():
    from swinventory.common.net import bind_exposure, ip_of

    assert [bind_exposure(b) for b in ("0.0.0.0", "::", "127.0.0.1", "::1", "10.0.0.5", "2001:db8::1", "*", "junk")] == [
        "any", "any", "loopback", "loopback", "specific", "specific", "any", "specific"]
    assert ip_of("10.0.0.5/24") == "10.0.0.5" and ip_of("2001:db8::5/64") == "2001:db8::5" and ip_of("10.0.0.5") == "10.0.0.5"
