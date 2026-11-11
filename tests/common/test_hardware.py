import json
from pathlib import Path

import pytest

from swinventory.common.hardware import classify_virtualization, clean_serial, domain_of, normalize_serial
from swinventory.common.models import HardwareInfo, Snapshot


@pytest.mark.parametrize("raw", ["", "  ", "None", "none", "N/A", "Unknown", "Default string", "To Be Filled By O.E.M.",
                                 "Not Specified", "System Serial Number", "0", "0000000000", "00000000-0000-0000-0000-000000000000",
                                 "FFFFFFFF", None])
def test_placeholder_serials_are_dropped(raw):
    assert clean_serial(raw) == ""


def test_real_serials_are_kept_trimmed():
    assert clean_serial("  ABC1234XYZ \n") == "ABC1234XYZ"
    assert clean_serial("VMware-56 4d 5c 7e") == "VMware-56 4d 5c 7e"


def test_normalize_serial_is_case_and_separator_insensitive():
    assert normalize_serial("vmware-56 4d 5c") == normalize_serial("VMWARE-56-4D-5C") == "VMWARE564D5C"
    assert normalize_serial("") == "" and normalize_serial(None) == ""


@pytest.mark.parametrize("fqdn,domain", [("web01.corp.example.com", "corp.example.com"), ("web01", ""), ("", ""), ("web01.", ""),
                                         ("WEB01.Corp.Local", "corp.local")])
def test_domain_of(fqdn, domain):
    assert domain_of(fqdn) == domain


@pytest.mark.parametrize("kw,expected", [
    (dict(vendor="Dell Inc.", model="PowerEdge R740"), ("physical", "")),
    (dict(vendor="HPE", model="ProLiant DL380 Gen10"), ("physical", "")),
    (dict(vendor="VMware, Inc.", model="VMware7,1"), ("virtual", "vmware")),
    (dict(vendor="VMware, Inc.", model="VMware Virtual Platform"), ("virtual", "vmware")),
    (dict(vendor="QEMU", model="Standard PC (Q35 + ICH9, 2009)"), ("virtual", "kvm")),
    (dict(vendor="Red Hat", model="KVM"), ("virtual", "kvm")),
    (dict(vendor="Microsoft Corporation", model="Virtual Machine"), ("virtual", "hyperv")),
    (dict(vendor="innotek GmbH", model="VirtualBox"), ("virtual", "virtualbox")),
    (dict(vendor="Xen", model="HVM domU"), ("virtual", "xen")),
    (dict(vendor="Amazon EC2", model="t3.large"), ("virtual", "aws")),
    (dict(vendor="Google", model="Google Compute Engine"), ("virtual", "gcp")),
    (dict(vendor="OpenStack Foundation", model="OpenStack Nova"), ("virtual", "openstack")),
    (dict(vendor="Microsoft Corporation", model="Surface Pro 9"), ("physical", "")),     # 'Microsoft' 만으로는 VM 이 아니다
    (dict(vendor="", model=""), ("unknown", "")),                                          # DMI 를 읽지 못함 — 추측하지 않는다
    (dict(vendor="", model="", hypervisor_flag=True), ("virtual", "unknown")),
    (dict(vendor="Dell Inc.", model="PowerEdge R740", detected="kvm"), ("virtual", "kvm")),   # 감지 도구가 DMI 보다 우선
    (dict(vendor="QEMU", model="KVM", container="docker"), ("container", "docker")),         # 컨테이너가 최우선
])
def test_classify_virtualization(kw, expected):
    assert classify_virtualization(**kw) == expected


def test_snapshot_roundtrip_with_hardware_and_without():
    hw = HardwareInfo(kind="virtual", virt="vmware", vendor="VMware, Inc.", model="VMware7,1", serial="VMware-56", fqdn="a.corp.local", domain="corp.local")
    snap = Snapshot(host_id="h", hostname="a", collected_at="2026-11-05T00:00:00+00:00", agent_version="0.2.0", hardware=hw)
    assert Snapshot.from_dict(snap.to_dict()).hardware == hw
    old = snap.to_dict(); old.pop("hardware")
    assert Snapshot.from_dict(old).hardware is None            # 하드웨어 수집이 없던 옛 에이전트의 스냅샷


VECTORS = json.loads((Path(__file__).resolve().parents[2] / "contracts" / "hardware-vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", VECTORS["classify"], ids=lambda c: f"{c['vendor']}|{c['model']}|{c.get('detected', '')}{c.get('container', '')}")
def test_shared_classify_vectors(case):
    kw = {k: v for k, v in case.items() if k != "expect"}
    assert list(classify_virtualization(**kw)) == case["expect"]


@pytest.mark.parametrize("case", VECTORS["serial"], ids=lambda c: repr(c["raw"]))
def test_shared_serial_vectors(case):
    assert clean_serial(case["raw"]) == case["clean"]
    assert normalize_serial(case["raw"]) == case["normalized"]


@pytest.mark.parametrize("case", VECTORS["domain"], ids=lambda c: repr(c["fqdn"]))
def test_shared_domain_vectors(case):
    assert domain_of(case["fqdn"]) == case["domain"]
