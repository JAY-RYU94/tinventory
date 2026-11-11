"""자산 대장 ↔ 수집 호스트 자동 연결 규칙(순수 로직). 우선순위: 명시 연결 > 시리얼 > 호스트명 > IP, 모호하면 연결하지 않는다."""
from swinventory.common.models import HardwareInfo
from swinventory.server.assetview import AssetBook


def asset(id, no, kind="physical", serial="", hostname="", domain="", ip="", parent=None, host_id=None, note=""):
    return {"id": id, "asset_no": no, "kind": kind, "serial": serial, "hostname": hostname, "domain": domain, "ip": ip,
            "parent_asset_id": parent, "host_id": host_id, "note": note}


def host(host_id, hostname):
    return {"host_id": host_id, "hostname": hostname}


def hw(kind="physical", serial="", fqdn="", virt="", domain=None):
    from swinventory.common.hardware import domain_of
    return HardwareInfo(kind, virt, "", "", serial, fqdn, domain if domain is not None else domain_of(fqdn))


def book(assets, hosts, hardware=None, ips=None):
    return AssetBook(assets, hosts, hardware or {}, ips or {})


def linked(b, asset_id):
    return b.link_of_asset(asset_id)


# --- 연결 규칙 ---
def test_serial_match_ignores_case_spaces_and_hyphens():
    b = book([asset(1, "A-1", serial="vmware-56 4d 5c")], [host("h1", "x")], {"h1": hw(serial="VMWARE-56-4D-5C")})
    assert linked(b, 1) == ("h1", "serial")


def test_hostname_match_short_vs_fqdn_and_case():
    b = book([asset(1, "A-1", hostname="WEB01")], [host("h1", "web01.corp.example.com")], {"h1": hw(fqdn="web01.corp.example.com")})
    assert linked(b, 1) == ("h1", "hostname")
    b = book([asset(1, "A-1", hostname="web01", domain="corp.example.com")], [host("h1", "web01")], {"h1": hw(fqdn="web01.corp.example.com")})
    assert linked(b, 1) == ("h1", "hostname")


def test_hostname_match_rejected_when_domains_differ():
    b = book([asset(1, "A-1", hostname="web01", domain="a.example.com")], [host("h1", "web01")], {"h1": hw(fqdn="web01.b.example.com")})
    assert linked(b, 1) is None


def test_ip_match():
    b = book([asset(1, "A-1", ip="10.0.0.5")], [host("h1", "x")], ips={"h1": {"10.0.0.5", "fe80::1"}})
    assert linked(b, 1) == ("h1", "ip")


def test_ipv6_is_compared_in_canonical_form():
    b = book([asset(1, "A-1", ip="2001:DB8:0:0:0:0:0:5")], [host("h1", "x")], ips={"h1": {"2001:db8::5"}})
    assert linked(b, 1) == ("h1", "ip")


def test_priority_explicit_then_serial_then_hostname_then_ip():
    assets = [asset(1, "A", host_id="h3", serial="S1", hostname="web01", ip="10.0.0.1")]
    hosts = [host("h1", "web01"), host("h2", "other"), host("h3", "zzz")]
    hardware = {"h2": hw(serial="S1")}
    b = book(assets, hosts, hardware, {"h1": {"10.0.0.1"}})
    assert linked(b, 1) == ("h3", "explicit")
    b = book([asset(1, "A", serial="S1", hostname="web01", ip="10.0.0.1")], hosts, hardware, {"h1": {"10.0.0.1"}})
    assert linked(b, 1) == ("h2", "serial")                       # 시리얼이 호스트명·IP 보다 강한 증거
    b = book([asset(1, "A", hostname="web01", ip="10.0.0.9")], hosts, hardware, {"h2": {"10.0.0.9"}})
    assert linked(b, 1) == ("h1", "hostname")


def test_a_host_is_claimed_by_one_asset_only():
    b = book([asset(1, "A", serial="S1"), asset(2, "B", hostname="web01")], [host("h1", "web01")], {"h1": hw(serial="S1")})
    assert linked(b, 1) == ("h1", "serial") and linked(b, 2) is None


def test_ambiguous_serial_is_not_linked_but_hostname_still_can_be():
    """클론된 VM 은 같은 시리얼을 보고한다 — 시리얼로 아무 호스트나 묶으면 오연결이다."""
    hosts = [host("h1", "web01"), host("h2", "web02")]
    hardware = {"h1": hw(serial="CLONE"), "h2": hw(serial="CLONE")}
    b = book([asset(1, "A", serial="CLONE", hostname="web02")], hosts, hardware)
    assert linked(b, 1) == ("h2", "hostname")
    b = book([asset(1, "A", serial="CLONE")], hosts, hardware)
    assert linked(b, 1) is None


def test_two_assets_with_the_same_serial_are_ambiguous():
    b = book([asset(1, "A", serial="S"), asset(2, "B", serial="S")], [host("h1", "x")], {"h1": hw(serial="S")})
    assert linked(b, 1) is None and linked(b, 2) is None


def test_ambiguous_hostname_two_hosts_same_short_name():
    hosts = [host("h1", "web01"), host("h2", "web01")]
    b = book([asset(1, "A", hostname="web01")], hosts, {"h1": hw(fqdn="web01.a.com"), "h2": hw(fqdn="web01.b.com")})
    assert linked(b, 1) is None
    b = book([asset(1, "A", hostname="web01", domain="b.com")], hosts, {"h1": hw(fqdn="web01.a.com"), "h2": hw(fqdn="web01.b.com")})
    assert linked(b, 1) == ("h2", "hostname")               # 도메인을 적어 두면 구분된다


def test_placeholder_serials_never_match():
    b = book([asset(1, "A", serial="To Be Filled By O.E.M.")], [host("h1", "x")], {"h1": hw(serial="To Be Filled By O.E.M.")})
    assert linked(b, 1) is None


def test_dangling_explicit_link_to_a_deleted_host_is_ignored():
    b = book([asset(1, "A", host_id="gone")], [host("h1", "x")])
    assert linked(b, 1) is None
    assert b.rows()[0]["status"] == "uncollected"


# --- 호스트 쪽 보기(다른 목록에 붙는 열) ---
def test_host_without_asset_shows_detected_values():
    b = book([], [host("h1", "web01")], {"h1": hw("virtual", "SN", "web01.corp.local", "vmware")})
    v = b.host_view("h1")
    assert (v["asset_id"], v["asset_no"]) == (None, None)
    assert (v["kind"], v["kind_source"], v["virt"], v["domain"], v["serial"]) == ("virtual", "detected", "vmware", "corp.local", "SN")


def test_host_without_any_hardware_is_unknown():
    v = book([], [host("h1", "x")]).host_view("h1")
    assert v["kind"] == "unknown" and v["kind_source"] == "detected" and v["domain"] == ""


def test_asset_values_override_detected_and_fill_gaps():
    b = book([asset(1, "A-77", "virtual", serial="LEDGER", hostname="web01", domain="corp.example.com")], [host("h1", "web01")],
             {"h1": hw("unknown", "", "web01")})
    v = b.host_view("h1")
    assert (v["asset_no"], v["kind"], v["kind_source"], v["domain"], v["serial"]) == ("A-77", "virtual", "asset", "corp.example.com", "LEDGER")


def test_collected_serial_is_used_when_ledger_has_none():
    b = book([asset(1, "A", hostname="web01")], [host("h1", "web01")], {"h1": hw("physical", "REAL-SN", "web01")})
    assert b.host_view("h1")["serial"] == "REAL-SN"


def test_flags_kind_serial_and_ip_mismatch():
    b = book([asset(1, "A", "physical", serial="LEDGER-SN", hostname="web01", ip="10.9.9.9")], [host("h1", "web01")],
             {"h1": hw("virtual", "OTHER-SN", "web01", "vmware")}, {"h1": {"10.0.0.5"}})
    assert set(b.host_view("h1")["flags"]) == {"kind_mismatch", "serial_mismatch", "ip_mismatch"}


def test_no_flags_when_consistent_or_unknowable():
    b = book([asset(1, "A", "virtual", hostname="web01", ip="10.0.0.5")], [host("h1", "web01")],
             {"h1": hw("container", "", "web01")}, {"h1": {"10.0.0.5"}})
    assert b.host_view("h1")["flags"] == []                  # 컨테이너/unknown 은 VM·물리와 비교하지 않는다


# --- VM → 물리 호스트 ---
def test_vm_shows_parent_and_parent_lists_vms():
    assets = [asset(1, "P-1", "physical", hostname="esx01"), asset(2, "V-1", "virtual", hostname="web01", parent=1)]
    b = book(assets, [host("h1", "esx01"), host("h2", "web01")])
    v = b.host_view("h2")
    assert (v["parent_asset_no"], v["parent_hostname"]) == ("P-1", "esx01")
    rows = {r["asset"]["asset_no"]: r for r in b.rows() if r["asset"]}
    assert rows["P-1"]["vm_count"] == 1 and rows["V-1"]["parent_asset_no"] == "P-1"


def test_parent_label_falls_back_to_asset_hostname_when_parent_not_collected():
    assets = [asset(1, "P-1", "physical", hostname="esx01"), asset(2, "V-1", "virtual", hostname="web01", parent=1)]
    v = book(assets, [host("h2", "web01")]).host_view("h2")
    assert v["parent_asset_no"] == "P-1" and v["parent_hostname"] == "esx01"


# --- 통합 목록 ---
def test_rows_cover_linked_uncollected_and_unregistered():
    b = book([asset(1, "A-1", hostname="web01"), asset(2, "A-2", hostname="ghost")], [host("h1", "web01"), host("h2", "stray")])
    by = {r["status"]: r for r in b.rows()}
    assert set(by) == {"linked", "uncollected", "unregistered"}
    assert by["linked"]["host_id"] == "h1" and by["uncollected"]["host_id"] is None and by["unregistered"]["asset"] is None
    assert b.summary() == {"assets": 2, "linked": 1, "uncollected": 1, "unregistered": 1, "physical": 2, "virtual": 0,
                           "kind_mismatch": 0, "ip_mismatch": 0, "serial_mismatch": 0}


def test_summary_counts_effective_kind_over_all_hosts():
    b = book([asset(1, "A", "virtual", hostname="web01")], [host("h1", "web01"), host("h2", "db01")],
             {"h2": hw("physical", "S", "db01")})
    s = b.summary()
    assert (s["virtual"], s["physical"]) == (1, 1)           # 등록 자산은 대장 값, 미등록 호스트는 감지 값
