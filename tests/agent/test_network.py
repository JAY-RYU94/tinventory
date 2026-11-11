import json

import pytest

from swinventory.agent.collectors.linux_network import IP_ADDR_CMD, IpAddrInterfaces, ProcNetPorts
from swinventory.agent.collectors.windows import (
    ADAPTERS_CMD, ADDRS_CMD, TCP_LISTEN_CMD, UDP_ENDPOINT_CMD, WinInterfaces, WinPorts,
)
from swinventory.agent.runtime.command import CommandResult
from swinventory.common.models import ListeningPort, NetworkInterface
from tests.fakes import FakeCommandRunner, FakeFileReader

IP_JSON = json.dumps([
    {"ifindex": 1, "ifname": "lo", "operstate": "UNKNOWN", "link_type": "loopback", "address": "00:00:00:00:00:00",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
                   {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}]},
    {"ifindex": 2, "ifname": "eth0", "operstate": "UP", "link_type": "ether", "address": "02:42:AC:11:00:02",
     "addr_info": [{"family": "inet", "local": "10.0.0.6", "prefixlen": 24, "scope": "global", "secondary": True},
                   {"family": "inet", "local": "10.0.0.5", "prefixlen": 24, "scope": "global"},
                   {"family": "inet6", "local": "2001:db8::5", "prefixlen": 64, "scope": "global"},
                   {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]},
    {"ifindex": 3, "ifname": "veth1234abc", "operstate": "UP", "link_type": "ether", "address": "aa:bb:cc:dd:ee:ff", "addr_info": []},
    {"ifindex": 4, "ifname": "docker0", "operstate": "DOWN", "link_type": "ether", "address": "02:42:11:22:33:44",
     "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "scope": "global"}]},
    {"ifindex": 5, "ifname": "wg0", "operstate": "UNKNOWN", "link_type": "none",
     "addr_info": [{"family": "inet", "local": "10.99.0.1", "prefixlen": 32, "scope": "global"}]},
    # 실제 Ubuntu/Debian/Rocky 컨테이너에서 관측된 커널 터널 가상 장치: address 가 MAC 이 아니라 터널 끝점이다
    {"ifindex": 7, "ifname": "gre0", "operstate": "DOWN", "link_type": "gre", "address": "0.0.0.0", "addr_info": []},
    {"ifindex": 8, "ifname": "ip6tnl0", "operstate": "DOWN", "link_type": "tunnel6", "address": "::", "addr_info": []},
    {"ifindex": 9, "ifname": "gretap0", "operstate": "DOWN", "link_type": "ether", "address": "00:00:00:00:00:00", "addr_info": []},
    {"ifindex": 6, "ifname": "eth1", "operstate": "DOWN", "link_type": "ether", "address": "02:00:00:00:00:01",
     "addr_info": [{"family": "inet", "local": "169.254.3.4", "prefixlen": 16, "scope": "link"}]},
])


def ip_collector(stdout=IP_JSON, rc=0):
    return IpAddrInterfaces(FakeCommandRunner({IP_ADDR_CMD: CommandResult(rc, stdout)}))


def test_linux_interfaces_exclude_loopback_veth_and_non_global_addresses():
    res = ip_collector().collect()
    assert res.ok and ip_collector().name == "network.interfaces"
    assert res.value == [
        NetworkInterface("docker0", "02:42:11:22:33:44", "down", ("172.17.0.1/16",)),
        NetworkInterface("eth0", "02:42:ac:11:00:02", "up", ("10.0.0.5/24", "10.0.0.6/24", "2001:db8::5/64")),
        NetworkInterface("eth1", "02:00:00:00:00:01", "down", ()),            # 링크 로컬뿐이어도 MAC 정보가 있어 남긴다
        NetworkInterface("wg0", "", "unknown", ("10.99.0.1/32",)),              # MAC 없는 터널
    ]


def test_tunnel_pseudo_devices_without_mac_or_address_are_dropped_and_non_mac_is_never_a_mac():
    value = ip_collector().collect().value
    assert {i.name for i in value} == {"docker0", "eth0", "eth1", "wg0"}      # gre0·ip6tnl0·gretap0 은 식별 정보가 없다
    assert all(i.mac == "" or len(i.mac.split(":")) == 6 for i in value)
    odd = json.dumps([{"ifname": "tun9", "operstate": "UP", "link_type": "none", "address": "10.1.1.1",
                       "addr_info": [{"family": "inet", "local": "10.8.0.1", "prefixlen": 24, "scope": "global"}]}])
    assert ip_collector(odd).collect().value == [NetworkInterface("tun9", "", "up", ("10.8.0.1/24",))]   # 주소가 있으면 남기되 MAC 은 비운다


@pytest.mark.parametrize("runner,why", [
    (FakeCommandRunner(), "ip 명령 없음"),
    (FakeCommandRunner({IP_ADDR_CMD: CommandResult(1, "", "Option -j is unknown")}), "구형 iproute2(-j 미지원)"),
    (FakeCommandRunner({IP_ADDR_CMD: CommandResult(0, "not json")}), "JSON 아님"),
    (FakeCommandRunner({IP_ADDR_CMD: CommandResult(0, '{"ifname": "eth0"}')}), "배열이 아님"),
])
def test_interface_failures_are_reported_not_raised(runner, why):
    res = IpAddrInterfaces(runner).collect()
    assert not res.ok and res.error, why


def test_empty_interface_list_is_valid():
    assert ip_collector("[]").collect().value == []


# --- /proc/net 포트 ---------------------------------------------------------

HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
TAIL = " 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"


def row(n, local, remote, st):
    return f"   {n}: {local} {remote} {st}{TAIL}"


ZERO4, ZERO6 = "00000000:0000", "00000000000000000000000000000000:0000"
TCP = HDR + row(0, "00000000:0016", ZERO4, "0A") + row(1, "0100007F:0019", ZERO4, "0A") + \
    row(2, "0F00000A:1F90", ZERO4, "0A") + row(3, "0F00000A:D431", "0100000A:01BB", "01")        # ESTABLISHED 제외
TCP6 = HDR + row(0, "00000000000000000000000000000000:0016", ZERO6, "0A") + \
    row(1, "00000000000000000000000001000000:0277", ZERO6, "0A") + \
    row(2, "0000000000000000FFFF00000F00000A:1F90", ZERO6, "0A")                                # IPv4 매핑 → 10.0.0.15 (tcp4 와 중복)
UDP = HDR + row(0, "00000000:007B", ZERO4, "07") + row(1, "00000000:D431", ZERO4, "07") + \
    row(2, "0F00000A:0044", "0100000A:0043", "01") + row(3, "0100007F:0035", ZERO4, "07")      # 54321(임시 포트)·연결된 소켓 제외
UDP6 = HDR + row(0, "00000000000000000000000000000000:00A1", ZERO6, "07")


def proc(files=None, **overrides):
    base = {"/proc/net/tcp": TCP, "/proc/net/tcp6": TCP6, "/proc/net/udp": UDP, "/proc/net/udp6": UDP6,
            "/proc/sys/net/ipv4/ip_local_port_range": "32768\t60999\n"}
    base.update(files or {})
    for k, v in overrides.items():
        base.pop(k, None) if v is None else base.__setitem__(k, v)
    return ProcNetPorts(FakeFileReader(base))


def test_proc_net_ports_parse_listeners_only_and_normalize():
    res = proc().collect()
    assert res.ok and proc().name == "network.ports"
    assert res.value == [
        ListeningPort("tcp", 22, "0.0.0.0"), ListeningPort("tcp", 22, "::"), ListeningPort("tcp", 25, "127.0.0.1"),
        ListeningPort("tcp", 631, "::1"), ListeningPort("tcp", 8080, "10.0.0.15"),
        ListeningPort("udp", 53, "127.0.0.1"), ListeningPort("udp", 123, "0.0.0.0"), ListeningPort("udp", 161, "::"),
    ]


def test_udp_ephemeral_range_comes_from_the_system_and_tcp_is_not_filtered():
    udp_hi = HDR + row(0, "00000000:D431", ZERO4, "07")           # 54321
    wide = proc({"/proc/net/udp": udp_hi, "/proc/sys/net/ipv4/ip_local_port_range": "60000\t61000\n"}).collect().value
    assert ListeningPort("udp", 54321, "0.0.0.0") in wide          # 임시 포트 범위가 아니면 서비스로 본다
    tcp_hi = HDR + row(0, "00000000:D431", ZERO4, "0A")
    assert ListeningPort("tcp", 54321, "0.0.0.0") in proc({"/proc/net/tcp": tcp_hi}).collect().value   # TCP 리스너는 임시 범위여도 실제 서비스
    default = proc(**{"/proc/sys/net/ipv4/ip_local_port_range": None}).collect().value                  # 파일이 없으면 기본 32768-60999
    assert ListeningPort("udp", 54321, "0.0.0.0") not in default


def test_missing_ipv6_files_are_fine_but_missing_tcp_is_a_failure():
    ok = proc(**{"/proc/net/tcp6": None, "/proc/net/udp6": None}).collect()
    assert ok.ok and ListeningPort("tcp", 22, "::") not in ok.value
    assert not proc(**{"/proc/net/tcp": None}).collect().ok


def test_malformed_proc_line_is_a_failure_not_silently_skipped():
    bad = proc({"/proc/net/tcp": HDR + "   0: garbage\n"}).collect()
    assert not bad.ok


# --- Windows (Fake 로만 검증) -----------------------------------------------

def test_windows_interfaces_merge_adapters_and_addresses():
    adapters = json.dumps([{"Name": "Ethernet", "MacAddress": "00-15-5D-01-02-03", "Status": "Up"},
                           {"Name": "Ethernet 2", "MacAddress": "00-15-5D-0A-0B-0C", "Status": "Disconnected"}])
    addrs = json.dumps([
        {"InterfaceAlias": "Ethernet", "IPAddress": "10.1.2.3", "PrefixLength": 24},
        {"InterfaceAlias": "Ethernet", "IPAddress": "fe80::1%12", "PrefixLength": 64},
        {"InterfaceAlias": "Ethernet", "IPAddress": "2001:db8::9", "PrefixLength": 64},
        {"InterfaceAlias": "Loopback Pseudo-Interface 1", "IPAddress": "127.0.0.1", "PrefixLength": 8},
        {"InterfaceAlias": "Ethernet 2", "IPAddress": "169.254.1.1", "PrefixLength": 16}])
    res = WinInterfaces(FakeCommandRunner({ADAPTERS_CMD: CommandResult(0, adapters), ADDRS_CMD: CommandResult(0, addrs)})).collect()
    assert res.ok
    assert res.value == [NetworkInterface("Ethernet", "00:15:5d:01:02:03", "up", ("10.1.2.3/24", "2001:db8::9/64")),
                         NetworkInterface("Ethernet 2", "00:15:5d:0a:0b:0c", "down", ())]


def test_windows_single_object_json_is_normalized():
    adapters = json.dumps({"Name": "Ethernet", "MacAddress": "00-15-5D-01-02-03", "Status": "Up"})   # 1건이면 객체
    addrs = json.dumps({"InterfaceAlias": "Ethernet", "IPAddress": "10.1.2.3", "PrefixLength": 24})
    res = WinInterfaces(FakeCommandRunner({ADAPTERS_CMD: CommandResult(0, adapters), ADDRS_CMD: CommandResult(0, addrs)})).collect()
    assert res.ok and res.value[0].addresses == ("10.1.2.3/24",)


def test_windows_ports_tcp_listen_and_udp_endpoints_without_ephemeral():
    tcp = json.dumps([{"LocalAddress": "0.0.0.0", "LocalPort": 135}, {"LocalAddress": "::", "LocalPort": 135},
                      {"LocalAddress": "127.0.0.1", "LocalPort": 5432}])
    udp = json.dumps([{"LocalAddress": "0.0.0.0", "LocalPort": 123}, {"LocalAddress": "0.0.0.0", "LocalPort": 56000},
                      {"LocalAddress": "fe80::1%6", "LocalPort": 5353}])
    res = WinPorts(FakeCommandRunner({TCP_LISTEN_CMD: CommandResult(0, tcp), UDP_ENDPOINT_CMD: CommandResult(0, udp)})).collect()
    assert res.ok and res.value == [
        ListeningPort("tcp", 135, "0.0.0.0"), ListeningPort("tcp", 135, "::"), ListeningPort("tcp", 5432, "127.0.0.1"),
        ListeningPort("udp", 123, "0.0.0.0"), ListeningPort("udp", 5353, "fe80::1")]


def test_windows_empty_output_means_no_ports():
    res = WinPorts(FakeCommandRunner({TCP_LISTEN_CMD: CommandResult(0, ""), UDP_ENDPOINT_CMD: CommandResult(0, "  ")})).collect()
    assert res.ok and res.value == []
