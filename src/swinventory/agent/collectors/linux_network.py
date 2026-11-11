"""Linux 네트워크 수집. 비특권(읽기 전용)으로 동작한다.

- 인터페이스: `ip -j addr show`(iproute2, JSON).
- 포트: /proc/net/{tcp,tcp6,udp,udp6} 를 직접 읽는다 — ss 같은 도구가 없는 최소 설치에서도, root 없이도 동작한다.
  프로세스 이름은 root 가 아니면 다른 사용자 프로세스를 볼 수 없어(들쭉날쭉한 값이 가짜 변경을 만든다) 수집하지 않는다.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from swinventory.agent.collectors.network import InterfaceCollector, PortCollector
from swinventory.agent.runtime.command import CommandRunner, run_checked
from swinventory.agent.runtime.fs import FileReader
from swinventory.common.models import ListeningPort, NetworkInterface

IP_ADDR_CMD = ("ip", "-j", "addr", "show")
SKIP_INTERFACE_PREFIXES = ("veth",)  # 컨테이너가 뜨고 질 때마다 생겼다 사라지는 쌍 — 변경 이력이 쏟아진다
EPHEMERAL_RANGE_PATH = "/proc/sys/net/ipv4/ip_local_port_range"
DEFAULT_EPHEMERAL = (32768, 60999)
LISTEN_FILES = (("tcp", "/proc/net/tcp", False), ("tcp", "/proc/net/tcp6", True),
                ("udp", "/proc/net/udp", False), ("udp", "/proc/net/udp6", True))


_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def normalize_mac(mac: str | None) -> str:
    """MAC 형식(6옥텟)일 때만 MAC 으로 본다. 터널 장치의 address 는 끝점 IP(0.0.0.0, ::)라 MAC 이 아니다."""
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if _MAC.match(mac) and mac != "00:00:00:00:00:00" else ""


class IpAddrInterfaces(InterfaceCollector):
    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def _run(self) -> str:
        return run_checked(self._runner, IP_ADDR_CMD).stdout

    def _parse(self, raw: Any) -> list[NetworkInterface]:
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("ip -j addr 출력이 배열이 아니다")
        out = []
        for item in data:
            name = item.get("ifname", "")
            if not name or item.get("link_type") == "loopback" or name.startswith(SKIP_INTERFACE_PREFIXES):
                continue
            # 전역 범위 주소만(루프백·링크 로컬은 식별 정보가 아니고 잡음이다)
            addrs = sorted(f"{a['local']}/{a['prefixlen']}" for a in item.get("addr_info", []) if a.get("scope") == "global")
            mac = normalize_mac(item.get("address"))
            if not mac and not addrs:  # MAC 도 주소도 없는 가상 장치(gre0, ip6tnl0 …)는 식별 정보가 없는 잡음이다
                continue
            out.append(NetworkInterface(name, mac,
                                        (item.get("operstate") or "unknown").lower().replace("lowerlayerdown", "down"),
                                        tuple(addrs)))
        return sorted(out, key=lambda i: i.name)


def _decode_address(hex_ip: str, ipv6: bool) -> str:
    """/proc/net 의 주소는 32비트 워드 단위 리틀엔디언 16진수다."""
    if ipv6:
        ip = ipaddress.IPv6Address(b"".join(bytes.fromhex(hex_ip[i:i + 8])[::-1] for i in range(0, 32, 8)))
        return str(ip.ipv4_mapped or ip)  # ::ffff:10.0.0.15 → 10.0.0.15
    return str(ipaddress.IPv4Address(bytes.fromhex(hex_ip)[::-1]))


class ProcNetPorts(PortCollector):
    def __init__(self, fs: FileReader):
        self._fs = fs

    def _run(self) -> dict[str, Any]:
        files: dict[str, str | None] = {}
        for _proto, path, _v6 in LISTEN_FILES:
            try:
                files[path] = self._fs.read_text(path)
            except FileNotFoundError:
                if path in ("/proc/net/tcp", "/proc/net/udp"):  # IPv6 가 꺼진 시스템에는 *6 파일이 없다
                    raise
                files[path] = None
        try:
            files[EPHEMERAL_RANGE_PATH] = self._fs.read_text(EPHEMERAL_RANGE_PATH)
        except FileNotFoundError:
            files[EPHEMERAL_RANGE_PATH] = None
        return files

    def _parse(self, raw: Any) -> list[ListeningPort]:
        low, high = DEFAULT_EPHEMERAL
        if raw[EPHEMERAL_RANGE_PATH]:
            low, high = (int(x) for x in raw[EPHEMERAL_RANGE_PATH].split()[:2])
        found: set[ListeningPort] = set()
        for proto, path, ipv6 in LISTEN_FILES:
            for line in (raw[path] or "").splitlines()[1:]:  # 첫 줄은 헤더
                if not line.strip():
                    continue
                cols = line.split()
                try:
                    local, remote, state = cols[1], cols[2], cols[3]
                    hex_ip, hex_port = local.split(":")
                    port = int(hex_port, 16)
                    bind = _decode_address(hex_ip, ipv6)
                except (IndexError, ValueError) as exc:
                    raise ValueError(f"{path} 줄을 해석하지 못했다: {line.strip()[:80]!r}") from exc
                if proto == "tcp":
                    if state != "0A":  # LISTEN 만
                        continue
                else:
                    # UDP 는 '리슨' 개념이 없다: 연결되지 않은(07) 소켓만 서비스로 보고, 시스템이 클라이언트에 임시로
                    # 나눠주는 포트 범위는 제외한다(DHCP·NTP 클라이언트 소켓이 가짜 변경을 만든다).
                    if state != "07" or remote.split(":")[1] != "0000" or low <= port <= high:
                        continue
                found.add(ListeningPort(proto, port, bind))
        return sorted(found, key=lambda p: (p.proto, p.port, p.bind))
