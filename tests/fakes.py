"""테스트 대역(Fake). 외부 접근 추상화(명령·파일·레지스트리)의 인메모리 구현."""
from __future__ import annotations

from typing import Any, Sequence

from swinventory.agent.runtime.command import CommandResult, CommandRunner
from swinventory.agent.runtime.fs import FileReader
from swinventory.agent.runtime.registry import RegistryReader


class FakeCommandRunner(CommandRunner):
    """등록되지 않은 명령은 실제 환경처럼 FileNotFoundError."""

    def __init__(self, responses: dict[tuple[str, ...], CommandResult] | None = None):
        self.responses = dict(responses or {})
        self.calls: list[tuple[str, ...]] = []

    def run(self, args: Sequence[str], timeout: float = 60.0) -> CommandResult:
        key = tuple(args)
        self.calls.append(key)
        if key not in self.responses:
            raise FileNotFoundError(args[0])
        return self.responses[key]


class FakeFileReader(FileReader):
    def __init__(self, files: dict[str, str] | None = None):
        self.files = dict(files or {})

    def read_text(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def exists(self, path: str) -> bool:
        return path in self.files


def _norm(hive: str, path: str, view: int) -> tuple[str, str, int]:
    return (hive.upper(), path.strip("\\").lower(), view)


class FakeRegistry(RegistryReader):
    """keys: {(hive, path, view): {값 이름: 값}}. 하위 키는 경로 접두로 추론한다."""

    def __init__(self, keys: dict[tuple[str, str, int], dict[str, Any]] | None = None):
        self._keys: dict[tuple[str, str, int], tuple[str, dict[str, Any]]] = {}
        for (hive, path, view), values in (keys or {}).items():
            self._keys[_norm(hive, path, view)] = (path.strip("\\"), dict(values))

    def values(self, hive: str, path: str, view: int = 64) -> dict[str, Any] | None:
        entry = self._keys.get(_norm(hive, path, view))
        return dict(entry[1]) if entry else None

    def subkeys(self, hive: str, path: str, view: int = 64) -> list[str]:
        parent = _norm(hive, path, view)
        out: list[str] = []
        for (h, p, v), (orig, _) in self._keys.items():
            if h != parent[0] or v != parent[2]:
                continue
            prefix = parent[1] + "\\"
            if p.startswith(prefix) and "\\" not in p[len(prefix):]:
                out.append(orig[len(path.strip("\\")) + 1:])
        return out

    def key_exists(self, hive: str, path: str, view: int = 64) -> bool:
        return _norm(hive, path, view) in self._keys


# --- 네트워크 수집용 공통 fixture (에이전트 CLI·프로필 테스트가 공유) -------------------
_HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
IP_JSON_SIMPLE = ('[{"ifname":"eth0","operstate":"UP","link_type":"ether","address":"02:42:ac:11:00:02",'
                  '"addr_info":[{"family":"inet","local":"10.0.0.5","prefixlen":24,"scope":"global"}]}]')
PROC_NET_FILES = {
    "/proc/net/tcp": _HDR + "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1\n",
    "/proc/net/tcp6": _HDR, "/proc/net/udp": _HDR, "/proc/net/udp6": _HDR,
    "/proc/sys/net/ipv4/ip_local_port_range": "32768\t60999\n",
}
