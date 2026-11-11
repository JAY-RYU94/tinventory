from __future__ import annotations

import re
from typing import Any

from swinventory.agent.collectors.kernel import LinuxKernelCollector
from swinventory.agent.collectors.software import SoftwareCollector
from swinventory.agent.runtime.command import CommandError, CommandRunner, run_checked
from swinventory.common.models import PackageRecord

# dpkg-query 가 \t, \n 이스케이프를 직접 해석하므로 백슬래시 문자열 그대로 넘긴다.
DPKG_LIST_CMD = ("dpkg-query", "-W", r"-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n")
DPKG_KERNEL_CMD = ("dpkg-query", "-W", r"-f=${Package}\t${Version}\t${db:Status-Abbrev}\n", "linux-image-*")

_KERNEL_PKG = re.compile(r"^linux-image-(\d.*)$")  # linux-image-generic 같은 메타 패키지는 숫자로 시작하지 않아 제외


def _split(line: str, fields: int) -> list[str]:
    parts = line.split("\t")
    if len(parts) != fields:
        raise ValueError(f"예상치 못한 dpkg-query 출력: {line!r}")
    return parts


class DpkgSoftware(SoftwareCollector):
    source = "dpkg"

    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def _run(self) -> str:
        return run_checked(self._runner, DPKG_LIST_CMD).stdout

    def _parse(self, raw: Any) -> list[PackageRecord]:
        out: list[PackageRecord] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            name, version, arch, status = _split(line, 4)
            if status.strip() != "ii":  # 설치 완료 상태만
                continue
            out.append(PackageRecord(self.source, name, version, arch))
        return out


class DebianKernel(LinuxKernelCollector):
    def _list_installed(self) -> list[str]:
        res = self._runner.run(DPKG_KERNEL_CMD)
        if res.returncode == 1 and "no packages found" in (res.stderr + res.stdout):
            return []  # 컨테이너 등 linux-image 패키지가 없는 환경: 실패가 아니다
        if res.returncode != 0:
            raise CommandError(f"dpkg-query exited {res.returncode}: {(res.stderr or res.stdout).strip()}")
        out: list[str] = []
        for line in res.stdout.splitlines():
            if not line.strip():
                continue
            name, _version, status = _split(line, 3)
            m = _KERNEL_PKG.match(name)
            if m and status.strip() == "ii":
                out.append(m.group(1))
        return out
