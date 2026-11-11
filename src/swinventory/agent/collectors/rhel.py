from __future__ import annotations

from typing import Any

from swinventory.agent.collectors.kernel import LinuxKernelCollector
from swinventory.agent.collectors.software import SoftwareCollector
from swinventory.agent.runtime.command import CommandError, CommandRunner, run_checked
from swinventory.common.models import PackageRecord

RPM_FORMAT = r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"
RPM_LIST_CMD = ("rpm", "-qa", "--qf", RPM_FORMAT)
KERNEL_PACKAGES = ("kernel-core", "kernel")  # RHEL8+ 는 kernel-core, 없으면 kernel


def rpm_kernel_cmd(package: str) -> tuple[str, ...]:
    return ("rpm", "-q", "--qf", RPM_FORMAT, package)


def _split(line: str) -> list[str]:
    parts = line.split("\t")
    if len(parts) != 3:
        raise ValueError(f"예상치 못한 rpm 출력: {line!r}")
    return parts


class RpmSoftware(SoftwareCollector):
    source = "rpm"

    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def _run(self) -> str:
        return run_checked(self._runner, RPM_LIST_CMD).stdout

    def _parse(self, raw: Any) -> list[PackageRecord]:
        out: list[PackageRecord] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            name, version, arch = _split(line)
            if name == "gpg-pubkey":
                continue
            # 같은 (name, arch) 의 다중 버전(kernel-core 등)을 합치지 않고 그대로 보존한다.
            out.append(PackageRecord(self.source, name, version, arch))
        return out


class RhelKernel(LinuxKernelCollector):
    def _list_installed(self) -> list[str]:
        for pkg in KERNEL_PACKAGES:
            res = self._runner.run(rpm_kernel_cmd(pkg))
            text = res.stderr + res.stdout
            if res.returncode != 0:
                if "is not installed" in text:
                    continue
                raise CommandError(f"rpm exited {res.returncode}: {text.strip()}")
            versions = []
            for line in res.stdout.splitlines():
                if line.strip():
                    _name, version, arch = _split(line)
                    versions.append(f"{version}.{arch}")  # uname -r 형식과 맞춘다
            if versions:
                return versions
        return []
