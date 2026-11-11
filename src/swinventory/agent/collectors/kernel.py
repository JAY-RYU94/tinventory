from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from swinventory.agent.collectors.base import BaseCollector
from swinventory.agent.runtime.command import CommandRunner, run_checked
from swinventory.common.models import KernelInfo
from swinventory.common.versioning import compare_versions, latest_version


class KernelCollector(BaseCollector[KernelInfo], ABC):
    @property
    def name(self) -> str:
        return "kernel"


class LinuxKernelCollector(KernelCollector, ABC):
    """uname -r(실행 중) + 패키지 관리자가 알려주는 설치된 커널. 하위는 목록 조회만 구현한다."""

    def __init__(self, runner: CommandRunner):
        self._runner = runner

    def _run(self) -> tuple[str, list[str]]:
        running = run_checked(self._runner, ("uname", "-r")).stdout.strip()
        if not running:
            raise ValueError("uname -r 출력이 비어 있다")
        return running, self._list_installed()

    @abstractmethod
    def _list_installed(self) -> list[str]:
        """설치된 커널 버전 문자열(uname -r 형식). 없으면 빈 리스트."""

    def _parse(self, raw: Any) -> KernelInfo:
        running, installed = raw
        unique = tuple(dict.fromkeys(installed)) or (running,)  # 목록이 없으면 실행 중 커널만 보고
        newest = latest_version(unique)
        reboot = newest is not None and compare_versions(newest, running) > 0
        return KernelInfo(running=running, installed=unique, reboot_required=reboot)
