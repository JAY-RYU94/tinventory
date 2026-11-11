"""명령 실행 추상화. 수집기는 subprocess 를 직접 부르지 않고 CommandRunner 를 주입받는다."""
from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Sequence


class CommandError(RuntimeError):
    """명령이 기대한 종료 코드로 끝나지 않았다."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(ABC):
    @abstractmethod
    def run(self, args: Sequence[str], timeout: float = 60.0) -> CommandResult:
        """셸을 거치지 않고 실행한다. 실행 파일이 없으면 FileNotFoundError."""


class SubprocessRunner(CommandRunner):
    def run(self, args: Sequence[str], timeout: float = 60.0) -> CommandResult:
        proc = subprocess.run(  # noqa: S603 - 인자 리스트, shell=False
            list(args), capture_output=True, text=True, timeout=timeout,
            check=False, encoding="utf-8", errors="replace",
        )
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def run_checked(runner: CommandRunner, args: Sequence[str], timeout: float = 60.0) -> CommandResult:
    """종료 코드 0 만 성공으로 본다."""
    res = runner.run(args, timeout)
    if res.returncode != 0:
        detail = (res.stderr or res.stdout).strip()
        raise CommandError(f"{args[0]} exited {res.returncode}: {detail}")
    return res
