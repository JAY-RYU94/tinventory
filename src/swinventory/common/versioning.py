"""버전 비교(근사). 숫자/문자 토큰 기반이며 dpkg·rpm 의 완전한 비교 규칙은 구현하지 않는다."""
from __future__ import annotations

import re
from typing import Iterable

_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def version_key(version: str) -> tuple[tuple[int, int, str], ...]:
    """숫자 토큰은 정수로, 문자 토큰은 소문자로 비교한다. 같은 위치에서는 숫자가 문자보다 새 버전."""
    return tuple(
        (1, int(tok), "") if tok.isdigit() else (0, 0, tok.lower())
        for tok in _TOKEN.findall(version)
    )


def compare_versions(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def latest_version(versions: Iterable[str]) -> str | None:
    return max(versions, key=version_key, default=None)
