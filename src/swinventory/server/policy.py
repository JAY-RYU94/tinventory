"""커널 하한선 정책: OS 계열별 최소 허용 커널(실행 중 커널 기준). 서버 설정(DB)에 저장한다."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Sequence

from swinventory.common.versioning import compare_versions

FAMILIES = ("*", "debian", "rhel", "windows")
_VERSION = re.compile(r"^[0-9A-Za-z._+~:-]{1,128}$")
SETTING_KEY = "kernel_policy"


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class KernelRule:
    os_family: str
    min_kernel: str


class KernelPolicy:
    def __init__(self, rules: Sequence[KernelRule] = ()):
        self.rules: tuple[KernelRule, ...] = tuple(rules)

    @property
    def active(self) -> bool:
        return bool(self.rules)

    @classmethod
    def from_dicts(cls, items: Any) -> "KernelPolicy":
        if not isinstance(items, list):
            raise PolicyError("rules 는 목록이어야 한다")
        rules, seen = [], set()
        for item in items:
            if not isinstance(item, dict):
                raise PolicyError("규칙은 {os_family, min_kernel} 객체여야 한다")
            family, minimum = item.get("os_family"), str(item.get("min_kernel") or "").strip()
            if family not in FAMILIES:
                raise PolicyError(f"os_family 는 {', '.join(FAMILIES)} 중 하나여야 한다: {family!r}")
            if family in seen:
                raise PolicyError(f"os_family '{family}' 규칙이 중복됐다")
            if not _VERSION.match(minimum) or not re.search(r"\d", minimum):
                raise PolicyError(f"min_kernel 이 올바르지 않다(숫자를 포함한 1~128자 버전 문자열): {minimum!r}")
            seen.add(family)
            rules.append(KernelRule(family, minimum))
        return cls(rules)

    @classmethod
    def from_json(cls, text: str | None) -> "KernelPolicy":
        """저장값이 없거나 손상됐으면 정책 없음(= 아무 호스트도 미달로 표시하지 않음)으로 본다."""
        try:
            return cls.from_dicts(json.loads(text)["rules"]) if text else cls()
        except (ValueError, KeyError, TypeError):
            return cls()

    def to_dicts(self) -> list[dict[str, str]]:
        return [{"os_family": r.os_family, "min_kernel": r.min_kernel} for r in self.rules]

    def to_json(self) -> str:
        return json.dumps({"rules": self.to_dicts()})

    def min_for(self, os_family: str | None) -> str | None:
        by_family = {r.os_family: r.min_kernel for r in self.rules}
        return by_family.get(os_family or "", by_family.get("*"))  # 계열 규칙이 "*" 보다 우선

    def evaluate(self, os_family: str | None, running: str | None) -> tuple[str | None, bool | None]:
        """(적용된 하한선, 준수 여부). 규칙이 없거나 커널 정보가 없으면 준수 여부는 None(판정 안 함)."""
        minimum = self.min_for(os_family)
        if minimum is None or not running:
            return minimum, None
        return minimum, compare_versions(running, minimum) >= 0


class KernelPolicyStore:
    """정책을 서버 설정(DB)에 저장·조회한다. 요청마다 읽으므로 변경이 즉시 반영된다."""

    def __init__(self, repo, clock):  # noqa: ANN001 - InventoryRepository (순환 import 회피)
        self._repo, self._clock = repo, clock

    def load(self) -> KernelPolicy:
        return KernelPolicy.from_json(self._repo.get_setting(SETTING_KEY))

    def save(self, policy: KernelPolicy) -> None:
        from swinventory.server.timeutil import normalize_ts  # noqa: PLC0415

        self._repo.set_setting(SETTING_KEY, policy.to_json(), normalize_ts(self._clock()))
