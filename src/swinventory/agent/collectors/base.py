"""수집기 베이스(템플릿 메서드). 예외는 CollectorResult 로 변환해 다른 수집기를 막지 않는다."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class CollectorResult(Generic[T]):
    name: str
    ok: bool
    value: T | None = None
    error: str | None = None


class BaseCollector(ABC, Generic[T]):
    @property
    @abstractmethod
    def name(self) -> str:
        """snapshot.collected / snapshot.errors 의 키."""

    def collect(self) -> CollectorResult[T]:
        """고정 순서: _run(외부 접근) → _parse(순수 변환). 어떤 예외도 실패 결과로 돌려준다."""
        try:
            value = self._parse(self._run())
        except Exception as exc:  # noqa: BLE001 - 수집기 격리가 목적
            return CollectorResult(self.name, False, None, f"{type(exc).__name__}: {exc}")
        return CollectorResult(self.name, True, value)

    @abstractmethod
    def _run(self) -> Any:
        """외부 접근(명령·파일·레지스트리)만 수행하고 원본을 돌려준다."""

    @abstractmethod
    def _parse(self, raw: Any) -> T:
        """원본 → 모델. 부수효과 없음."""
