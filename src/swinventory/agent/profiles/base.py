from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from swinventory.agent.collectors.base import BaseCollector


class UnsupportedPlatformError(RuntimeError):
    pass


class PlatformProfile(ABC):
    """플랫폼별 수집기 조합과 host_id 제공자(추상 팩토리)."""

    family: ClassVar[str]

    @abstractmethod
    def host_id(self) -> str: ...

    @abstractmethod
    def collectors(self) -> list[BaseCollector]: ...
