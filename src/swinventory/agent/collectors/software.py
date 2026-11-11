from __future__ import annotations

from typing import ClassVar

from swinventory.agent.collectors.base import BaseCollector
from swinventory.common.models import PackageRecord


class SoftwareCollector(BaseCollector[list[PackageRecord]]):
    """설치 소프트웨어 수집기 베이스. 이름 규칙: "software.<source>"."""

    source: ClassVar[str] = ""

    @property
    def name(self) -> str:
        if not self.source:
            raise NotImplementedError(f"{type(self).__name__}.source 를 지정해야 한다")
        return f"software.{self.source}"
