from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum

from swinventory.common.models import Snapshot


class TransportError(Exception):
    """재시도하면 성공할 수 있는 실패(네트워크·5xx·인증 설정 오류 등)."""


class PermanentTransportError(TransportError):
    """같은 내용을 다시 보내도 소용없는 거절(스키마 위반·본문 초과). 스풀하지 않고 격리한다."""


class SendOutcome(Enum):
    SENT = "sent"
    SPOOLED = "spooled"  # 전송은 못 했지만 로컬에 안전하게 보관됨


class BaseTransport(ABC):
    @abstractmethod
    def send(self, snapshot: Snapshot) -> SendOutcome:
        """실패 시 TransportError / PermanentTransportError."""
