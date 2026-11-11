from __future__ import annotations

import logging

from swinventory.agent.transport.base import (
    BaseTransport, PermanentTransportError, SendOutcome, TransportError,
)
from swinventory.agent.transport.spool import SqliteSpool
from swinventory.common.models import Snapshot

log = logging.getLogger("swinventory.agent")


class SpoolingTransport(BaseTransport):
    """실패 시 스풀에 보관하고 다음 기회에 오래된 순으로 재전송하는 데코레이터.

    순서 보존: 스풀이 비워지지 않았으면 현재 스냅샷은 항상 스풀 맨 뒤에 들어간다.
    """

    def __init__(self, inner: BaseTransport, spool: SqliteSpool):
        self._inner = inner
        self._spool = spool

    def flush(self) -> bool:
        """스풀을 오래된 순으로 전송한다. 모두 비우면 True, 재시도 가능한 실패로 멈추면 False."""
        while True:
            items = self._spool.oldest(50)
            if not items:
                return True
            for item in items:
                try:
                    self._inner.send(item.snapshot)
                except PermanentTransportError as exc:
                    log.error("스풀 항목 영구 거절, 격리: %s", exc)
                    self._spool.reject(item.id, str(exc))
                except TransportError as exc:
                    log.warning("스풀 재전송 중단(남은 %d건): %s", self._spool.count(), exc)
                    return False
                else:
                    self._spool.delete(item.id)

    def send(self, snapshot: Snapshot) -> SendOutcome:
        if not self.flush():
            self._spool.put(snapshot)
            return SendOutcome.SPOOLED
        try:
            return self._inner.send(snapshot)
        except PermanentTransportError:
            raise  # 같은 내용을 다시 보내도 소용없으므로 스풀하지 않는다
        except TransportError as exc:
            log.warning("전송 실패, 스풀에 보관: %s", exc)
            self._spool.put(snapshot)
            return SendOutcome.SPOOLED
