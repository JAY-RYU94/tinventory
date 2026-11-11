from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any, Callable

from swinventory.server.ai.config import AiConfigStore, AiNotConfigured
from swinventory.server.ai.facts import build_facts
from swinventory.server.ai.llm import LlmError, LlmFactory
from swinventory.server.ai.prompt import build_messages
from swinventory.server.policy import KernelPolicy
from swinventory.server.repo.base import InventoryRepository
from swinventory.server.timeutil import normalize_ts


class ReportBusy(RuntimeError):
    pass


class ReportService:
    """리포트 생성. 동시에 하나만 돌린다(비용·중복 방지; 프로세스 단위 잠금)."""

    def __init__(self, repo: InventoryRepository, ai_store: AiConfigStore, load_policy: Callable[[], KernelPolicy],
                 llm_factory: LlmFactory, clock: Callable[[], datetime], stale_after_hours: float):
        self._repo, self._ai, self._policy = repo, ai_store, load_policy
        self._factory, self._clock, self._stale = llm_factory, clock, stale_after_hours
        self._lock = threading.Lock()

    def facts(self) -> dict[str, Any]:
        return build_facts(self._repo, self._policy(), now=self._clock(), stale_after_hours=self._stale)

    def test_connection(self) -> dict[str, Any]:
        try:
            cfg = self._ai.resolve()
            started = time.monotonic()
            self._factory(cfg).complete("Reply with the single word OK.", "ping")
        except (AiNotConfigured, LlmError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, "model": cfg.model, "latency_ms": int((time.monotonic() - started) * 1000)}

    def generate(self) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise ReportBusy("리포트를 생성하는 중이다 — 끝난 뒤 다시 시도한다")
        try:
            cfg = self._ai.resolve()                       # AiNotConfigured
            facts = self.facts()
            system, user = build_messages(facts)
            result = self._factory(cfg).complete(system, user)  # LlmError
            report_id = self._repo.add_report(normalize_ts(self._clock()), cfg.model, result.text, facts,
                                              result.prompt_tokens, result.completion_tokens)
            return self._repo.get_report(report_id)
        finally:
            self._lock.release()
