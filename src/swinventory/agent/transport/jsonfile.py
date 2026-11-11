from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

from swinventory.agent.transport.base import BaseTransport, SendOutcome
from swinventory.common.models import Snapshot


class JsonFileTransport(BaseTransport):
    """개발용: 스냅샷을 디렉터리에 JSON 파일로 쓴다. tmp 파일에 쓴 뒤 rename 해서 반쪽 파일을 남기지 않는다."""

    def __init__(self, directory: str | Path):
        self._dir = Path(directory)

    def send(self, snapshot: Snapshot) -> SendOutcome:
        self._dir.mkdir(parents=True, exist_ok=True)
        stamp = re.sub(r"[^0-9A-Za-z]", "", snapshot.collected_at)
        final = self._dir / f"snapshot-{stamp}-{uuid.uuid4().hex[:8]}.json"
        tmp = final.with_suffix(".tmp")
        tmp.write_text(json.dumps(snapshot.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, final)
        return SendOutcome.SENT
