"""타임스탬프 정규화. DB 에는 고정 폭 UTC 문자열로 저장해 사전순 비교가 곧 시간순 비교가 되게 한다."""
from __future__ import annotations

from datetime import datetime, timezone

_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def normalize_ts(value: str | datetime) -> str:
    """ISO-8601 문자열/datetime → 'YYYY-MM-DDTHH:MM:SS.ffffffZ'(UTC). 형식 오류는 ValueError."""
    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):  # 3.10 의 fromisoformat 은 'Z' 를 모른다
            text = text[:-1] + "+00:00"
        value = datetime.fromisoformat(text)
    if value.tzinfo is None:  # tz 없는 값은 UTC 로 간주
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime(_FMT)
