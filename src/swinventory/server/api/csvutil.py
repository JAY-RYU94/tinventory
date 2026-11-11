from __future__ import annotations

import csv
import io
from typing import Any, Iterable, Sequence

from fastapi import Response

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        value = ";".join(f"{k}={v}" for k, v in sorted(value.items()))
    text = str(value)
    # 호스트명·패키지명은 에이전트가 보낸 신뢰할 수 없는 값이다. 엑셀이 수식으로 실행하지 않게 막는다(CSV injection).
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def csv_response(rows: Iterable[dict[str, Any]], columns: Sequence[str], filename: str) -> Response:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_cell(row.get(c)) for c in columns])
    return Response(
        content="﻿" + buf.getvalue(),  # BOM: 엑셀에서 한글이 깨지지 않게
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
