"""조회 라우트가 공유하는 쿼리 파라미터 정의."""
from __future__ import annotations

from fastapi import HTTPException, Query

FORMAT = Query("json", alias="format", pattern="^(json|csv)$", description="json(기본) 또는 csv")


def parse_tags(tag: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in tag:
        key, sep, value = item.partition(":")
        if not sep or not key:
            raise HTTPException(422, "tag 는 key:value 형식이어야 한다")
        out[key] = value
    return out
