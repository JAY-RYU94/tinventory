from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from swinventory.common.models import Snapshot

_SCHEMA = """
CREATE TABLE IF NOT EXISTS spool (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_spool_order ON spool(collected_at, id);
CREATE TABLE IF NOT EXISTS rejected (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    reason TEXT NOT NULL,
    rejected_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class SpoolItem:
    id: int
    snapshot: Snapshot


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SqliteSpool:
    """전송 실패분 보관소(표준 sqlite3). 오래된 순으로 꺼내고, 상한을 넘으면 가장 오래된 것부터 버린다.

    영구 거절·손상 항목은 rejected 테이블로 격리해 큐를 막지 않는다. 파일은 소유자만 읽도록(0600) 한다.
    """

    def __init__(self, path: str | Path, max_items: int = 200):
        self._path = Path(path)
        self._max = max_items
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        os.chmod(self._path, 0o600)

    def _connect(self):
        return closing(sqlite3.connect(self._path, timeout=30))

    def put(self, snapshot: Snapshot) -> None:
        with self._connect() as conn, conn:
            conn.execute("INSERT INTO spool(collected_at, payload, created_at) VALUES (?,?,?)",
                         (snapshot.collected_at, json.dumps(snapshot.to_dict(), ensure_ascii=False), _now()))
            conn.execute(
                "DELETE FROM spool WHERE id IN (SELECT id FROM spool ORDER BY collected_at, id "
                "LIMIT MAX(0, (SELECT COUNT(*) FROM spool) - ?))", (self._max,))

    def oldest(self, limit: int = 50) -> list[SpoolItem]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id, payload FROM spool ORDER BY collected_at, id").fetchall()
        items: list[SpoolItem] = []
        for row_id, payload in rows:
            try:
                items.append(SpoolItem(row_id, Snapshot.from_dict(json.loads(payload))))
            except (ValueError, KeyError, TypeError):
                self.reject(row_id, "corrupt payload")
                continue
            if len(items) >= limit:
                break
        return items

    def delete(self, item_id: int) -> None:
        with self._connect() as conn, conn:
            conn.execute("DELETE FROM spool WHERE id = ?", (item_id,))

    def reject(self, item_id: int, reason: str) -> None:
        with self._connect() as conn, conn:
            conn.execute(
                "INSERT INTO rejected(collected_at, payload, reason, rejected_at) "
                "SELECT collected_at, payload, ?, ? FROM spool WHERE id = ?", (reason[:500], _now(), item_id))
            conn.execute("DELETE FROM spool WHERE id = ?", (item_id,))

    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM spool").fetchone()[0]

    def rejected_count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM rejected").fetchone()[0]
