"""에이전트↔서버 계약 스키마 생성. `python -m swinventory.server.contract --write` 로 갱신한다."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from swinventory.server.api.models import IngestSnapshot

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "contracts" / "snapshot.v1.schema.json"


def render_schema() -> str:
    return json.dumps(IngestSnapshot.model_json_schema(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    if "--write" in sys.argv:
        SCHEMA_PATH.write_text(render_schema(), encoding="utf-8")
        print(f"wrote {SCHEMA_PATH}")
    else:
        sys.stdout.write(render_schema())
