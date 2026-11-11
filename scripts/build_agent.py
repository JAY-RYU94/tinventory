#!/usr/bin/env python3
"""에이전트를 단일 파일(.pyz)로 빌드한다. 표준 라이브러리만 쓰므로 대상 서버에는 python3 만 있으면 된다.

    python3 scripts/build_agent.py --out dist/swinventory-agent.pyz
    python3 dist/swinventory-agent.pyz collect --config /etc/swinventory/agent.json

server/ 코드와 서드파티는 포함하지 않는다(common + agent 만).
"""
from __future__ import annotations

import argparse
import shutil
import stat
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "swinventory"
MAIN = "import sys\nfrom swinventory.agent.cli import main\n\nsys.exit(main())\n"  # zipapp -m 은 종료 코드를 버린다


def build(out: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "app"
        pkg = stage / "swinventory"
        pkg.mkdir(parents=True)
        shutil.copy2(SRC / "__init__.py", pkg / "__init__.py")
        for sub in ("common", "agent"):
            shutil.copytree(SRC / sub, pkg / sub, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        # root 로 도는 컨테이너 헬퍼도 해시로 고정된 .pyz 안에 둔다 — 설치 스크립트가 여기서 꺼내 쓰므로 별도 다운로드 경로(무결성 구멍)가 없다
        shutil.copy2(ROOT / "deploy" / "agent" / "containers-helper.sh", pkg / "agent" / "containers-helper.sh")
        (stage / "__main__.py").write_text(MAIN, encoding="utf-8")
        out.parent.mkdir(parents=True, exist_ok=True)
        zipapp.create_archive(stage, out, interpreter="/usr/bin/env python3", compressed=True)
    out.chmod(out.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "swinventory-agent.pyz"))
    path = build(Path(ap.parse_args().out))
    print(f"built {path} ({path.stat().st_size // 1024} KiB)", file=sys.stderr)
