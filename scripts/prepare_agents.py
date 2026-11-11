#!/usr/bin/env python3
"""개발·데모용: 서버가 배포할 에이전트 디렉터리(dist/agents)를 만든다.

    python3 scripts/prepare_agents.py            # → dist/agents/ (SWINV_AGENT_DIR 로 지정)
Linux .pyz 를 빌드하고 설치 스크립트를 복사하며, Windows exe(windows-agent/build.sh publish 결과)가 있으면 함께 복사한다.
Docker 이미지는 같은 구성을 Dockerfile 이 만든다.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_agent import ROOT, build  # noqa: E402


def prepare(out: Path) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)
    build(out / "swinventory-agent.pyz")
    shutil.copy2(ROOT / "deploy" / "agent" / "install.sh", out / "install.sh")
    shutil.copy2(ROOT / "deploy" / "windows" / "install.ps1", out / "install.ps1")
    exe = ROOT / "windows-agent" / "artifacts" / "win-x64" / "swinventory-agent.exe"
    if exe.exists():
        shutil.copy2(exe, out / "swinventory-agent-win-x64.exe")
    return sorted(p.name for p in out.iterdir())


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist" / "agents"))
    files = prepare(Path(ap.parse_args().out))
    print("agents:", ", ".join(files), file=sys.stderr)
    if not any(f.endswith(".exe") for f in files):
        print("NOTE: Windows exe 가 없다 — windows-agent/build.sh publish 후 다시 실행하면 포함된다", file=sys.stderr)
