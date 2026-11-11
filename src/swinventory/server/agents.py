"""에이전트 배포 카탈로그. 서버가 에이전트 파일과 설치 스크립트를 직접 내려줘서 대상 서버에서 한 줄로 등록할 수 있게 한다.

허용 목록(고정 파일명)만 내보내므로 경로 탐색 여지가 없다. 해시는 파일이 바뀌면(mtime·크기) 다시 계산한다.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

DOWNLOADS = {"linux": "swinventory-agent.pyz", "windows": "swinventory-agent-win-x64.exe"}
# URL 이름 → 디렉터리 안의 파일명. 설치 스크립트는 /install/<URL 이름> 으로만 나간다
INSTALLERS = {"linux.sh": "install.sh", "windows.ps1": "install.ps1"}
INSTALLER_OF = {"linux": "linux.sh", "windows": "windows.ps1"}


class AgentCatalog:
    def __init__(self, directory: Path | str | None):
        self._dir = Path(directory) if directory else None
        self._hashes: dict[Path, tuple[tuple[int, int], str]] = {}

    def _file(self, name: str) -> Path | None:
        if self._dir is None:
            return None
        path = self._dir / name
        return path if path.is_file() else None

    def download(self, name: str) -> Path | None:
        return self._file(name) if name in DOWNLOADS.values() else None

    def installer(self, url_name: str) -> Path | None:
        return self._file(INSTALLERS[url_name]) if url_name in INSTALLERS else None

    def sha256(self, path: Path) -> str:
        st = path.stat()
        key = (st.st_mtime_ns, st.st_size)
        cached = self._hashes.get(path)
        if cached and cached[0] == key:
            return cached[1]
        digest = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        self._hashes[path] = (key, digest.hexdigest())
        return digest.hexdigest()

    def info(self, platform: str, base_url: str) -> dict:
        artifact = self.download(DOWNLOADS[platform])
        installer = self.installer(INSTALLER_OF[platform])
        if artifact is None or installer is None:
            return {"available": False, "file": DOWNLOADS[platform], "size": 0, "sha256": "", "url": "", "installer_url": ""}
        return {"available": True, "file": artifact.name, "size": artifact.stat().st_size, "sha256": self.sha256(artifact),
                "url": f"{base_url}/download/{artifact.name}", "installer_url": f"{base_url}/install/{INSTALLER_OF[platform]}"}

    def sums(self) -> str:
        lines = [f"{self.sha256(p)}  {p.name}" for name in DOWNLOADS.values() if (p := self.download(name)) is not None]
        return "\n".join(lines) + ("\n" if lines else "")
