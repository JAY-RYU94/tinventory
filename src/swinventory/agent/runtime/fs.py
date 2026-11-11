"""파일 읽기 추상화."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class FileReader(ABC):
    @abstractmethod
    def read_text(self, path: str) -> str:
        """없으면 FileNotFoundError."""

    @abstractmethod
    def exists(self, path: str) -> bool: ...


class LocalFileReader(FileReader):
    def read_text(self, path: str) -> str:
        return Path(path).read_text(encoding="utf-8", errors="replace")

    def exists(self, path: str) -> bool:
        return Path(path).exists()
