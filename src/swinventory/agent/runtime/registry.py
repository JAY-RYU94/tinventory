"""Windows 레지스트리 읽기 추상화. 읽기 전용(KEY_READ)만 쓴다 — SYSTEM/관리자 권한 불필요."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

HKLM = "HKLM"


class RegistryReader(ABC):
    """view: 64 또는 32(WOW6432Node). 존재하지 않는 키는 values→None, subkeys→[]."""

    @abstractmethod
    def values(self, hive: str, path: str, view: int = 64) -> dict[str, Any] | None: ...

    @abstractmethod
    def subkeys(self, hive: str, path: str, view: int = 64) -> list[str]: ...

    @abstractmethod
    def key_exists(self, hive: str, path: str, view: int = 64) -> bool: ...


class WinRegistryReader(RegistryReader):
    """winreg 기반 구현. winreg 는 Windows 에만 있으므로 호출 시점에 import 한다."""

    @staticmethod
    def _open(hive: str, path: str, view: int):
        import winreg  # noqa: PLC0415

        if hive != HKLM:
            raise ValueError(f"unsupported hive: {hive}")
        flag = winreg.KEY_WOW64_64KEY if view == 64 else winreg.KEY_WOW64_32KEY
        return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | flag)

    def values(self, hive: str, path: str, view: int = 64) -> dict[str, Any] | None:
        import winreg  # noqa: PLC0415

        try:
            key = self._open(hive, path, view)
        except FileNotFoundError:
            return None
        with key:
            out: dict[str, Any] = {}
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    return out
                out[name] = value
                i += 1

    def subkeys(self, hive: str, path: str, view: int = 64) -> list[str]:
        import winreg  # noqa: PLC0415

        try:
            key = self._open(hive, path, view)
        except FileNotFoundError:
            return []
        with key:
            out: list[str] = []
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, i))
                except OSError:
                    return out
                i += 1

    def key_exists(self, hive: str, path: str, view: int = 64) -> bool:
        try:
            self._open(hive, path, view).Close()
        except FileNotFoundError:
            return False
        return True
