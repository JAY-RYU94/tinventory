"""설정에 들어가는 비밀(AI API 키 등)의 at-rest 암호화. tclient 의 SecretBox 규약(Fernet, `enc:v1:`, 멱등)을 따른다."""
from __future__ import annotations

import os
import base64
import hashlib
import hmac
from pathlib import Path
from typing import Mapping

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"
KEY_HINT = "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"


class SecretError(RuntimeError):
    """메시지에는 키·평문을 싣지 않는다."""


class SecretBox:
    def __init__(self, key: bytes | str):
        try:
            self._fernet = Fernet(key)
            self._key = base64.urlsafe_b64decode(key)
        except (ValueError, TypeError):
            raise SecretError(f"SWINV_SECRET_KEY 는 유효한 Fernet 키여야 한다. 생성: {KEY_HINT}") from None

    @classmethod
    def from_env(cls, env: Mapping[str, str], *, default_key_file: str) -> "SecretBox":
        """키 우선순위: SWINV_SECRET_KEY → 키 파일(SWINV_SECRET_FILE, 없으면 default_key_file; 없으면 생성, 0600)."""
        if env.get("SWINV_SECRET_KEY"):
            return cls(env["SWINV_SECRET_KEY"])
        path = Path(env.get("SWINV_SECRET_FILE") or default_key_file)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:  # O_EXCL: 두 프로세스가 동시에 만들어도 한쪽 키만 남는다
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as f:
                    f.write(Fernet.generate_key())
        return cls(path.read_bytes().strip())

    def encrypt(self, plaintext: str) -> str:
        if plaintext.startswith(PREFIX):  # 멱등
            return plaintext
        return PREFIX + self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        if not value.startswith(PREFIX):
            return value
        try:
            return self._fernet.decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            raise SecretError("복호화에 실패했다 — 비밀 키가 바뀌었거나 값이 손상됐다") from None


    def derive_key(self, purpose: bytes) -> bytes:
        """서명 키는 암호화 키와 용도를 분리해 파생한다. 원본 키는 노출하지 않는다."""
        return hmac.new(self._key, purpose, hashlib.sha256).digest()
