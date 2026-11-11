import os
import stat

import pytest
from cryptography.fernet import Fernet

from swinventory.server.secrets import SecretBox, SecretError


def test_roundtrip_and_prefix():
    box = SecretBox(Fernet.generate_key())
    token = box.encrypt("sk-secret-value")
    assert token.startswith("enc:v1:") and "sk-secret-value" not in token
    assert box.decrypt(token) == "sk-secret-value"


def test_encrypt_is_idempotent_and_plaintext_passes_through_decrypt():
    box = SecretBox(Fernet.generate_key())
    token = box.encrypt("x")
    assert box.encrypt(token) == token
    assert box.decrypt("not-encrypted") == "not-encrypted"


def test_wrong_key_and_tampering_fail_closed():
    token = SecretBox(Fernet.generate_key()).encrypt("x")
    with pytest.raises(SecretError):
        SecretBox(Fernet.generate_key()).decrypt(token)
    box = SecretBox(Fernet.generate_key())
    t = box.encrypt("x")
    with pytest.raises(SecretError):
        box.decrypt(t[:-4] + ("AAAA" if not t.endswith("AAAA") else "BBBB"))


def test_invalid_key_message_is_actionable_and_does_not_echo_key():
    with pytest.raises(SecretError, match="Fernet") as ei:
        SecretBox("definitely-not-a-fernet-key")
    assert "definitely-not-a-fernet-key" not in str(ei.value)


def test_from_env_prefers_env_key(tmp_path):
    key = Fernet.generate_key().decode()
    box = SecretBox.from_env({"SWINV_SECRET_KEY": key}, default_key_file=str(tmp_path / "k"))
    assert SecretBox(key).decrypt(box.encrypt("v")) == "v"
    assert not (tmp_path / "k").exists()


def test_from_env_generates_private_key_file_once_and_reuses_it(tmp_path):
    path = tmp_path / "sub" / "secret.key"
    a = SecretBox.from_env({}, default_key_file=str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    token = a.encrypt("v")
    b = SecretBox.from_env({}, default_key_file=str(path))  # 재기동 후에도 복호화 가능해야 한다
    assert b.decrypt(token) == "v"


def test_from_env_honours_secret_file_override(tmp_path):
    path = tmp_path / "custom.key"
    SecretBox.from_env({"SWINV_SECRET_FILE": str(path)}, default_key_file=str(tmp_path / "unused"))
    assert path.exists() and not (tmp_path / "unused").exists()
