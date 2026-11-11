"""에이전트 설정. 우선순위: 설정 파일(JSON) < 환경변수(SWINV_*) < CLI 옵션."""
from __future__ import annotations

import json
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


class ConfigError(ValueError):
    pass


def _default_spool_path(env: Mapping[str, str]) -> str:
    state = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return str(Path(state) / "swinventory" / "spool.db")  # root 가 아니어도 쓸 수 있는 위치


def _as_bool(value: Any) -> bool:
    return value if isinstance(value, bool) else str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class AgentConfig:
    server_url: str | None = None
    token: str | None = None
    token_file: str | None = None
    ca_file: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    json_dir: str | None = None
    spool_path: str = ""
    spool_max_items: int = 200
    timeout: float = 30.0
    allow_insecure_http: bool = False

    @classmethod
    def load(cls, path: str | None, env: Mapping[str, str], overrides: Mapping[str, Any]) -> "AgentConfig":
        data: dict[str, Any] = {}
        if path:
            try:
                data.update(json.loads(Path(path).read_text(encoding="utf-8")))
            except (OSError, ValueError) as exc:
                raise ConfigError(f"설정 파일을 읽지 못했다({path}): {exc}") from exc
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"알 수 없는 설정 키: {sorted(unknown)}")
        for name in known:
            if f"SWINV_{name.upper()}" in env:
                data[name] = env[f"SWINV_{name.upper()}"]
        data.update({k: v for k, v in overrides.items() if v is not None})

        cfg = cls(**data)
        cfg.spool_max_items = int(cfg.spool_max_items)
        cfg.timeout = float(cfg.timeout)
        cfg.allow_insecure_http = _as_bool(cfg.allow_insecure_http)
        cfg.spool_path = cfg.spool_path or _default_spool_path(env)
        if cfg.token_file and not cfg.token:
            try:
                cfg.token = Path(cfg.token_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ConfigError(f"token_file 을 읽지 못했다: {exc}") from exc
        return cfg

    def validate(self, need_server: bool = False) -> None:
        if need_server and not self.server_url:
            raise ConfigError("server_url 이 필요하다")
        if not self.server_url and not self.json_dir:
            raise ConfigError("전송 목적지가 없다: server_url 또는 json_dir 를 설정한다")
        if self.server_url:
            scheme = urlparse(self.server_url).scheme
            if scheme != "https" and not (scheme == "http" and self.allow_insecure_http):
                raise ConfigError("server_url 은 https 여야 한다(개발용은 allow_insecure_http)")
            if not self.token:
                raise ConfigError("token 또는 token_file 이 필요하다")
