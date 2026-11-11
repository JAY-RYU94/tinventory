"""AI 연결 설정(tclient 의 사내 엔드포인트 규약): 쓰기 전용 암호화 키, 신뢰 영역, 제한된 TLS 검증 해제, 엔드포인트 정책."""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Callable, Literal, Mapping
from urllib.parse import parse_qsl, urlparse

from pydantic import BaseModel, Field, field_validator

from swinventory.server.ai.llm import AiConfig
from swinventory.server.repo.base import InventoryRepository
from swinventory.server.secrets import SecretBox, SecretError
from swinventory.server.timeutil import normalize_ts

SETTING_KEY = "ai_config"
OFFICIAL_HOSTS = {"api.openai.com"}                 # 공식 엔드포인트는 external 로 고정
BLOCKED_HOSTS = {"metadata.google.internal"}        # 클라우드 메타데이터는 어떤 설정으로도 호출하지 않는다
_SECRET_PARAM = re.compile(r"(key|token|secret|passw|auth|credential)", re.I)


class AiConfigError(ValueError):
    pass


class AiNotConfigured(RuntimeError):
    pass


class AiSettingsIn(BaseModel):
    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=128)
    trust_zone: Literal["internal", "external"]
    api_key: str | None = Field(default=None, max_length=500, description="쓰기 전용. 비우면 기존 값 유지")
    clear_api_key: bool = False
    verify_ssl: bool | None = None
    ca_file: str | None = Field(default=None, max_length=500)
    timeout: float = Field(default=120.0, gt=0, le=600)
    max_tokens: int = Field(default=4000, ge=256, le=16000)

    @field_validator("base_url", "model", "api_key", "ca_file")
    @classmethod
    def _no_control_chars(cls, value: str | None) -> str | None:
        if value is not None and re.search(r"[\x00-\x1f\x7f]", value):
            raise ValueError("제어문자를 넣을 수 없다")
        return value


def validate_endpoint(s: AiSettingsIn, allowlist: tuple[str, ...]) -> None:
    url = urlparse(s.base_url.strip())
    host = (url.hostname or "").lower()
    if url.scheme not in ("http", "https") or not host:
        raise AiConfigError("base_url 은 http(s)://호스트/... 형식이어야 한다")
    if url.username or url.password:
        raise AiConfigError("base_url 에 자격증명(user:pw@)을 넣을 수 없다 — API 키 항목을 사용한다")
    if any(_SECRET_PARAM.search(k) for k, _ in parse_qsl(url.query, keep_blank_values=True)):
        raise AiConfigError("base_url 쿼리에 key/token/password 같은 자격증명을 넣을 수 없다")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:  # IP 가 아니라 호스트명
        ip = None
    # 주의: AiConfigError 는 ValueError 의 하위 클래스라 위 try 안에서 던지면 except 에 삼켜진다 — 밖에서 검사한다
    if ip is not None and ip.is_link_local:
        raise AiConfigError("링크 로컬(169.254.x.x) 주소는 허용하지 않는다(클라우드 메타데이터)")
    if host in BLOCKED_HOSTS:
        raise AiConfigError("클라우드 메타데이터 호스트는 허용하지 않는다")
    if allowlist and host not in {h.lower() for h in allowlist}:
        raise AiConfigError(f"허용된 엔드포인트 호스트가 아니다(SWINV_AI_ENDPOINT_ALLOWLIST): {host}")
    if host in OFFICIAL_HOSTS and s.trust_zone != "external":
        raise AiConfigError("공식 OpenAI 엔드포인트는 trust_zone 이 external 이어야 한다")
    if s.trust_zone == "external" and url.scheme != "https":
        raise AiConfigError("external 엔드포인트는 https 여야 한다")
    if s.verify_ssl is False and s.trust_zone != "internal":
        raise AiConfigError("TLS 검증 비활성화는 internal 엔드포인트에서만 허용한다(가능하면 ca_file 사용)")


class AiConfigStore:
    def __init__(self, repo: InventoryRepository, box: Callable[[], SecretBox], env: Mapping[str, str],
                 allowlist: tuple[str, ...] = (), clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._repo, self._box, self._env, self._allowlist, self._clock = repo, box, env, allowlist, clock

    def _load(self) -> dict | None:
        raw = self._repo.get_setting(SETTING_KEY)
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return None

    def _key_source(self, stored: dict | None) -> str | None:
        if stored and stored.get("api_key_enc"):
            return "settings"
        return "env" if self._env.get("OPENAI_API_KEY") else None

    def public(self) -> dict:
        """API 응답용. 키 자체는 절대 싣지 않고 존재 여부와 출처만 알려준다."""
        stored = self._load()
        source = self._key_source(stored)
        base = {"has_api_key": source is not None, "api_key_source": source}
        if not stored:
            return {"configured": False, **base}
        return {"configured": True, **base, **{k: stored.get(k) for k in
                ("base_url", "model", "trust_zone", "verify_ssl", "ca_file", "timeout", "max_tokens")}}

    def update(self, s: AiSettingsIn) -> dict:
        validate_endpoint(s, self._allowlist)
        stored = self._load() or {}
        enc = stored.get("api_key_enc")
        if s.api_key:
            enc = self._box().encrypt(s.api_key.strip())
        elif s.clear_api_key:
            enc = None
        doc = {"base_url": s.base_url.strip(), "model": s.model.strip(), "trust_zone": s.trust_zone,
               "verify_ssl": s.verify_ssl, "ca_file": (s.ca_file or "").strip() or None,
               "timeout": s.timeout, "max_tokens": s.max_tokens, "api_key_enc": enc}
        self._repo.set_setting(SETTING_KEY, json.dumps(doc), normalize_ts(self._clock()))
        return self.public()

    def resolve(self) -> AiConfig:
        """실행용 설정(복호화된 키 포함). 미설정이면 AiNotConfigured."""
        stored = self._load()
        if not stored:
            raise AiNotConfigured("AI 연결이 설정되지 않았다 — 설정 화면에서 엔드포인트와 모델을 입력한다")
        key = ""
        if stored.get("api_key_enc"):
            try:
                key = self._box().decrypt(stored["api_key_enc"])
            except SecretError as exc:
                raise AiNotConfigured(f"저장된 API 키를 읽지 못했다({exc}) — 설정에서 API 키를 다시 입력한다") from None
        key = key or self._env.get("OPENAI_API_KEY", "")
        if stored["trust_zone"] == "external" and not key:
            raise AiNotConfigured("외부 엔드포인트는 API 키가 필요하다 — 설정에서 입력하거나 OPENAI_API_KEY 를 지정한다")
        return AiConfig(base_url=stored["base_url"], model=stored["model"], trust_zone=stored["trust_zone"], api_key=key,
                        verify_ssl=stored.get("verify_ssl"), ca_file=stored.get("ca_file"),
                        timeout=float(stored.get("timeout") or 120), max_tokens=int(stored.get("max_tokens") or 4000))
