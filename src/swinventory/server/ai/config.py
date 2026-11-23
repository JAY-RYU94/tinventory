"""AI 연결 설정(tclient 의 사내 엔드포인트 규약): 쓰기 전용 암호화 키, 신뢰 영역, 제한된 TLS 검증 해제, 엔드포인트 정책."""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Callable, Literal, Mapping
from urllib.parse import parse_qsl, urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from swinventory.server.ai.llm import AiConfig
from swinventory.server.repo.base import InventoryRepository
from swinventory.server.secrets import SecretBox, SecretError
from swinventory.server.timeutil import normalize_ts

SETTING_KEY = "ai_config"
OFFICIAL_HOSTS = {"api.openai.com"}                 # 공식 엔드포인트는 external 로 고정
BLOCKED_HOSTS = {"metadata.google.internal"}        # 클라우드 메타데이터는 어떤 설정으로도 호출하지 않는다
_SECRET_PARAM = re.compile(r"(key|token|secret|passw|auth|credential)", re.I)
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_RESERVED_HEADERS = {
    "accept", "connection", "content-length", "content-type", "expect", "host", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer",
    "transfer-encoding", "upgrade",
}
_MAX_HEADER_TOTAL = 16_384


class AiConfigError(ValueError):
    pass


class AiNotConfigured(RuntimeError):
    pass


class AiHeaderIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    # null means keep the saved secret for this name; "" is a real empty header value.
    value: str | None = Field(default=None, max_length=4096)

    @field_validator("name")
    @classmethod
    def _header_name(cls, value: str) -> str:
        if not _HEADER_NAME.fullmatch(value):
            raise ValueError("헤더 이름은 HTTP token 문자만 사용할 수 있다")
        if value.casefold() in _RESERVED_HEADERS:
            raise ValueError("HTTP 요청 제어에 쓰이는 헤더는 추가할 수 없다")
        return value

    @field_validator("value")
    @classmethod
    def _header_value(cls, value: str | None) -> str | None:
        if value is None:
            return None
        # HTAB is valid HTTP field whitespace. Reject all other C0 controls, DEL, CR/LF and NUL.
        if any((ord(ch) < 0x20 and ch != "\t") or ord(ch) == 0x7f for ch in value):
            raise ValueError("헤더 값에 제어문자를 넣을 수 없다")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError("헤더 값은 HTTP Latin-1 문자 범위여야 한다") from None
        return value


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
    extra_headers: list[AiHeaderIn] | None = Field(default=None, max_length=32)
    auth_header: str | None = Field(default=None, max_length=128)

    @field_validator("base_url", "model", "api_key", "ca_file")
    @classmethod
    def _no_control_chars(cls, value: str | None) -> str | None:
        if value is not None and re.search(r"[\x00-\x1f\x7f]", value):
            raise ValueError("제어문자를 넣을 수 없다")
        return value

    @field_validator("auth_header")
    @classmethod
    def _auth_header_name(cls, value: str | None) -> str | None:
        if value is not None and not _HEADER_NAME.fullmatch(value):
            raise ValueError("사용자 인증 헤더는 유효한 HTTP 헤더 이름이어야 한다")
        return value

    @model_validator(mode="after")
    def _unique_bounded_headers(self) -> "AiSettingsIn":
        if self.extra_headers is None:
            return self
        seen: set[str] = set()
        total = 0
        for item in self.extra_headers:
            key = item.name.casefold()
            if key in seen:
                raise ValueError("헤더 이름은 대소문자를 구분하지 않고 중복될 수 없다")
            seen.add(key)
            total += len(item.name) + (len(item.value) if item.value is not None else 0)
        if total > _MAX_HEADER_TOTAL:
            raise ValueError("추가 헤더 전체 크기는 16 KiB 이하여야 한다")
        return self


def validate_endpoint(s: AiSettingsIn, allowlist: tuple[str, ...]) -> None:
    try:
        url = urlparse(s.base_url.strip())
        port = url.port
    except ValueError:
        raise AiConfigError("base_url 주소가 올바르지 않다") from None
    host = (url.hostname or "").lower()
    if url.scheme not in ("http", "https") or not host:
        raise AiConfigError("base_url 은 http(s)://호스트/... 형식이어야 한다")
    if url.username or url.password:
        raise AiConfigError("base_url 에 자격증명(user:pw@)을 넣을 수 없다 — API 키 항목을 사용한다")
    if port is not None and not 1 <= port <= 65535:
        raise AiConfigError("base_url 포트는 1~65535 범위여야 한다")
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


def _origin(base_url: str | None) -> tuple[str, str, int | None] | None:
    """scheme/host/effective-port. 경로가 바뀌어도 origin 이 같으면 비밀 헤더를 유지한다."""
    if not base_url:
        return None
    try:
        url = urlparse(base_url.strip())
        host, port = (url.hostname or "").casefold(), url.port
    except ValueError:
        return None
    if not host:
        return None
    effective_port = port if port is not None else {"http": 80, "https": 443}.get(url.scheme.casefold())
    return url.scheme.casefold(), host, effective_port


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
            return {"configured": False, **base, "extra_headers": [], "auth_header": None}
        return {"configured": True, **base, **{k: stored.get(k) for k in
                ("base_url", "model", "trust_zone", "verify_ssl", "ca_file", "timeout", "max_tokens")},
                "extra_headers": [{"name": h.get("name", ""), "has_value": h.get("value_enc") is not None}
                                  for h in stored.get("extra_headers", []) if isinstance(h, dict)],
                "auth_header": stored.get("auth_header")}

    def update(self, s: AiSettingsIn) -> dict:
        validate_endpoint(s, self._allowlist)
        stored = self._load() or {}
        enc = stored.get("api_key_enc")
        supplied_key = s.api_key.strip() if s.api_key and s.api_key.strip() else ""
        if supplied_key:
            enc = self._box().encrypt(supplied_key)
        elif s.clear_api_key:
            enc = None
        headers_in = s.extra_headers if "extra_headers" in s.model_fields_set else None
        old_headers = [h for h in stored.get("extra_headers", []) if isinstance(h, dict)]
        old_by_name = {str(h.get("name", "")).casefold(): h for h in old_headers}
        if headers_in is None:
            final_headers = old_headers
        else:
            final_headers = []
            for item in headers_in:
                previous = old_by_name.get(item.name.casefold())
                if item.value is None and previous:
                    value_enc = previous.get("value_enc")
                else:
                    # SecretBox.encrypt 는 enc:v1: 접두사를 기존 암호문으로 보므로 사용자 입력은 항상 새로 암호화한다.
                    value_enc = self._box().encrypt_literal(item.value or "")
                final_headers.append({"name": item.name, "value_enc": value_enc})

        total_header_size = 0
        try:
            for header in final_headers:
                value_enc = header.get("value_enc")
                value = self._box().decrypt(value_enc) if value_enc is not None else ""
                total_header_size += len(header["name"]) + len(value)
        except SecretError:
            raise AiConfigError("저장된 추가 헤더를 읽지 못했다 — 설정에서 값을 다시 입력한다") from None
        if total_header_size > _MAX_HEADER_TOTAL:
            raise AiConfigError("추가 헤더 전체 크기는 16 KiB 이하여야 한다")

        old_origin, new_origin = _origin(stored.get("base_url")), _origin(s.base_url)
        if old_headers and old_origin != new_origin:
            if headers_in is None or any(
                    item.value is None and item.name.casefold() in old_by_name for item in headers_in):
                raise AiConfigError("새 엔드포인트로 바꿀 때는 기존 추가 헤더 값을 새로 입력하거나 해당 헤더를 삭제해야 한다")

        if "auth_header" in s.model_fields_set:
            auth_header = s.auth_header
        else:
            auth_header = stored.get("auth_header")
        headers_by_name = {h["name"].casefold(): h for h in final_headers}
        if auth_header is not None:
            matching = headers_by_name.get(auth_header.casefold())
            if matching is None:
                raise AiConfigError("사용자 인증 헤더로 선택한 이름이 추가 헤더 목록에 없다")
            auth_header = matching["name"]

        has_api_key = bool(enc or self._env.get("OPENAI_API_KEY"))
        if has_api_key and "authorization" in headers_by_name:
            raise AiConfigError("추가 Authorization 헤더와 API 키의 Bearer Authorization 을 함께 설정할 수 없다. API 키를 지우거나 다른 헤더 이름을 사용한다")

        doc = {"base_url": s.base_url.strip(), "model": s.model.strip(), "trust_zone": s.trust_zone,
               "verify_ssl": s.verify_ssl, "ca_file": (s.ca_file or "").strip() or None,
               "timeout": s.timeout, "max_tokens": s.max_tokens, "api_key_enc": enc,
               "extra_headers": final_headers, "auth_header": auth_header}
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
            except SecretError:
                raise AiNotConfigured("저장된 API 키를 읽지 못했다 — 설정에서 API 키를 다시 입력한다") from None
        key = key or self._env.get("OPENAI_API_KEY", "")
        headers = []
        for header in stored.get("extra_headers", []):
            name, encrypted = header.get("name", ""), header.get("value_enc")
            if encrypted is None:
                value = ""
            else:
                try:
                    value = self._box().decrypt(encrypted)
                except SecretError:
                    raise AiNotConfigured("저장된 추가 헤더를 읽지 못했다 — 설정에서 값을 다시 입력한다") from None
            headers.append((name, value))
        if any(name.casefold() == "authorization" for name, _ in headers) and key:
            raise AiNotConfigured("추가 Authorization 헤더와 API 키 Bearer 가 충돌한다 — 하나만 설정한다")
        auth_name = stored.get("auth_header")
        custom_auth = next((value for name, value in headers if auth_name and name.casefold() == auth_name.casefold()), "")
        if stored["trust_zone"] == "external" and not key and not custom_auth.strip():
            raise AiNotConfigured("외부 엔드포인트는 API 키 또는 사용자 인증 헤더가 필요하다 — API 키를 입력하거나 추가 헤더를 인증용으로 지정한다")
        return AiConfig(base_url=stored["base_url"], model=stored["model"], trust_zone=stored["trust_zone"], api_key=key,
                        verify_ssl=stored.get("verify_ssl"), ca_file=stored.get("ca_file"),
                        timeout=float(stored.get("timeout") or 120), max_tokens=int(stored.get("max_tokens") or 4000),
                        extra_headers=tuple(headers))
