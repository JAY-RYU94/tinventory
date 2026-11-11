"""OpenAI 호환 chat completions 클라이언트. 외부 접근은 AiHttp 로 추상화해 테스트에서 대체한다."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Mapping


class LlmError(RuntimeError):
    """메시지는 UI 에 그대로 보여줘도 안전하다(키·원문 응답을 싣지 않는다)."""


@dataclass(frozen=True)
class AiConfig:
    base_url: str
    model: str
    trust_zone: str  # internal | external
    api_key: str = ""
    verify_ssl: bool | None = None  # None=기본(검증). False 는 internal 에서만 허용(검증은 설정 저장 시점)
    ca_file: str | None = None      # 사내 게이트웨이의 사설 CA — 검증을 끄는 것보다 낫다
    timeout: float = 120.0
    max_tokens: int = 4000


@dataclass(frozen=True)
class LlmResult:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class LlmClient(ABC):
    @abstractmethod
    def complete(self, system: str, user: str) -> LlmResult: ...


LlmFactory = Callable[[AiConfig], LlmClient]


class AiHttp(ABC):
    @abstractmethod
    def post_json(self, url: str, body: dict, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes]:
        """4xx/5xx 도 예외가 아니라 (status, body) 로 돌려준다. 연결 실패만 OSError."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None  # Authorization 헤더를 들고 다른 곳으로 따라가면 키가 유출된다


class UrllibAiHttp(AiHttp):
    def __init__(self, verify: bool = True, ca_file: str | None = None):
        ctx = ssl.create_default_context(cafile=ca_file)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))

    def post_json(self, url: str, body: dict, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=dict(headers), method="POST")
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


def default_llm_factory(config: AiConfig) -> LlmClient:
    try:
        http = UrllibAiHttp(verify=config.verify_ssl is not False, ca_file=config.ca_file)
    except OSError as exc:
        raise LlmError(f"CA 파일을 읽지 못했다: {type(exc).__name__}") from None
    return OpenAICompatClient(config, http)


class OpenAICompatClient(LlmClient):
    def __init__(self, config: AiConfig, http: AiHttp):
        self._cfg = config
        self._http = http

    def _redact(self, text: str) -> str:
        key = self._cfg.api_key
        return text.replace(key, "***") if key else text

    def _post(self, body: dict) -> tuple[int, bytes]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._cfg.api_key:  # 키가 없는 사내 게이트웨이(로컬 Ollama 등)는 헤더를 보내지 않는다
            headers["Authorization"] = f"Bearer {self._cfg.api_key}"
        url = self._cfg.base_url.rstrip("/") + "/chat/completions"
        try:
            return self._http.post_json(url, body, headers, self._cfg.timeout)
        except (OSError, TimeoutError) as exc:
            raise LlmError(f"LLM 엔드포인트에 연결하지 못했다: {self._redact(type(exc).__name__ + ': ' + str(exc))[:200]}") from None

    def complete(self, system: str, user: str) -> LlmResult:
        body: dict = {"model": self._cfg.model, "max_tokens": self._cfg.max_tokens,
                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        # temperature 등 샘플링 파라미터는 보내지 않는다(신형 모델이 400 으로 거부).
        status, raw = self._post(body)
        if status == 400 and b"max_completion_tokens" in raw:  # 신형 OpenAI 모델: max_tokens 대신 이 이름을 요구
            body["max_completion_tokens"] = body.pop("max_tokens")
            status, raw = self._post(body)
        if not 200 <= status < 300:
            raise LlmError(self._status_message(status, raw))
        try:
            data = json.loads(raw)
            text = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise LlmError("LLM 응답 형식이 올바르지 않다(choices[0].message.content 없음)") from None
        if not isinstance(text, str) or not text.strip():
            raise LlmError("LLM 이 빈 응답을 돌려줬다(모델·max_tokens 설정을 확인한다)")
        usage = data.get("usage") or {}
        return LlmResult(text.strip(), str(data.get("model") or self._cfg.model),
                         usage.get("prompt_tokens"), usage.get("completion_tokens"))

    def _status_message(self, status: int, raw: bytes) -> str:
        if status in (401, 403):
            return f"인증 실패({status}) — API 키를 확인한다"
        if status == 404:
            return "엔드포인트를 찾지 못했다(404) — base_url 과 모델명을 확인한다"
        if status == 429:
            return "요청 한도 초과(429) — 잠시 후 다시 시도한다"
        if status >= 500:
            return f"LLM 서버 오류({status})"
        detail = ""
        try:
            err = json.loads(raw).get("error", {})
            detail = err.get("message", "") if isinstance(err, dict) else str(err)
        except (ValueError, AttributeError):
            pass
        return f"요청이 거부됐다({status})" + (f": {self._redact(detail)[:200]}" if detail else "")
