from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Mapping

from swinventory.agent.transport.base import (
    BaseTransport, PermanentTransportError, SendOutcome, TransportError,
)
from swinventory.common.models import Snapshot

INGEST_PATH = "/v1/ingest"
_PERMANENT_STATUSES = {400, 413, 422}  # 401/403(토큰 교정 후 복구)·404(URL 교정)·429·5xx 는 재시도 대상


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes = b""


class HttpPoster(ABC):
    """HTTP POST 추상화. 4xx/5xx 도 예외가 아니라 응답으로 돌려주고, 연결 실패만 OSError."""

    @abstractmethod
    def post(self, url: str, body: bytes, headers: Mapping[str, str], timeout: float) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None  # Bearer 토큰을 들고 다른 곳으로 따라가지 않는다


class UrllibPoster(HttpPoster):
    """표준 라이브러리 구현. 사설 CA(ca_file)와 mTLS(client_cert/client_key)를 지원한다."""

    def __init__(self, ca_file: str | None = None, client_cert: str | None = None,
                 client_key: str | None = None):
        ctx = ssl.create_default_context(cafile=ca_file)
        if client_cert:
            ctx.load_cert_chain(client_cert, client_key)
        self._opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))

    def post(self, url: str, body: bytes, headers: Mapping[str, str], timeout: float) -> HttpResponse:
        req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return HttpResponse(resp.status, resp.read())
        except urllib.error.HTTPError as exc:
            return HttpResponse(exc.code, exc.read())


class HttpsTransport(BaseTransport):
    def __init__(self, base_url: str, token: str, poster: HttpPoster, timeout: float = 30.0):
        self._url = base_url.rstrip("/") + INGEST_PATH
        self._token = token
        self._poster = poster
        self._timeout = timeout

    def send(self, snapshot: Snapshot) -> SendOutcome:
        body = json.dumps(snapshot.to_dict(), ensure_ascii=False).encode("utf-8")
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        try:
            resp = self._poster.post(self._url, body, headers, self._timeout)
        except (OSError, TimeoutError) as exc:  # URLError·ssl.SSLError 포함. 메시지에 토큰은 없다
            raise TransportError(f"request failed: {type(exc).__name__}: {exc}") from exc
        if 200 <= resp.status < 300:
            return SendOutcome.SENT
        detail = resp.body[:200].decode("utf-8", errors="replace")
        error = PermanentTransportError if resp.status in _PERMANENT_STATUSES else TransportError
        raise error(f"server responded {resp.status}: {detail}")
