from __future__ import annotations

import json
from typing import Awaitable, Callable

Scope = dict
Receive = Callable[[], Awaitable[dict]]
Send = Callable[[dict], Awaitable[None]]

_BODY_METHODS = {"POST", "PUT", "PATCH"}


async def _respond(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    """요청 본문 상한(ASGI). 앱 바깥에서 막아 파싱 전에 메모리를 지킨다.

    Content-Length 가 있으면 즉시 판정하고, 없으면(chunked) 상한까지만 버퍼링한 뒤 앱에 재생한다.
    앱 안에서 예외로 끊으면 ServerErrorMiddleware 가 500 으로 바꿔버리기 때문에 앱 호출 전에 판정한다.
    """

    def __init__(self, app: Callable, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return
        declared = next((v for k, v in scope["headers"] if k == b"content-length"), None)
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True
            if too_big:
                await _respond(send, 413, "request body too large")
                return
            await self.app(scope, receive, send)
            return

        chunks: list[bytes] = []
        total = 0
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            body = msg.get("body", b"")
            total += len(body)
            if total > self.max_bytes:
                await _respond(send, 413, "request body too large")
                return
            chunks.append(body)
            if not msg.get("more_body", False):
                break

        replayed = False

        async def replay() -> dict:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class RejectNulMiddleware:
    """경로·쿼리에 NUL(%00)이 있으면 400. PostgreSQL 은 NUL 이 든 문자열 파라미터를 거부해 500 이 되고,
    입력 하나하나를 라우트마다 정제하기보다 경계에서 한 번에 막는 편이 빠짐이 없다."""

    def __init__(self, app: Callable):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            target = scope.get("raw_path", b"") + b"?" + scope.get("query_string", b"")
            if b"\x00" in target or b"%00" in target:
                await _respond(send, 400, "NUL 문자는 허용되지 않는다")
                return
        await self.app(scope, receive, send)


_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
_NO_CSP_PATHS = ("/docs", "/redoc", "/openapi.json")  # Swagger UI 는 CDN 스크립트를 쓴다


class SecurityHeadersMiddleware:
    """화면(정적 파일)과 API 응답에 보안 헤더를 붙인다. 에이전트가 보낸 문자열은 신뢰하지 않는다."""

    def __init__(self, app: Callable):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")

        async def send_with_headers(msg: dict) -> None:
            if msg["type"] == "http.response.start":
                headers = list(msg.get("headers", []))
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"referrer-policy", b"no-referrer"))
                if not path.startswith(_NO_CSP_PATHS):
                    headers.append((b"content-security-policy", _CSP.encode()))
                    headers.append((b"x-frame-options", b"DENY"))
                if path.startswith("/v1/"):
                    headers.append((b"cache-control", b"no-store"))
                msg = {**msg, "headers": headers}
            await send(msg)

        await self.app(scope, receive, send_with_headers)
