"""서버 등록: 에이전트·설치 스크립트 배포(무인증)와 sha256 이 고정된 설치 명령 생성(인증).

명령은 서버가 만든다 — 화면과 테스트가 같은 문자열을 쓰고, base_url 을 엄격히 검증하며 인용 규칙을 한 곳에서 지킨다.
"""
from __future__ import annotations

import re
import shlex
from typing import Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse

from swinventory.server.agents import DOWNLOADS, INSTALLERS, AgentCatalog

# 명령에 그대로 들어가므로 셸 메타문자·공백·인증정보·쿼리·프래그먼트가 없는 http(s) 주소만 허용한다
_BASE_URL = re.compile(r"^https?://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?(/[A-Za-z0-9._~-]+)*$")
PLACEHOLDER = "<수집 토큰>"


def validate_base_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not _BASE_URL.match(url):
        raise HTTPException(422, "base_url 은 http(s)://호스트[:포트][/경로] 형식이어야 한다(공백·인증정보·쿼리·특수문자 불가). "
                                 "프록시 뒤라면 SWINV_PUBLIC_URL 을 설정한다")
    return url


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"   # PowerShell 작은따옴표 문자열: ' 는 '' 로


def linux_command(info: dict, base_url: str, token: str, ca: bool, insecure: bool) -> str:
    q = shlex.quote
    curl_ca = f"--cacert {q('/path/to/ca.pem')} " if ca else ""
    flags = f"--token-stdin --server-url {q(base_url)} --agent-url {q(info['url'])} --sha256 {info['sha256']}"
    flags += f" --ca-file {q('/path/to/ca.pem')}" if ca else ""
    flags += " --allow-insecure-http" if insecure else ""
    # 토큰은 표준입력으로 넘긴다: printf 는 셸 내장이라 ps 인자에 남지 않는다(sudo VAR=값 은 설치가 끝날 때까지 ps 에 보인다)
    return (f'f=$(mktemp) && curl -fsSL {curl_ca}{q(info["installer_url"])} -o "$f" && '
            f"printf '%s' {q(token)} | sudo sh \"$f\" {flags}")


def windows_command(info: dict, base_url: str, token: str, ca: bool, insecure: bool) -> str:
    args = f"-ServerUrl {ps_quote(base_url)} -AgentUrl {ps_quote(info['url'])} -Sha256 {ps_quote(info['sha256'])}"
    args += f" -CaFile {ps_quote(r'C:\path\to\ca.pem')}" if ca else ""
    args += " -AllowInsecureHttp" if insecure else ""
    return (f"$env:SWINV_TOKEN={ps_quote(token)}; $f = Join-Path $env:TEMP 'swinv-install.ps1'; "
            f"Invoke-WebRequest -UseBasicParsing {ps_quote(info['installer_url'])} -OutFile $f; "
            f"powershell -NoProfile -ExecutionPolicy Bypass -File $f {args}")


def build_router(catalog: AgentCatalog, ingest_tokens: tuple[str, ...], public_url: str | None,
                 require_read: Callable[..., None], require_admin: Callable[..., None]) -> APIRouter:
    router = APIRouter()

    @router.get("/install/{name}", include_in_schema=False)
    def installer(name: str) -> FileResponse:
        path = catalog.installer(name)
        if path is None:
            raise HTTPException(404, "not found")
        return FileResponse(path, media_type="text/plain; charset=utf-8", headers={"Cache-Control": "no-store"})

    @router.get("/download/{name}", include_in_schema=False)
    def download(name: str):  # noqa: ANN201
        if name == "SHA256SUMS":
            return PlainTextResponse(catalog.sums(), headers={"Cache-Control": "no-store"})
        path = catalog.download(name) if name in DOWNLOADS.values() else None
        if path is None:
            raise HTTPException(404, "not found")
        return FileResponse(path, media_type="application/octet-stream", filename=path.name, headers={"Cache-Control": "no-cache"})

    @router.get("/v1/enrollment", dependencies=[Depends(require_read)])
    def enrollment(request: Request, base_url: str | None = Query(None, max_length=200), ca: bool = False,
                   include_token: bool = False) -> dict:
        """대상 서버에서 실행할 설치 명령. include_token=true 는 관리자만(수집 전용 토큰이 명령에 들어간다)."""
        if include_token:
            require_admin(request.headers.get("authorization"))
        base = validate_base_url(base_url or public_url or str(request.base_url))
        insecure = base.startswith("http://")
        token = ingest_tokens[0] if include_token and ingest_tokens else PLACEHOLDER
        agents = {p: catalog.info(p, base) for p in ("linux", "windows")}
        notes = []
        if insecure:
            notes.append("평문 http 입니다. 실험실 전용이며 운영에서는 https 를 사용하세요(토큰이 평문으로 전송됩니다).")
        if re.match(r"^https?://(localhost|127\.|\[?::1)", base):
            notes.append("이 주소는 다른 서버에서 접근할 수 없습니다. 대상 서버가 접근할 수 있는 주소로 바꾸세요.")
        if ca:
            notes.append("사설 CA 를 쓰는 경우 대상 서버에 CA 파일을 먼저 배포하고 명령의 /path/to/ca.pem(Windows 는 C:\\path\\to\\ca.pem)을 실제 경로로 바꾸세요. "
                         "Windows 에서 설치 스크립트 다운로드 자체는 Windows 인증서 저장소를 쓰므로 CA 를 신뢰 저장소에 등록해야 합니다.")
        commands: dict[str, str | None] = {}
        for platform, build in (("linux", linux_command), ("windows", windows_command)):
            if agents[platform]["available"]:
                commands[platform] = build(agents[platform], base, token, ca, insecure)
            else:
                commands[platform] = None
                label = "Linux" if platform == "linux" else "Windows"
                notes.append(f"{label} 에이전트가 이 서버에 포함되어 있지 않습니다(SWINV_AGENT_DIR 의 {DOWNLOADS[platform]}·{INSTALLERS[INSTALLER_OF_NAME[platform]]} 확인).")
        return {"base_url": base, "insecure": insecure, "token_included": include_token and bool(ingest_tokens),
                "agents": agents, "commands": commands, "notes": notes}

    return router


INSTALLER_OF_NAME = {"linux": "linux.sh", "windows": "windows.ps1"}
