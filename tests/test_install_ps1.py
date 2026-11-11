"""deploy/windows/install.ps1 의 다운로드·무결성 검증(-DownloadOnly)을 Linux 의 PowerShell(pwsh) 컨테이너에서 실제로 실행한다.

docker 와 로컬 이미지 swinv-pwsh 가 있을 때만 실행된다(없으면 건너뜀). 만들기: make pwsh-image
(MCR 의 PowerShell 이미지는 amd64 위주라 Apple Silicon 에서 에뮬레이션으로 세그폴트가 난다 — 네이티브 .NET SDK 위에 PowerShell 도구를 설치한 이미지를 쓴다.)
Windows 전용 부분(관리자·예약 작업·ACL)은 -DownloadOnly 가 관리자 확인 앞에서 끝나므로 여기서 검증되지 않는다.
"""
import hashlib
import re
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

IMAGE = "swinv-pwsh:latest"
SCRIPTS = Path(__file__).resolve().parents[1] / "deploy" / "windows"
PAYLOAD = b"MZ-fake-windows-agent\x00\xff"
GOOD = hashlib.sha256(PAYLOAD).hexdigest()


def _have_pwsh_image() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _have_pwsh_image(), reason="docker 와 swinv-pwsh 이미지가 필요하다(make pwsh-image)")


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/agent.exe":
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("0.0.0.0", 0), _Handler)   # 컨테이너에서 host.docker.internal 로 접근
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://host.docker.internal:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


def pwsh(args: str):
    """(종료 코드, stdout+stderr, OutFile 존재 여부). OutFile 은 /tmp/a.exe, 임시 다운로드 잔여물은 LEFTOVER 로 표시한다."""
    cmd = (f"pwsh -NoProfile -File /s/install.ps1 {args}; echo EXIT=$?; test -f /tmp/a.exe && echo OUTFILE=yes || echo OUTFILE=no; "
           "ls /tmp/swinv-agent-*.exe >/dev/null 2>&1 && echo LEFTOVER=yes || echo LEFTOVER=no")
    r = subprocess.run(["docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway", "-v", f"{SCRIPTS}:/s:ro", IMAGE,
                        "bash", "-c", cmd], capture_output=True, text=True, timeout=180)
    out = r.stdout + r.stderr
    return int(re.search(r"EXIT=(\d+)", out).group(1)), out, "OUTFILE=yes" in out


def test_download_only_fetches_and_verifies(server):
    code, out, has_file = pwsh(f"-DownloadOnly -AgentUrl {server}/agent.exe -Sha256 {GOOD} -AllowInsecureHttp -OutFile /tmp/a.exe")
    assert code == 0, out
    assert has_file


def test_uppercase_hash_is_accepted(server):
    assert pwsh(f"-DownloadOnly -AgentUrl {server}/agent.exe -Sha256 {GOOD.upper()} -AllowInsecureHttp -OutFile /tmp/a.exe")[0] == 0


def test_hash_mismatch_fails_and_no_file_is_left(server):
    code, out, has_file = pwsh(f"-DownloadOnly -AgentUrl {server}/agent.exe -Sha256 {'0' * 64} -AllowInsecureHttp -OutFile /tmp/a.exe")
    assert code == 1 and "해시 불일치" in out
    assert GOOD in out and not has_file
    assert "LEFTOVER=no" in out          # 검증에 실패한 exe 가 임시 폴더에 남아 있으면 안 된다(실행될 위험)


@pytest.mark.parametrize("args_tail,expected,why", [
    ("-AllowInsecureHttp", 2, "sha256 없이 -AgentUrl 만"),
    (f"-Sha256 {GOOD}", 2, "평문 http 인데 -AllowInsecureHttp 없음"),
    ("-Sha256 not-hex -AllowInsecureHttp", 2, "sha256 형식 오류"),
    (f"-Sha256 {GOOD[:-1]} -AllowInsecureHttp", 2, "sha256 길이 오류"),
])
def test_argument_errors_exit_2_without_downloading(server, args_tail, expected, why):
    assert pwsh(f"-DownloadOnly -AgentUrl {server}/agent.exe {args_tail}")[0] == expected, why


def test_non_http_scheme_and_missing_agent_url_exit_2():
    assert pwsh(f"-DownloadOnly -AgentUrl ftp://x/agent.exe -Sha256 {GOOD}")[0] == 2
    assert pwsh(f"-DownloadOnly -Sha256 {GOOD}")[0] == 2


def test_http_404_and_unreachable_server_exit_1(server):
    assert pwsh(f"-DownloadOnly -AgentUrl {server}/missing.exe -Sha256 {GOOD} -AllowInsecureHttp")[0] == 1
    assert pwsh(f"-DownloadOnly -AgentUrl http://127.0.0.1:1/agent.exe -Sha256 {GOOD} -AllowInsecureHttp")[0] == 1
