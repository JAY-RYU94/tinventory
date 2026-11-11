"""deploy/agent/install.sh 의 다운로드·무결성 검증 경로(--download-only: root·systemd 없이 실행 가능)."""
import hashlib
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "agent" / "install.sh"
PAYLOAD = b"fake-agent-bytes-\x00\xff"
GOOD = hashlib.sha256(PAYLOAD).hexdigest()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/agent.pyz":
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD)))
            self.end_headers()
            self.wfile.write(PAYLOAD)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


def run(*args, env=None, path=None):
    e = {**os.environ, **(env or {})}
    if path is not None:
        e["PATH"] = path
    return subprocess.run(["/bin/sh", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=60)


def download(server, sha=GOOD, **kw):
    return run("--download-only", "--agent-url", f"{server}/agent.pyz", "--sha256", sha, "--allow-insecure-http", **kw)


def test_download_only_fetches_and_verifies_the_agent(server):
    r = download(server)
    assert r.returncode == 0, r.stderr
    path = Path(r.stdout.strip().splitlines()[-1])
    try:
        assert path.read_bytes() == PAYLOAD
    finally:
        path.unlink(missing_ok=True)


def test_uppercase_sha256_is_accepted(server):
    r = download(server, sha=GOOD.upper())
    assert r.returncode == 0, r.stderr
    Path(r.stdout.strip().splitlines()[-1]).unlink(missing_ok=True)


def test_hash_mismatch_fails_and_leaves_no_file_behind(server, tmp_path):
    out = tmp_path / "agent.pyz"
    r = run("--download-only", "--agent-url", f"{server}/agent.pyz", "--sha256", "0" * 64, "--allow-insecure-http", "--out", str(out))
    assert r.returncode == 1 and "해시 불일치" in r.stderr
    assert GOOD in r.stderr and "0" * 64 in r.stderr             # 실제 값과 기대 값을 함께 보여줘 원인을 알 수 있게
    assert not out.exists()                                       # 검증에 실패한 파일은 남기지 않는다(실행 금지)


def test_out_option_writes_the_verified_file(server, tmp_path):
    out = tmp_path / "agent.pyz"
    r = run("--download-only", "--agent-url", f"{server}/agent.pyz", "--sha256", GOOD, "--allow-insecure-http", "--out", str(out))
    assert r.returncode == 0 and out.read_bytes() == PAYLOAD


@pytest.mark.parametrize("args,why", [
    (["--agent-url", "http://127.0.0.1:1/agent.pyz", "--allow-insecure-http"], "sha256 없이 agent-url 만"),
    (["--agent-url", "http://127.0.0.1:1/agent.pyz", "--sha256", GOOD], "평문 http 인데 --allow-insecure-http 없음"),
    (["--agent-url", "ftp://x/agent.pyz", "--sha256", GOOD], "http(s) 가 아닌 스킴"),
    (["--agent-url", "https://x/agent.pyz", "--sha256", "not-hex"], "sha256 형식 오류"),
    (["--agent-url", "https://x/agent.pyz", "--sha256", GOOD[:-1]], "sha256 길이 오류"),
])
def test_argument_errors_exit_2_before_any_download(args, why):
    r = run("--download-only", *args)
    assert r.returncode == 2, why


def test_http_404_and_unreachable_server_fail_with_exit_1(server):
    r = run("--download-only", "--agent-url", f"{server}/missing.pyz", "--sha256", GOOD, "--allow-insecure-http")
    assert r.returncode == 1
    r = run("--download-only", "--agent-url", "http://127.0.0.1:1/agent.pyz", "--sha256", GOOD, "--allow-insecure-http")
    assert r.returncode == 1


def test_works_without_curl_wget_or_sha256sum_using_python_fallbacks(server, tmp_path):
    """최소 설치 서버에는 curl/wget 이 없을 수 있다 — python3 만 있어도 다운로드·해시 검증이 되어야 한다."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("mktemp", "rm", "tr", "cut", "cat", "sed", "dirname", "head", "mv", "id"):
        found = shutil.which(tool)
        if found:
            (bindir / tool).symlink_to(found)
    (bindir / "python3").symlink_to(Path(sys.base_prefix) / "bin" / "python3")
    r = download(server, path=str(bindir))
    assert r.returncode == 0, r.stderr
    Path(r.stdout.strip().splitlines()[-1]).unlink(missing_ok=True)
    assert run("--download-only", "--agent-url", f"{server}/agent.pyz", "--sha256", "f" * 64, "--allow-insecure-http", path=str(bindir)).returncode == 1


def test_install_requires_root_but_download_only_does_not():
    if os.geteuid() == 0:
        pytest.skip("root 로 실행 중")
    r = run("--server-url", "https://x.example.com", "--token", "t")
    assert r.returncode == 2 and "root" in r.stderr
