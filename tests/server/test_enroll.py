"""서버 등록: 서버가 에이전트·설치 스크립트를 배포하고 sha256 이 고정된 설치 명령을 만들어 준다."""
import hashlib
import shlex

import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from tests.server.conftest import make_snapshot

ING, RD, AD = ({"Authorization": f"Bearer {t}"} for t in ("ing-secret", "rd", "adm"))
PYZ, EXE = b"PYZ-BYTES-\x00\x01", b"MZ-EXE-BYTES"


@pytest.fixture
def agents(tmp_path):
    d = tmp_path / "agents"
    d.mkdir()
    (d / "swinventory-agent.pyz").write_bytes(PYZ)
    (d / "swinventory-agent-win-x64.exe").write_bytes(EXE)
    (d / "install.sh").write_text("#!/bin/sh\necho linux installer\n")
    (d / "install.ps1").write_text("Write-Host 'windows installer'\n")
    return d


def make(repo, clock, agents_dir, *, ingest=("ing-secret",), public_url=None):
    s = ApiSettings(ingest_tokens=ingest, read_tokens=("rd",), admin_tokens=("adm",), public_url=public_url)
    return TestClient(create_app(repo, s, clock=clock, env={}, agent_dir=agents_dir))


@pytest.fixture
def client(repo, clock, agents):
    return make(repo, clock, agents)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --- 배포(무인증: 부트스트랩에 토큰이 필요하면 안 된다) ------------------------------

def test_agent_files_and_installers_are_downloadable_without_auth(client):
    assert client.get("/download/swinventory-agent.pyz").content == PYZ
    assert client.get("/download/swinventory-agent-win-x64.exe").content == EXE
    assert "linux installer" in client.get("/install/linux.sh").text
    assert "windows installer" in client.get("/install/windows.ps1").text
    sums = client.get("/download/SHA256SUMS").text.splitlines()
    assert f"{sha(PYZ)}  swinventory-agent.pyz" in sums and f"{sha(EXE)}  swinventory-agent-win-x64.exe" in sums


def test_downloads_are_attachments_and_scripts_are_not_cached(client):
    r = client.get("/download/swinventory-agent.pyz")
    assert "attachment" in r.headers["content-disposition"] and r.headers["content-type"].startswith("application/octet-stream")
    s = client.get("/install/linux.sh")
    assert s.headers["content-type"].startswith("text/plain") and s.headers["cache-control"] == "no-store"
    assert s.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", [
    "/download/../../etc/passwd", "/download/..%2f..%2fetc%2fpasswd", "/download/install.sh",          # 설치 스크립트는 /install 로만
    "/download/unknown.bin", "/install/linux.sh%2f..%2f..", "/install/install.sh", "/install/../x", "/download/", "/install/",
])
def test_only_allowlisted_names_are_served(client, path):
    r = client.get(path)
    # 정규화된 경로가 웹 루트로 접히면 정적 마운트의 UI 페이지가 나온다(안전: 설치 스크립트·외부 파일은 아니다)
    assert r.status_code in (404, 405) or ("<!doctype html>" in r.text.lower() and "installer" not in r.text)
    assert "linux installer" not in r.text and "windows installer" not in r.text and "root:" not in r.text


def test_missing_artifacts_are_404_and_not_listed_in_sums(repo, clock, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    c = make(repo, clock, empty)
    assert c.get("/download/swinventory-agent.pyz").status_code == 404
    assert c.get("/install/linux.sh").status_code == 404
    assert c.get("/download/SHA256SUMS").text == ""
    c2 = make(repo, clock, None)                                   # 에이전트 디렉터리 미설정
    assert c2.get("/download/swinventory-agent.pyz").status_code == 404


# --- 설치 명령 ----------------------------------------------------------------

def enroll(client, headers=RD, **params):
    return client.get("/v1/enrollment", params=params, headers=headers)


def test_enrollment_requires_auth_and_describes_both_platforms(client):
    assert client.get("/v1/enrollment").status_code == 401
    assert client.get("/v1/enrollment", headers=ING).status_code == 403            # 수집 토큰으로는 못 본다
    r = enroll(client, base_url="https://inv.example.com")
    assert r.status_code == 200
    b = r.json()
    assert b["base_url"] == "https://inv.example.com" and b["insecure"] is False and b["token_included"] is False
    assert b["agents"]["linux"] == {"available": True, "file": "swinventory-agent.pyz", "size": len(PYZ), "sha256": sha(PYZ),
                                    "url": "https://inv.example.com/download/swinventory-agent.pyz",
                                    "installer_url": "https://inv.example.com/install/linux.sh"}
    assert b["agents"]["windows"]["sha256"] == sha(EXE) and b["agents"]["windows"]["installer_url"].endswith("/install/windows.ps1")


def test_linux_command_pins_the_hash_and_masks_the_token_by_default(client):
    cmd = enroll(client, base_url="https://inv.example.com").json()["commands"]["linux"]
    assert "ing-secret" not in cmd and "<수집 토큰>" in cmd
    parts = shlex.split(cmd.replace("&&", " && ").replace("|", " | "))
    assert "https://inv.example.com/install/linux.sh" in parts
    assert parts[parts.index("--sha256") + 1] == sha(PYZ)
    assert parts[parts.index("--agent-url") + 1] == "https://inv.example.com/download/swinventory-agent.pyz"
    assert parts[parts.index("--server-url") + 1] == "https://inv.example.com"
    assert "--allow-insecure-http" not in parts


def test_windows_command_pins_the_hash_and_masks_the_token_by_default(client):
    cmd = enroll(client, base_url="https://inv.example.com").json()["commands"]["windows"]
    assert "ing-secret" not in cmd and "<수집 토큰>" in cmd
    assert sha(EXE) in cmd and "-AgentUrl 'https://inv.example.com/download/swinventory-agent-win-x64.exe'" in cmd
    assert "-ServerUrl 'https://inv.example.com'" in cmd and "-AllowInsecureHttp" not in cmd


def test_include_token_is_admin_only_and_linux_passes_it_via_stdin_not_argv(client):
    assert enroll(client, headers=RD, base_url="https://x.example.com", include_token="true").status_code == 403
    b = enroll(client, headers=AD, base_url="https://x.example.com", include_token="true").json()
    assert b["token_included"] is True
    parts = shlex.split(b["commands"]["linux"].replace("&&", " && ").replace("|", " | "))
    i = parts.index("printf")
    assert parts[i + 1] == "%s" and parts[i + 2] == "ing-secret" and parts[i + 3] == "|"        # printf 는 셸 내장이라 ps 에 인자가 남지 않는다
    assert "--token-stdin" in parts and "--token" not in parts
    assert parts.count("ing-secret") == 1                                                     # 토큰은 한 곳(표준입력)에만
    assert "$env:SWINV_TOKEN='ing-secret'" in b["commands"]["windows"] and "-Token " not in b["commands"]["windows"]


def test_token_is_quoted_for_both_shells(repo, clock, agents):
    c = make(repo, clock, agents, ingest=("it's a \"tricky\" $token;rm -rf",))
    b = enroll(c, headers=AD, base_url="https://x.example.com", include_token="true").json()
    parts = shlex.split(b["commands"]["linux"].replace("&&", " && ").replace("|", " | "))
    assert parts[parts.index("printf") + 2] == "it's a \"tricky\" $token;rm -rf"       # 셸이 해석해도 토큰 문자열 그대로
    assert "$env:SWINV_TOKEN='it''s a \"tricky\" $token;rm -rf'" in b["commands"]["windows"]


def test_include_token_without_configured_ingest_token_keeps_the_placeholder(repo, clock, agents):
    c = make(repo, clock, agents, ingest=())
    b = enroll(c, headers=AD, base_url="https://x.example.com", include_token="true").json()
    assert b["token_included"] is False and "<수집 토큰>" in b["commands"]["linux"]


def test_plain_http_adds_the_insecure_flag_and_a_warning(client):
    b = enroll(client, base_url="http://10.0.0.5:8000").json()
    assert b["insecure"] is True and any("https" in n for n in b["notes"])
    assert "--allow-insecure-http" in shlex.split(b["commands"]["linux"].replace("&&", " && ").replace("|", " | "))
    assert "-AllowInsecureHttp" in b["commands"]["windows"]


def test_private_ca_adds_ca_arguments(client):
    b = enroll(client, base_url="https://inv.example.com", ca="true").json()
    parts = shlex.split(b["commands"]["linux"].replace("&&", " && ").replace("|", " | "))
    assert "--cacert" in parts and "--ca-file" in parts                            # curl 과 설치 스크립트 모두
    assert "-CaFile" in b["commands"]["windows"]
    plain = enroll(client, base_url="https://inv.example.com").json()
    assert "--cacert" not in plain["commands"]["linux"] and "-CaFile" not in plain["commands"]["windows"]


@pytest.mark.parametrize("bad", [
    "javascript:alert(1)", "ftp://x.example.com", "https://x.example.com; rm -rf /", "https://x.example.com/$(id)",
    "https://x.example.com/`id`", "https://user:pw@x.example.com", "https://x.example.com?a=b", "https://x.example.com/a b",
    "https://x.example.com/'x", "https://x.example.com\nrm", "   ", "https://", "https://x.example.com/#frag",
])
def test_base_url_is_validated_to_prevent_command_injection(client, bad):
    assert enroll(client, base_url=bad).status_code == 422


def test_base_url_defaults_to_the_request_origin_and_public_url_overrides_it(repo, clock, agents):
    c = make(repo, clock, agents)
    assert enroll(c).json()["base_url"] == "http://testserver"
    c2 = make(repo, clock, agents, public_url="https://inventory.corp.example")
    assert enroll(c2).json()["base_url"] == "https://inventory.corp.example"
    assert enroll(c2, base_url="https://other.example.com").json()["base_url"] == "https://other.example.com"   # 명시하면 그대로


def test_missing_artifact_gives_no_command_and_a_reason(repo, clock, tmp_path):
    d = tmp_path / "a"
    d.mkdir()
    (d / "swinventory-agent.pyz").write_bytes(PYZ)
    (d / "install.sh").write_text("#!/bin/sh\n")
    b = enroll(make(repo, clock, d), base_url="https://x.example.com").json()
    assert b["agents"]["linux"]["available"] is True and b["commands"]["linux"]
    assert b["agents"]["windows"]["available"] is False and b["commands"]["windows"] is None
    assert any("Windows" in n for n in b["notes"])


def test_hash_follows_the_file_when_it_is_replaced(client, agents):
    first = enroll(client, base_url="https://x.example.com").json()["agents"]["linux"]["sha256"]
    (agents / "swinventory-agent.pyz").write_bytes(PYZ + b"-new")
    second = enroll(client, base_url="https://x.example.com").json()["agents"]["linux"]["sha256"]
    assert first == sha(PYZ) and second == sha(PYZ + b"-new")


def test_registered_hosts_appear_after_running_the_command(client):
    """등록 확인: 명령을 실행하면 에이전트가 첫 스냅샷을 올리고 호스트 목록에 나타난다."""
    assert client.get("/v1/hosts", headers=RD).json() == []
    assert client.post("/v1/ingest", json=make_snapshot(host_id="new1", hostname="new-host").to_dict(), headers=ING).status_code == 200
    hosts = client.get("/v1/hosts", headers=RD).json()
    assert [h["hostname"] for h in hosts] == ["new-host"] and hosts[0]["first_seen"]
