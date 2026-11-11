"""에이전트 .pyz 빌드 산출물 — root 로 도는 컨테이너 헬퍼가 해시로 고정된 .pyz 안에 들어 있어야 한다(별도 다운로드 경로 없음)."""
import importlib.util
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _build(tmp_path):
    spec = importlib.util.spec_from_file_location("build_agent", ROOT / "scripts" / "build_agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build(tmp_path / "agent.pyz")


def test_pyz_embeds_the_container_helper_identical_to_the_deploy_script(tmp_path):
    pyz = _build(tmp_path)
    with zipfile.ZipFile(pyz) as z:
        embedded = z.read("swinventory/agent/containers-helper.sh")
    assert embedded == (ROOT / "deploy" / "agent" / "containers-helper.sh").read_bytes()


def test_pyz_has_no_server_code(tmp_path):
    names = zipfile.ZipFile(_build(tmp_path)).namelist()
    assert not any(n.startswith("swinventory/server") for n in names)


def _copy_sources(dockerfile: str) -> list[str]:
    """COPY 줄의 원본 경로들(--from 단계 복사는 저장소 파일이 아니므로 제외)."""
    out = []
    for line in dockerfile.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "COPY" and not any(p.startswith("--from") for p in parts[1:]):
            out += [p.rstrip("/") for p in parts[1:-1]]
    return out


def test_dockerfile_copies_every_file_build_agent_reads():
    """서버 이미지는 Docker 안에서 .pyz 를 빌드한다 — build_agent.py 가 읽는 저장소 파일이 Dockerfile 에서 복사되지 않으면 이미지 빌드가 실패한다
    (컨테이너 헬퍼를 .pyz 에 넣으면서 실제로 e2e 에서 터졌고 단위 테스트는 못 잡았다)."""
    import re

    source = (ROOT / "scripts" / "build_agent.py").read_text(encoding="utf-8")
    sources = _copy_sources((ROOT / "Dockerfile").read_text(encoding="utf-8"))
    refs = re.findall(r'ROOT\s*/\s*((?:"[^"]+"\s*/\s*)*"[^"]+")', source)
    paths = ["/".join(re.findall(r'"([^"]+)"', r)) for r in refs]
    assert "deploy/agent/containers-helper.sh" in paths and "src/swinventory" in paths      # 정규식이 실제로 경로를 뽑았는지(0건 통과 방지)
    for path in (p for p in paths if not p.startswith("dist/")):                          # dist/ 는 출력 경로(--out 기본값)다
        assert any(path == s or path.startswith(s + "/") for s in sources), f"Dockerfile 이 {path} 를 복사하지 않는다"


def test_copy_source_parser_is_not_fooled_by_sibling_files():
    """같은 최상위 디렉터리의 다른 파일을 복사한다고 해서 이 파일이 복사되는 것은 아니다."""
    df = "COPY deploy/agent/install.sh /opt/x\nCOPY src ./src\nCOPY --from=winagent /out/ /opt/y/\n"
    sources = _copy_sources(df)
    assert sources == ["deploy/agent/install.sh", "src"]
    assert not any("deploy/agent/containers-helper.sh" == s or "deploy/agent/containers-helper.sh".startswith(s + "/") for s in sources)
