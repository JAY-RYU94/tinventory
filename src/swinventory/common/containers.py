"""컨테이너 이미지 참조의 순수 규칙. 에이전트·서버가 공유한다 — 표준 라이브러리만 사용."""
from __future__ import annotations

_DOCKER_HUBS = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")


def split_image(ref: str | None) -> tuple[str, str, str]:
    """(저장소, 태그, 다이제스트). 태그도 다이제스트도 없으면 태그는 latest. 레지스트리 포트(host:5000)를 태그로 오인하지 않는다."""
    text = (ref or "").strip()
    if not text:
        return "", "", ""
    name, _, digest = text.partition("@")
    slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > slash:                       # 마지막 '/' 뒤의 ':' 만 태그 구분자다
        repo, tag = name[:colon], name[colon + 1:]
    else:
        repo, tag = name, ""
    if not tag and not digest:
        tag = "latest"
    return repo, tag, digest


def normalize_image_ref(ref: str | None) -> str:
    """같은 이미지를 한 이름으로 모은다: docker.io/·library/ 접두 제거, 저장소 이름은 소문자(태그는 대소문자 유지), 태그 없으면 :latest."""
    repo, tag, digest = split_image(ref)
    if not repo:
        return ""
    repo = repo.lower()
    for hub in _DOCKER_HUBS:
        if repo.startswith(hub):
            repo = repo[len(hub):]
            break
    if repo.startswith("library/"):
        repo = repo[len("library/"):]
    out = f"{repo}:{tag}" if tag else repo
    return f"{out}@{digest}" if digest else out
