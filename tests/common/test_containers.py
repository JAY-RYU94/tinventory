import pytest

from swinventory.common.containers import normalize_image_ref, split_image

CASES = [
    ("nginx", "nginx:latest"), ("nginx:1.25", "nginx:1.25"), ("library/nginx:1.25", "nginx:1.25"),
    ("docker.io/library/nginx:1.25", "nginx:1.25"), ("docker.io/rancher/local-path-provisioner:v0.0.32", "rancher/local-path-provisioner:v0.0.32"),
    ("index.docker.io/library/redis:7", "redis:7"), ("registry.corp:5000/team/app:2.1", "registry.corp:5000/team/app:2.1"),
    ("registry.corp:5000/team/app", "registry.corp:5000/team/app:latest"),          # 포트의 ':' 를 태그로 오인하지 않는다
    ("ghcr.io/org/app@sha256:" + "a" * 64, "ghcr.io/org/app@sha256:" + "a" * 64),   # 다이제스트 고정은 태그를 붙이지 않는다
    ("ghcr.io/org/app:1.0@sha256:" + "a" * 64, "ghcr.io/org/app:1.0@sha256:" + "a" * 64),
    ("  NGINX:1.25 \n", "nginx:1.25"),                                                 # 저장소 이름은 소문자
    ("", ""),
]


@pytest.mark.parametrize("raw,expected", CASES)
def test_normalize_image_ref(raw, expected):
    assert normalize_image_ref(raw) == expected


def test_normalize_keeps_tag_case_but_lowercases_the_repository():
    assert normalize_image_ref("Docker.IO/Library/Nginx:V1.25-RC1") == "nginx:V1.25-RC1"


@pytest.mark.parametrize("ref,parts", [
    ("nginx:1.25", ("nginx", "1.25", "")),
    ("registry.corp:5000/team/app:2.1", ("registry.corp:5000/team/app", "2.1", "")),
    ("registry.corp:5000/team/app", ("registry.corp:5000/team/app", "latest", "")),
    ("ghcr.io/org/app@sha256:" + "a" * 64, ("ghcr.io/org/app", "", "sha256:" + "a" * 64)),
    ("ghcr.io/org/app:1.0@sha256:" + "b" * 64, ("ghcr.io/org/app", "1.0", "sha256:" + "b" * 64)),
    ("", ("", "", "")),
])
def test_split_image(ref, parts):
    assert split_image(ref) == parts
