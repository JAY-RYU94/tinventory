"""컨테이너 헬퍼가 남긴 파일(진짜 k3s·Docker 에서 헬퍼를 돌려 얻은 출력)을 비특권 에이전트가 해석한다."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from swinventory.agent.collectors.containers import HELPER_DIR, HelperContainers
from swinventory.common.models import ContainerRecord, K8sNodeInfo
from tests.fakes import FakeFileReader

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "containers"
K3S, DOCKER = FIX / "k3s", FIX / "docker"


def load(directory: Path) -> dict[str, str]:
    return {f"{HELPER_DIR}/{p.name}": p.read_text(encoding="utf-8") for p in directory.iterdir() if p.is_file()}


def at(files: dict[str, str], *, age=timedelta(minutes=5)):
    """helper 의 collected_at 으로부터 age 뒤를 '지금'으로 하는 시계."""
    ts = int(files[f"{HELPER_DIR}/collected_at.txt"].strip())
    return lambda: datetime.fromtimestamp(ts, timezone.utc) + age


def collect(files, **kw):
    return HelperContainers(FakeFileReader(files), at(files, **kw)).collect()


# --- 진짜 k3s(containerd + crictl) ---
def test_real_k3s_helper_output_is_parsed_into_containers_and_node_identity():
    files = load(K3S)
    res = collect(files)
    assert res.ok and res.name == "containers"
    containers, k8s = res.value
    by_name = {c.name: c for c in containers}
    assert set(by_name) == {"local-path-provisioner", "coredns"}
    lpp = by_name["local-path-provisioner"]
    assert (lpp.runtime, lpp.state, lpp.pod.startswith("local-path-provisioner-"), lpp.namespace) == ("containerd", "running", True, "kube-system")
    assert lpp.image == "rancher/local-path-provisioner:v0.0.32"            # userSpecifiedImage 를 정규화(docker.io/ 제거)
    assert lpp.image_id == "sha256:0594e75cdd5df85c117280c0671da048b04e853ac30c7e078fe5ad981dfa92cd"
    assert lpp.image_digest == "sha256:9289da488b07912cb4128eb96928a331a5f3e60c28c5cfc5790f354a4ad0cc68"
    assert len(lpp.container_id) == 12 and lpp.created_at.startswith("2026-")
    assert k8s == K8sNodeInfo(cluster_id="91c99b828fa997d253056b4d6f74b5d9f748f9c183c7a963d6f377adfdb66d68",
                              api_server="https://127.0.0.1:6443", version="v1.34.1+k3s1", runtime="containerd")


def test_labels_annotations_and_env_are_never_kept():
    """라벨·어노테이션에는 비밀이 들어 있을 수 있다 — 화이트리스트한 필드(파드 이름·네임스페이스)만 꺼낸다."""
    containers, _ = collect(load(K3S)).value
    blob = json.dumps([c.to_dict() for c in containers])
    for leak in ("io.kubernetes.container.hash", "terminationMessagePath", "annotations", "labels"):
        assert leak not in blob
    assert not any(hasattr(c, "labels") or hasattr(c, "env") for c in containers)


# --- 진짜 Docker ---
def test_real_docker_helper_output():
    files = load(DOCKER)
    containers, k8s = collect(files).value
    by_name = {c.name: c for c in containers}
    assert set(by_name) == {"swinv-fix-a", "swinv-fix-b", "swinv-fix-c"}
    a = by_name["swinv-fix-a"]
    assert (a.runtime, a.state, a.image, a.pod, a.namespace) == ("docker", "running", "alpine:3.20", "", "")
    assert a.image_digest == "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc" and a.image_id.startswith("sha256:")
    assert (by_name["swinv-fix-b"].state, by_name["swinv-fix-c"].image) == ("exited", "hello-world:latest")
    assert a.created_at == "2026-11-06T10:34:18+00:00"
    assert k8s is None                                       # 쿠버네티스 흔적이 없는 일반 서버


def test_docker_secrets_in_labels_and_env_are_not_in_helper_output_or_result():
    blob = json.dumps([c.to_dict() for c in collect(load(DOCKER)).value[0]])
    assert "hunter2" not in blob and "sekrit" not in blob


# --- 적용 대상 아님 / 오래됨 / 부분 ---
def test_helper_not_installed_means_not_applicable_not_an_error():
    res = HelperContainers(FakeFileReader({}), lambda: datetime.now(timezone.utc)).collect()
    assert res.ok and res.value is None                      # 오케스트레이터는 이것을 collected 에 넣지 않는다


def test_stale_helper_result_is_an_error_not_current_truth():
    """타이머가 멈췄다면 마지막 값을 '현재 상태'로 서버에 보내 가짜 변경 없음을 만들면 안 된다."""
    res = collect(load(K3S), age=timedelta(hours=4))
    assert not res.ok and "오래" in res.error


def test_fresh_helper_without_any_runtime_files_means_no_containers():
    files = {f"{HELPER_DIR}/collected_at.txt": "1793961237\n"}
    res = HelperContainers(FakeFileReader(files), lambda: datetime.fromtimestamp(1793961300, timezone.utc)).collect()
    assert res.ok and res.value == ([], None)


def test_corrupt_helper_file_fails_the_collector_without_partial_data():
    files = load(K3S); files[f"{HELPER_DIR}/crictl_ps.json"] = "{not json"
    res = collect(files)
    assert not res.ok and res.value is None


def test_garbled_collected_at_is_an_error():
    files = load(K3S); files[f"{HELPER_DIR}/collected_at.txt"] = "yesterday\n"
    assert not HelperContainers(FakeFileReader(files), lambda: datetime.now(timezone.utc)).collect().ok


# --- 형식 변형(옛 containerd·cri-o) ---
def _cri(image, **extra):
    return json.dumps({"containers": [{"id": "a" * 64, "metadata": {"name": "app"}, "image": image, "imageRef": "sha256:" + "c" * 64, "state": "CONTAINER_EXITED",
                                       "createdAt": "1700000000000000000", "labels": {"io.kubernetes.pod.name": "p", "io.kubernetes.pod.namespace": "ns"}, **extra}]})


def test_old_containerd_puts_the_readable_ref_in_image_image():
    files = {f"{HELPER_DIR}/collected_at.txt": "1700000100\n", f"{HELPER_DIR}/crictl_ps.json": _cri({"image": "docker.io/library/nginx:1.25"}),
             f"{HELPER_DIR}/crictl_version.txt": "RuntimeName:  cri-o\nRuntimeVersion:  1.29.1\n"}
    (c,), _ = HelperContainers(FakeFileReader(files), lambda: datetime.fromtimestamp(1700000200, timezone.utc)).collect().value
    assert (c.image, c.runtime, c.state, c.pod, c.namespace, c.created_at) == ("nginx:1.25", "cri-o", "exited", "p", "ns", "2023-11-14T22:13:20+00:00")


def test_sha_only_image_is_resolved_through_the_image_list():
    imgs = json.dumps({"images": [{"id": "sha256:" + "c" * 64, "repoTags": ["docker.io/team/app:2.0"], "repoDigests": ["docker.io/team/app@sha256:" + "d" * 64]}]})
    files = {f"{HELPER_DIR}/collected_at.txt": "1700000100\n", f"{HELPER_DIR}/crictl_ps.json": _cri({"image": "sha256:" + "c" * 64}),
             f"{HELPER_DIR}/crictl_images.json": imgs}
    (c,), _ = HelperContainers(FakeFileReader(files), lambda: datetime.fromtimestamp(1700000200, timezone.utc)).collect().value
    assert (c.image, c.image_digest) == ("team/app:2.0", "sha256:" + "d" * 64)


def test_unresolvable_sha_image_is_kept_as_the_id_not_dropped():
    files = {f"{HELPER_DIR}/collected_at.txt": "1700000100\n", f"{HELPER_DIR}/crictl_ps.json": _cri({"image": "sha256:" + "c" * 64})}
    (c,), _ = HelperContainers(FakeFileReader(files), lambda: datetime.fromtimestamp(1700000200, timezone.utc)).collect().value
    assert c.image == "sha256:" + "c" * 64 and c.state == "exited"


def test_node_with_only_a_version_file_is_still_a_k8s_node():
    files = {f"{HELPER_DIR}/collected_at.txt": "1700000100\n", f"{HELPER_DIR}/k8s_version.txt": "Kubernetes v1.29.3\n"}
    _, k8s = HelperContainers(FakeFileReader(files), lambda: datetime.fromtimestamp(1700000200, timezone.utc)).collect().value
    assert k8s == K8sNodeInfo(cluster_id="", api_server="", version="v1.29.3", runtime="")


def test_api_server_with_credentials_is_dropped():
    files = load(K3S); files[f"{HELPER_DIR}/k8s_server.txt"] = "https://admin:pw@10.0.0.1:6443\n"
    _, k8s = collect(files).value
    assert k8s.api_server == ""


def test_huge_container_list_is_capped():
    items = [{"id": f"{i:064x}", "metadata": {"name": f"c{i}"}, "image": {"image": "x:1"}, "state": "CONTAINER_RUNNING", "createdAt": "1700000000000000000"} for i in range(6000)]
    files = {f"{HELPER_DIR}/collected_at.txt": "1700000100\n", f"{HELPER_DIR}/crictl_ps.json": json.dumps({"containers": items})}
    (containers, _) = HelperContainers(FakeFileReader(files), lambda: datetime.fromtimestamp(1700000200, timezone.utc)).collect().value
    assert len(containers) == 5000


def test_readable_image_comes_from_user_specified_image_even_without_the_image_list():
    """이미지 목록 파일이 없거나(crictl images 실패) 목록에 없을 때도 읽을 수 있는 이름이 나와야 한다."""
    files = load(K3S)
    del files[f"{HELPER_DIR}/crictl_images.json"]
    containers, _ = collect(files).value
    assert {c.image for c in containers} == {"rancher/local-path-provisioner:v0.0.32", c_image(containers, "coredns")}
    assert all(not c.image.startswith("sha256:") for c in containers)
    assert all(c.image_digest == "" for c in containers)                      # 목록이 없으면 다이제스트는 모른다 — 지어내지 않는다


def c_image(containers, name):
    return next(c.image for c in containers if c.name == name)
