"""에이전트(다른 언어 구현 포함)와 서버 사이의 계약 동결.

contracts/snapshot.v1.schema.json 은 서버 수신 모델에서 생성한다. 모델을 바꾸면 이 테스트가 깨지고,
`python -m swinventory.server.contract --write` 로 갱신하면서 에이전트 구현도 함께 맞추게 된다.
"""
import json
from pathlib import Path

from swinventory.server.contract import render_schema

SCHEMA = Path(__file__).resolve().parents[2] / "contracts" / "snapshot.v1.schema.json"


def test_checked_in_schema_matches_server_model():
    assert SCHEMA.read_text(encoding="utf-8") == render_schema()


def test_golden_snapshot_is_accepted_by_server_model():
    from swinventory.server.api.models import IngestSnapshot

    golden = json.loads((SCHEMA.parent / "golden" / "snapshot.debian.json").read_text(encoding="utf-8"))
    IngestSnapshot.model_validate(golden)


def test_legacy_v1_snapshot_without_network_sections_is_still_accepted():
    """네트워크 수집이 없던 에이전트(0.1.x)가 먼저 배포돼 있어도 서버가 받아야 한다 — 서버를 먼저 올리고 에이전트를 점진 교체한다."""
    from swinventory.server.api.models import IngestSnapshot

    legacy = json.loads((SCHEMA.parent / "golden" / "snapshot.debian.v1-legacy.json").read_text(encoding="utf-8"))
    assert "interfaces" not in legacy and "ports" not in legacy
    snap = IngestSnapshot.model_validate(legacy).to_snapshot()
    assert snap.interfaces == [] and snap.ports == [] and "network.ports" not in snap.collected


def test_golden_network_sections_roundtrip_through_the_server_model():
    from swinventory.server.api.models import IngestSnapshot

    golden = json.loads((SCHEMA.parent / "golden" / "snapshot.debian.json").read_text(encoding="utf-8"))
    snap = IngestSnapshot.model_validate(golden).to_snapshot()
    assert [(i.name, i.mac, i.addresses) for i in snap.interfaces] == [("eth0", "02:42:ac:11:00:02", ("10.0.0.5/24", "2001:db8::5/64"))]
    assert [(p.proto, p.port, p.bind) for p in snap.ports][:2] == [("tcp", 22, "0.0.0.0"), ("tcp", 22, "::")]


def test_golden_hardware_roundtrips_through_the_server_model():
    from swinventory.server.api.models import IngestSnapshot

    golden = json.loads((SCHEMA.parent / "golden" / "snapshot.debian.json").read_text(encoding="utf-8"))
    snap = IngestSnapshot.model_validate(golden).to_snapshot()
    assert snap.hardware is not None
    assert (snap.hardware.kind, snap.hardware.virt, snap.hardware.serial, snap.hardware.domain) == \
        ("virtual", "vmware", "VMware-56 4d 5c 7e", "corp.example.com")
    assert "hardware" in snap.collected


def test_legacy_snapshot_without_hardware_is_still_accepted():
    from swinventory.server.api.models import IngestSnapshot

    legacy = json.loads((SCHEMA.parent / "golden" / "snapshot.debian.v1-legacy.json").read_text(encoding="utf-8"))
    assert "hardware" not in legacy
    assert IngestSnapshot.model_validate(legacy).to_snapshot().hardware is None


def test_golden_containers_and_k8s_roundtrip_through_the_server_model():
    from swinventory.server.api.models import IngestSnapshot

    golden = json.loads((SCHEMA.parent / "golden" / "snapshot.debian.containers.json").read_text(encoding="utf-8"))   # Windows 에이전트는 컨테이너를 수집하지 않아 공유 골든과 분리
    snap = IngestSnapshot.model_validate(golden).to_snapshot()
    assert [(c.name, c.image, c.pod, c.namespace) for c in snap.containers] == [("local-path-provisioner", "rancher/local-path-provisioner:v0.0.32", "local-path-provisioner-578895bd58-zvx2j", "kube-system")]
    assert snap.k8s is not None and snap.k8s.version == "v1.34.1+k3s1" and snap.k8s.cluster_id.startswith("91c99b82")
    assert "containers" in snap.collected


def test_snapshots_without_containers_are_still_accepted():
    from swinventory.server.api.models import IngestSnapshot

    legacy = json.loads((SCHEMA.parent / "golden" / "snapshot.debian.v1-legacy.json").read_text(encoding="utf-8"))
    snap = IngestSnapshot.model_validate(legacy).to_snapshot()
    assert snap.containers == [] and snap.k8s is None
