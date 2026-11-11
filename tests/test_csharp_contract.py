"""C# Windows 에이전트가 만든 스냅샷을 Python 서버가 그대로 받아 적재·diff 하는지(크로스 언어 계약).

`windows-agent/build.sh contract` 로 artifacts/snapshot.windows*.json 을 만든 뒤에만 실행된다(없으면 건너뜀).
"""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from swinventory.server.api.models import IngestSnapshot
from swinventory.server.app import ApiSettings, create_app
from swinventory.server.repo.sql import SqlInventoryRepository

ART = Path(__file__).resolve().parents[1] / "windows-agent" / "artifacts"
V1, V2 = ART / "snapshot.windows.json", ART / "snapshot.windows.v2.json"
pytestmark = pytest.mark.skipif(not (V1.exists() and V2.exists()), reason="windows-agent/build.sh contract 로 생성")

ING, RD = {"Authorization": "Bearer ing"}, {"Authorization": "Bearer rd"}
HOST = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def client():
    repo = SqlInventoryRepository.from_url("sqlite://")
    return TestClient(create_app(repo, ApiSettings(ingest_tokens=("ing",), read_tokens=("rd",), admin_tokens=("adm",)), env={}))


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_csharp_snapshot_validates_against_the_server_model_without_dropping_anything():
    data = load(V1)
    snap = IngestSnapshot.model_validate(data).to_snapshot()
    assert snap.collected == ["os", "kernel", "software.win_registry", "software.win_hotfix", "network.interfaces", "network.ports", "hardware"]
    assert snap.errors == {}
    assert snap.hardware is not None and (snap.hardware.kind, snap.hardware.virt, snap.hardware.serial) == ("virtual", "hyperv", "1234-5678-9012")
    # 서버가 '잘못된 항목은 걸러낸다'는 정책이라, C# 이 만든 값이 하나도 걸러지지 않았는지 개수로 확인한다
    assert len(snap.interfaces) == len(data["interfaces"]) == 1 and len(snap.ports) == len(data["ports"]) == 5   # tcp 135(IPv4·IPv6)·3389·5432 + udp 123
    assert len(snap.packages) == len(data["packages"]) and len(snap.interfaces[0].addresses) == len(data["interfaces"][0]["addresses"])


def test_csharp_snapshot_is_ingested_with_windows_semantics(client):
    r = client.post("/v1/ingest", json=load(V1), headers=ING)
    assert r.status_code == 200 and r.json() == {"status": "baseline", "event_count": 0}
    d = client.get(f"/v1/hosts/{HOST}", headers=RD).json()
    assert (d["host"]["os_family"], d["host"]["os_name"], d["host"]["os_version"]) == ("windows", "Windows Server 2022 Standard", "21H2")
    assert d["host"]["hostname"] == "WIN-SRV01" and d["host"]["agent_version"] == "0.2.0"
    assert (d["kernel"]["running"], d["kernel"]["reboot_required"]) == ("10.0.20348.2461", True)       # RebootPending 키
    # 장비 정보가 C# → 서버 전 구간에서 그대로 보존된다(도메인 가입 Hyper-V 게스트)
    assert d["hardware"] == {"kind": "virtual", "virt": "hyperv", "vendor": "Microsoft Corporation", "model": "Virtual Machine",
                             "serial": "1234-5678-9012", "fqdn": "WIN-SRV01.corp.example.com", "domain": "corp.example.com"}
    names = {(p["source"], p["name"], p["version"], p["arch"]) for p in d["packages"]}
    assert ("win_registry", "한글 프로그램", "1.2", "x64") in names and ("win_registry", "Legacy Tool", "1.0", "x86") in names
    assert ("win_hotfix", "KB5034441", "", "") in names
    assert [(i["name"], i["mac"], i["addresses"]) for i in d["interfaces"]] == [("Ethernet", "00:15:5d:01:02:03", ["10.1.2.3/24", "2001:db8::9/64"])]
    ports = {(p["proto"], p["port"], p["bind"], p["exposure"], p["notable"]) for p in d["ports"]}
    assert ("tcp", 3389, "0.0.0.0", "any", True) in ports and ("tcp", 5432, "127.0.0.1", "loopback", False) in ports
    assert ("udp", 123, "0.0.0.0", "any", False) in ports


def test_csharp_second_snapshot_produces_exactly_the_expected_events(client):
    """언어가 달라도 diff 의미가 같아야 한다: 설치·버전 변경·포트 열림·IP 교체·커널 업데이트만 이벤트가 되고 나머지는 조용하다."""
    assert client.post("/v1/ingest", json=load(V1), headers=ING).json()["status"] == "baseline"
    r = client.post("/v1/ingest", json=load(V2), headers=ING)
    assert r.json() == {"status": "applied", "event_count": 6}
    events = client.get("/v1/events", params={"host": HOST}, headers=RD).json()
    got = sorted((e["event_type"], e["subject_key"], e["old_value"], e["new_value"]) for e in events)
    assert got == sorted([
        ("package_installed", "KB5036000", None, ""),
        ("package_version_changed", "Git", "2.45.0", "2.46.0"),
        ("port_opened", "tcp/8443", None, "0.0.0.0"),
        ("ip_added", "10.1.2.4", None, "10.1.2.4/24"),
        ("ip_removed", "10.1.2.3", "10.1.2.3/24", None),
        ("kernel_changed", "running", "10.0.20348.2461", "10.0.20348.2500"),
    ])


def test_csharp_snapshot_resent_unchanged_is_duplicate_and_kernel_policy_applies_to_windows(client):
    client.post("/v1/ingest", json=load(V1), headers=ING)
    assert client.post("/v1/ingest", json=load(V1), headers=ING).json()["status"] == "duplicate"
    client.put("/v1/settings/kernel-policy", json={"rules": [{"os_family": "windows", "min_kernel": "10.0.20348.2500"}]},
               headers={"Authorization": "Bearer adm"})
    rows = client.get("/v1/kernels/hosts", headers=RD).json()
    assert [(r["os_family"], r["min_kernel"], r["compliant"]) for r in rows] == [("windows", "10.0.20348.2500", False)]
    client.post("/v1/ingest", json=load(V2), headers=ING)
    assert client.get("/v1/kernels/hosts", headers=RD).json()[0]["compliant"] is True        # 2500 으로 올라오면 준수
