"""PostgreSQL 텍스트 컬럼은 NUL(\\x00)을 저장하지 못한다(SQLite 는 통과). 어느 경로로 들어와도 500 이 되면 안 된다."""
import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from tests.server.conftest import dpkg, make_snapshot

ING, RD, AD = ({"Authorization": f"Bearer {t}"} for t in ("ing", "rd", "adm"))


@pytest.fixture
def client(repo, clock):
    return TestClient(create_app(repo, ApiSettings(ingest_tokens=("ing",), read_tokens=("rd",), admin_tokens=("adm",)),
                                 clock=clock, env={}))


def test_ingest_strips_control_characters_instead_of_failing(client, repo):
    """거부하면(422) 패키지명 하나 때문에 그 호스트의 스냅샷 전체가 영영 막힌다 — 제거하고 받는다."""
    snap = make_snapshot(hostname="web\x00evil\x1b[31m", packages=[dpkg("pk\x00g", "1.\x002"), dpkg("good", "1")],
                         collected=["os", "kernel", "software.dpkg"], errors={"software.rpm\x00": "e\x00rr\x07or"})
    r = client.post("/v1/ingest", json=snap.to_dict(), headers=ING)
    assert r.status_code == 200, r.text
    detail = repo.host_detail("h1")
    assert detail["host"]["hostname"] == "webevil[31m"
    assert sorted((p["name"], p["version"]) for p in detail["packages"]) == [("good", "1"), ("pkg", "1.2")]
    assert detail["host"]["last_errors"] == {"software.rpm": "error"}


def test_value_that_is_only_control_characters_fails_validation_not_stored_empty(client, repo):
    for field, value in (("hostname", "\x00"), ("host_id", "\x00\x01"), ):
        body = make_snapshot().to_dict()
        body[field] = value
        assert client.post("/v1/ingest", json=body, headers=ING).status_code == 422, field
    body = make_snapshot(packages=[dpkg("\x00", "1")]).to_dict()
    assert client.post("/v1/ingest", json=body, headers=ING).status_code == 422
    assert repo.list_hosts() == []


def test_ingest_keeps_tabs_and_newlines_in_error_text(client, repo):
    snap = make_snapshot(errors={"software.dpkg": "line1\nline2\tcol"}, collected=["os", "kernel"])
    assert client.post("/v1/ingest", json=snap.to_dict(), headers=ING).status_code == 200
    assert repo.host_detail("h1")["host"]["last_errors"]["software.dpkg"] == "line1\nline2\tcol"


def test_tag_values_with_control_characters_are_rejected(client):
    client.post("/v1/ingest", json=make_snapshot().to_dict(), headers=ING)
    for tags in ({"team": "in\x00fra"}, {"te\x00am": "x"}, {"team": "a\x1bb"}):
        assert client.put("/v1/hosts/h1/tags", json=tags, headers=AD).status_code == 422
    assert client.put("/v1/hosts/h1/tags", json={"team": "infra"}, headers=AD).status_code == 200


@pytest.mark.parametrize("path", [
    "/v1/software?q=a%00b", "/v1/software/pk%00g", "/v1/hosts/h%001", "/v1/events?host=h%001", "/v1/hosts?tag=k:v%00",
    "/v1/kernels/hosts?running=5.%00", "/v1/software?q=a%2500b".replace("%2500", "%00"),
])
def test_nul_in_url_is_a_400_not_a_500(client, path):
    assert client.get(path, headers=RD).status_code == 400


def test_percent_encoded_literal_percent_is_not_confused_with_nul(client):
    client.post("/v1/ingest", json=make_snapshot(packages=[dpkg("bash", "1")]).to_dict(), headers=ING)
    assert client.get("/v1/software?q=bash", headers=RD).status_code == 200
    assert client.get("/v1/software?q=100%25", headers=RD).status_code == 200      # '%25' = 리터럴 '%'


def test_ai_settings_reject_control_characters(client):
    body = {"base_url": "https://llm.corp.example/v1", "model": "gpt\x00oss", "trust_zone": "internal"}
    assert client.put("/v1/settings/ai", json=body, headers=AD).status_code == 422
    assert client.put("/v1/settings/ai", json={**body, "model": "gpt-oss", "api_key": "sk-\x00x"}, headers=AD).status_code == 422
    assert client.put("/v1/settings/ai", json={**body, "model": "gpt-oss"}, headers=AD).status_code == 200
