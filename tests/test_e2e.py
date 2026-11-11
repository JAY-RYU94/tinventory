"""층간 계약: 에이전트가 만든 스냅샷을 에이전트 전송 계층으로 보내 실제 서버가 적재하는지."""
from urllib.parse import urlparse

from fastapi.testclient import TestClient

from swinventory.agent.cli import main
from swinventory.agent.transport.http import HttpPoster, HttpResponse
from swinventory.server.app import ApiSettings, create_app
from swinventory.server.repo.sql import SqlInventoryRepository
from tests.agent.test_cli import debian_env, write_config


class AsgiPoster(HttpPoster):
    def __init__(self, client):
        self.client = client

    def post(self, url, body, headers, timeout):
        r = self.client.post(urlparse(url).path, content=body, headers=headers)
        return HttpResponse(r.status_code, r.content)


def test_agent_to_server_roundtrip(tmp_path):
    repo = SqlInventoryRepository.from_url("sqlite://")
    client = TestClient(create_app(repo, ApiSettings(ingest_tokens=("tok",), read_tokens=("rd",))))
    cfg = write_config(tmp_path, server_url="https://inv.example.com", token="tok",
                       spool_path=str(tmp_path / "spool.db"))
    assert main(["collect", "--config", cfg], poster=AsgiPoster(client), **debian_env()) == 0

    detail = client.get("/v1/hosts/mid-1", headers={"Authorization": "Bearer rd"}).json()
    assert detail["kernel"]["running"] == "5.15.0-91-generic"
    assert [p["name"] for p in detail["packages"]] == ["bash"]
    assert detail["host"]["os_name"] == "Ubuntu 22.04"


def test_wrong_token_is_spooled_not_dropped(tmp_path):
    repo = SqlInventoryRepository.from_url("sqlite://")
    client = TestClient(create_app(repo, ApiSettings(ingest_tokens=("right",))))
    spool = tmp_path / "spool.db"
    cfg = write_config(tmp_path, server_url="https://inv.example.com", token="wrong", spool_path=str(spool))
    assert main(["collect", "--config", cfg], poster=AsgiPoster(client), **debian_env()) == 0
    assert repo.list_hosts() == []  # 서버에는 안 들어갔지만
    from swinventory.agent.transport.spool import SqliteSpool
    assert SqliteSpool(spool, max_items=10).count() == 1  # 스풀에 보관돼 토큰 교정 후 재전송된다
