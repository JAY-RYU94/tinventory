import json

import pytest

from swinventory.agent.cli import main
from swinventory.agent.collectors.debian import DPKG_KERNEL_CMD, DPKG_LIST_CMD
from swinventory.agent.config import AgentConfig, ConfigError
from swinventory.agent.runtime.command import CommandResult
from swinventory.agent.transport.http import HttpPoster, HttpResponse
from swinventory.agent.collectors.linux_network import IP_ADDR_CMD
from tests.fakes import IP_JSON_SIMPLE, PROC_NET_FILES, FakeCommandRunner, FakeFileReader


def debian_env():
    fs = FakeFileReader({
        "/etc/os-release": 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04"\n',
        "/etc/machine-id": "mid-1\n", **PROC_NET_FILES,
    })
    runner = FakeCommandRunner({
        ("uname", "-r"): CommandResult(0, "5.15.0-91-generic\n"),
        DPKG_LIST_CMD: CommandResult(0, "bash\t5.1\tamd64\tii \n"),
        DPKG_KERNEL_CMD: CommandResult(0, "linux-image-5.15.0-91-generic\t5.15.0-91.101\tii \n"),
        IP_ADDR_CMD: CommandResult(0, IP_JSON_SIMPLE),
    })
    return dict(fs=fs, runner=runner, system="Linux")


class RecordingPoster(HttpPoster):
    def __init__(self, status=200):
        self.status, self.requests = status, []

    def post(self, url, body, headers, timeout):
        self.requests.append((url, json.loads(body), headers))
        return HttpResponse(self.status, b"{}")


def write_config(tmp_path, **kw):
    p = tmp_path / "agent.json"
    p.write_text(json.dumps(kw))
    return str(p)


def test_print_outputs_snapshot_json_without_sending(capsys):
    assert main(["print"], **debian_env()) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["host_id"] == "mid-1"
    assert data["collected"] == ["os", "kernel", "software.dpkg", "network.interfaces", "network.ports", "hardware"]
    assert data["interfaces"][0]["addresses"] == ["10.0.0.5/24"] and data["ports"] == [{"proto": "tcp", "port": 22, "bind": "0.0.0.0"}]
    assert data["packages"][0]["name"] == "bash"


def test_collect_to_json_dir(tmp_path):
    out = tmp_path / "out"
    assert main(["collect", "--json-dir", str(out)], **debian_env()) == 0
    files = list(out.iterdir())
    assert len(files) == 1 and json.loads(files[0].read_text())["hostname"]


def test_collect_over_https_with_token_file_and_spool(tmp_path):
    tok = tmp_path / "token"
    tok.write_text("tok-123\n")
    cfg = write_config(tmp_path, server_url="https://inv.example.com", token_file=str(tok),
                       spool_path=str(tmp_path / "spool.db"))
    poster = RecordingPoster()
    assert main(["collect", "--config", cfg], poster=poster, **debian_env()) == 0
    url, body, headers = poster.requests[0]
    assert url == "https://inv.example.com/v1/ingest"
    assert headers["Authorization"] == "Bearer tok-123"
    assert body["host_id"] == "mid-1"


def test_server_down_spools_and_exits_zero_then_flush_delivers(tmp_path):
    cfg = write_config(tmp_path, server_url="https://inv.example.com", token="t",
                       spool_path=str(tmp_path / "spool.db"))
    assert main(["collect", "--config", cfg], poster=RecordingPoster(503), **debian_env()) == 0
    good = RecordingPoster(200)
    assert main(["flush", "--config", cfg], poster=good, **debian_env()) == 0
    assert len(good.requests) == 1


def test_flush_exit_code_when_still_failing(tmp_path):
    cfg = write_config(tmp_path, server_url="https://inv.example.com", token="t",
                       spool_path=str(tmp_path / "spool.db"))
    main(["collect", "--config", cfg], poster=RecordingPoster(503), **debian_env())
    assert main(["flush", "--config", cfg], poster=RecordingPoster(503), **debian_env()) == 5


def test_permanent_rejection_exits_4(tmp_path):
    cfg = write_config(tmp_path, server_url="https://inv.example.com", token="t",
                       spool_path=str(tmp_path / "spool.db"))
    assert main(["collect", "--config", cfg], poster=RecordingPoster(422), **debian_env()) == 4


def test_config_errors_exit_2(tmp_path, capsys):
    assert main(["collect"], env={}, **debian_env()) == 2                      # 목적지 없음
    cfg = write_config(tmp_path, server_url="http://inv.example.com", token="t")
    assert main(["collect", "--config", cfg], **debian_env()) == 2             # 평문 http 거부
    cfg = write_config(tmp_path, server_url="https://inv.example.com")
    assert main(["collect", "--config", cfg], env={}, **debian_env()) == 2     # 토큰 없음


def test_unsupported_platform_exits_3():
    env = debian_env()
    env["fs"] = FakeFileReader({"/etc/os-release": "ID=arch\n"})
    assert main(["print"], **env) == 3


def test_env_overrides_config(tmp_path):
    cfg = AgentConfig.load(None, {"SWINV_SERVER_URL": "https://a", "SWINV_TOKEN": "t",
                                  "SWINV_SPOOL_PATH": "/tmp/x.db"}, {})
    assert (cfg.server_url, cfg.token, cfg.spool_path) == ("https://a", "t", "/tmp/x.db")


def test_allow_insecure_http_flag_for_dev():
    cfg = AgentConfig.load(None, {}, {"server_url": "http://127.0.0.1:8000", "token": "t",
                                      "allow_insecure_http": True})
    cfg.validate()


def test_validate_rejects_missing_destination():
    with pytest.raises(ConfigError):
        AgentConfig.load(None, {}, {}).validate()


def test_run_loop_sleeps_between_iterations(tmp_path):
    sleeps = []
    out = tmp_path / "out"
    rc = main(["run", "--interval", "600", "--max-runs", "3", "--json-dir", str(out)],
              sleep=sleeps.append, **debian_env())
    assert rc == 0 and sleeps == [600, 600] and len(list(out.iterdir())) == 3


def test_run_loop_survives_a_failing_iteration(tmp_path):
    env = debian_env()
    env["fs"].files.pop("/etc/machine-id")  # host_id 실패 → 이번 회차만 실패
    sleeps = []
    rc = main(["run", "--interval", "5", "--max-runs", "2", "--json-dir", str(tmp_path / "o")],
              sleep=sleeps.append, **env)
    assert rc == 1 and sleeps == [5]
