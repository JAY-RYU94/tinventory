import json
from datetime import timedelta

import pytest

from swinventory.server.cli import main
from tests.server.conftest import T0, dpkg, make_snapshot

ENV = {"SWINV_READ_TOKENS": "rd", "SWINV_DB_URL": "sqlite://"}


def test_prune_requires_at_least_one_retention_option(repo, clock, capsys):
    assert main(["prune"], repo=repo, now=clock) == 2
    assert "하나 이상" in capsys.readouterr().err


def test_prune_reports_counts_and_respects_day_thresholds(repo, service, clock, capsys):
    service.ingest(make_snapshot(host_id="old", packages=[dpkg("bash", "1")]))
    for d in (1, 2, 3):
        clock.advance(days=1)
        service.ingest(make_snapshot(at=T0 + timedelta(days=d), packages=[dpkg("bash", str(d + 1))]))
    clock.advance(days=100)  # 지금은 T0 + 103일
    # 지금은 T0+103일. 스냅샷은 T0, +1일, +2일, +3일 4개, 이벤트는 +2일·+3일 2건.
    rc = main(["prune", "--snapshot-days", "100", "--event-days", "100.5"], repo=repo, now=clock)
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    # 스냅샷 기준일 T0+3일(미만만 삭제 → +3일 스냅샷은 보존), 이벤트 기준일 T0+2.5일(+2일 이벤트만 삭제)
    assert out == {"snapshots": 3, "events": 1, "hosts": 0}
    assert len(repo.list_events(limit=10)) == 1


def test_prune_hosts_by_days(repo, service, clock, capsys):
    service.ingest(make_snapshot(host_id="gone"))
    clock.advance(days=200)
    service.ingest(make_snapshot(host_id="alive", at=T0 + timedelta(days=200)))
    assert main(["prune", "--host-days", "100"], repo=repo, now=clock) == 0
    assert json.loads(capsys.readouterr().out)["hosts"] == 1
    assert [h["host_id"] for h in repo.list_hosts()] == ["alive"]


def test_negative_days_are_rejected(repo, clock):
    assert main(["prune", "--snapshot-days", "-1"], repo=repo, now=clock) == 2


def test_serve_defaults_to_loopback_and_passes_tls(monkeypatch):
    calls = []
    run = lambda app, **kw: calls.append(kw)  # noqa: E731
    assert main(["serve"], env=ENV, run=run) == 0
    assert calls[-1]["host"] == "127.0.0.1" and calls[-1]["port"] == 8000 and "ssl_certfile" not in calls[-1]
    assert main(["serve", "--host", "0.0.0.0", "--port", "9000", "--ssl-certfile", "c.pem", "--ssl-keyfile", "k.pem"],
                env=ENV, run=run) == 0
    assert calls[-1] == {"host": "0.0.0.0", "port": 9000, "ssl_certfile": "c.pem", "ssl_keyfile": "k.pem",
                         "proxy_headers": False, "log_level": "info"}


def test_serve_env_defaults_and_half_configured_tls(monkeypatch, capsys):
    calls = []
    run = lambda app, **kw: calls.append(kw)  # noqa: E731
    assert main(["serve"], env={**ENV, "SWINV_HOST": "0.0.0.0", "SWINV_PORT": "8443"}, run=run) == 0
    assert (calls[-1]["host"], calls[-1]["port"]) == ("0.0.0.0", 8443)
    assert main(["serve", "--ssl-certfile", "c.pem"], env=ENV, run=run) == 2   # 키 없이 인증서만
    assert len(calls) == 1


def test_serve_refuses_to_start_without_tokens(capsys):
    assert main(["serve"], env={"SWINV_DB_URL": "sqlite://"}, run=lambda *a, **k: None) == 2
    assert "토큰" in capsys.readouterr().err
