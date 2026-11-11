"""운영 안전장치: 헬스체크·본문 상한·CSV·태그 필터·호스트 삭제·보존 정리·동시성 충돌."""
import csv
import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from swinventory.server.repo.base import ConflictError
from swinventory.server.timeutil import normalize_ts
from tests.server.conftest import T0, dpkg, make_snapshot

ING, RD, AD = ({"Authorization": f"Bearer {t}"} for t in ("ing", "rd", "adm"))


@pytest.fixture
def client(repo, clock):
    s = ApiSettings(ingest_tokens=("ing",), read_tokens=("rd",), admin_tokens=("adm",), max_body_bytes=4000)
    return TestClient(create_app(repo, s, clock=clock))


def push(client, snap):
    r = client.post("/v1/ingest", json=snap.to_dict(), headers=ING)
    assert r.status_code == 200, r.text
    return r.json()


def rows(resp):
    assert resp.headers["content-type"].startswith("text/csv")
    return list(csv.DictReader(io.StringIO(resp.content.decode("utf-8-sig"))))


# --- 헬스체크 -------------------------------------------------------------

def test_healthz_is_unauthenticated_and_checks_db(client, repo, monkeypatch):
    assert client.get("/healthz").json() == {"status": "ok"}
    monkeypatch.setattr(repo, "ping", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    r = client.get("/healthz")
    assert r.status_code == 503 and "db down" not in r.text  # 내부 오류 내용은 노출하지 않는다


# --- 본문 크기 상한 -------------------------------------------------------

def test_body_limit_by_content_length(client):
    big = make_snapshot(packages=[dpkg(f"pkg{i}", "1") for i in range(400)]).to_dict()
    r = client.post("/v1/ingest", json=big, headers=ING)
    assert r.status_code == 413
    assert client.get("/v1/hosts", headers=RD).json() == []  # 적재되지 않았다


def test_body_limit_applies_to_chunked_uploads(client):
    def chunks():
        for _ in range(10):
            yield b"x" * 1000

    r = client.post("/v1/ingest", content=chunks(), headers={**ING, "Content-Type": "application/json"})
    assert r.status_code == 413


def test_normal_body_passes(client):
    assert push(client, make_snapshot())["status"] == "baseline"


# --- CSV ------------------------------------------------------------------

def test_kernel_hosts_csv_and_formula_injection_guard(client):
    push(client, make_snapshot(host_id="a", hostname="=cmd|'/C calc'!A0", kernel="5.15-91",
                               installed=["5.15-91", "5.15-100"], reboot=True))
    push(client, make_snapshot(host_id="b", hostname="web02", kernel="5.15-100"))
    client.put("/v1/hosts/b/tags", json={"team": "infra"}, headers=AD)
    r = client.get("/v1/kernels/hosts", params={"format": "csv"}, headers=RD)
    assert "attachment" in r.headers["content-disposition"]
    data = {x["host_id"]: x for x in rows(r)}
    assert data["a"]["hostname"].startswith("'=")  # 엑셀 수식 실행 방지
    assert data["a"]["reboot_required"] == "true" and data["a"]["latest_installed"] == "5.15-100"
    assert data["b"]["tags"] == "team=infra"


def test_software_and_events_csv(client):
    push(client, make_snapshot(packages=[dpkg("bash", "5.1")]))
    push(client, make_snapshot(at=T0 + timedelta(hours=1), packages=[dpkg("bash", "5.2")]))
    sw = rows(client.get("/v1/software/bash", params={"format": "csv"}, headers=RD))
    assert [(x["host_id"], x["version"]) for x in sw] == [("h1", "5.2")]
    ev = rows(client.get("/v1/events", params={"format": "csv"}, headers=RD))
    assert [(x["event_type"], x["old_value"], x["new_value"]) for x in ev] == [
        ("package_version_changed", "5.1", "5.2")]
    assert client.get("/v1/events", params={"format": "xml"}, headers=RD).status_code == 422


# --- 태그 필터·상태 -------------------------------------------------------

def test_tag_filter_on_hosts_and_kernel_hosts(client):
    for hid in ("a", "b", "c"):
        push(client, make_snapshot(host_id=hid, hostname=hid))
    client.put("/v1/hosts/a/tags", json={"team": "infra", "env": "prod"}, headers=AD)
    client.put("/v1/hosts/b/tags", json={"team": "infra", "env": "dev"}, headers=AD)
    ids = lambda r: sorted(h["host_id"] for h in r.json())  # noqa: E731
    assert ids(client.get("/v1/hosts", params={"tag": "team:infra"}, headers=RD)) == ["a", "b"]
    assert ids(client.get("/v1/hosts", params={"tag": ["team:infra", "env:prod"]}, headers=RD)) == ["a"]
    assert ids(client.get("/v1/kernels/hosts", params={"tag": "env:dev"}, headers=RD)) == ["b"]
    assert client.get("/v1/hosts", params={"tag": "novalue"}, headers=RD).status_code == 422


def test_host_status_ok_error_stale(client, clock):
    push(client, make_snapshot(host_id="ok"))
    push(client, make_snapshot(host_id="err", collected=["os", "kernel"], errors={"software.dpkg": "x"}))
    clock.advance(hours=100)
    push(client, make_snapshot(host_id="fresh", at=T0 + timedelta(hours=100)))
    status = {h["host_id"]: h["status"] for h in client.get("/v1/hosts", headers=RD).json()}
    assert status == {"ok": "stale", "err": "stale", "fresh": "ok"}
    clock.advance(hours=1)
    push(client, make_snapshot(host_id="err", at=T0 + timedelta(hours=101),
                               collected=["os", "kernel"], errors={"software.dpkg": "x"}))
    status = {h["host_id"]: h["status"] for h in client.get("/v1/hosts", headers=RD).json()}
    assert status["err"] == "error"
    assert client.get("/v1/hosts/err", headers=RD).json()["host"]["status"] == "error"


# --- 호스트 삭제 ----------------------------------------------------------

def test_delete_host_removes_everything_and_allows_reregistration(client):
    push(client, make_snapshot(host_id="gone", packages=[dpkg("bash", "5.1")]))
    push(client, make_snapshot(host_id="gone", at=T0 + timedelta(hours=1), packages=[dpkg("bash", "5.2")]))
    client.put("/v1/hosts/gone/tags", json={"team": "x"}, headers=AD)
    assert client.delete("/v1/hosts/gone", headers=RD).status_code == 403
    assert client.delete("/v1/hosts/gone", headers=AD).status_code == 200
    assert client.get("/v1/hosts/gone", headers=RD).status_code == 404
    assert client.get("/v1/software/bash", headers=RD).status_code == 404
    assert client.get("/v1/events", headers=RD).json() == []
    assert client.delete("/v1/hosts/gone", headers=AD).status_code == 404
    assert push(client, make_snapshot(host_id="gone", at=T0 + timedelta(hours=2)))["status"] == "baseline"


# --- 보존 정리 ------------------------------------------------------------

def test_prune_old_snapshots_and_events_keeps_current_state(repo, service, clock):
    service.ingest(make_snapshot(packages=[dpkg("bash", "5.1")]))
    for day in (1, 2, 3):
        clock.advance(days=1)
        service.ingest(make_snapshot(at=T0 + timedelta(days=day), packages=[dpkg("bash", f"5.{day + 1}")]))
    assert len(repo.list_events(limit=100)) == 3
    counts = repo.prune(snapshots_before=normalize_ts(T0 + timedelta(days=2)),
                        events_before=normalize_ts(T0 + timedelta(days=1, hours=12)))
    assert counts == {"snapshots": 2, "events": 1, "hosts": 0}
    assert len(repo.list_events(limit=100)) == 2
    detail = repo.host_detail("h1")
    assert detail["packages"][0]["version"] == "5.4"
    # 정리 후에도 중복/역순 판정과 후속 diff 가 정상 동작한다
    assert service.ingest(make_snapshot(at=T0 + timedelta(days=3), packages=[dpkg("bash", "5.4")])).status == "duplicate"
    assert service.ingest(make_snapshot(at=T0 + timedelta(days=4), packages=[dpkg("bash", "5.9")])).event_count == 1


def test_prune_snapshots_only_keeps_events_that_pointed_at_them(repo, service, clock):
    """스냅샷만 정리하면 그 스냅샷을 가리키던 이벤트는 남되 참조(FK)만 풀려야 한다."""
    service.ingest(make_snapshot(packages=[dpkg("bash", "5.1")]))
    service.ingest(make_snapshot(at=T0 + timedelta(days=1), packages=[dpkg("bash", "5.2")]))
    assert len(repo.list_events(limit=10)) == 1
    counts = repo.prune(snapshots_before=normalize_ts(T0 + timedelta(days=5)))
    assert counts["snapshots"] == 2 and counts["events"] == 0
    assert len(repo.list_events(limit=10)) == 1  # 이벤트는 보존
    assert repo.host_detail("h1")["packages"][0]["version"] == "5.2"


def test_sqlite_foreign_keys_are_enforced(repo):
    """위 테스트가 FK 위반을 실제로 잡을 수 있으려면 SQLite 에서 FK 가 켜져 있어야 한다."""
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError), repo._engine.begin() as c:
        c.execute(text("INSERT INTO host_tags(host_id, key, value) VALUES ('ghost', 'k', 'v')"))


def test_prune_hosts_not_seen_since(repo, service, clock):
    service.ingest(make_snapshot(host_id="old", packages=[dpkg("bash", "1")]))
    clock.advance(days=200)
    service.ingest(make_snapshot(host_id="new", at=T0 + timedelta(days=200)))
    counts = repo.prune(hosts_before=normalize_ts(T0 + timedelta(days=100)))
    assert counts["hosts"] == 1
    assert [h["host_id"] for h in repo.list_hosts()] == ["new"]
    assert repo.host_detail("old") is None


def test_prune_without_arguments_deletes_nothing(repo, service):
    service.ingest(make_snapshot(packages=[dpkg("bash", "1")]))
    assert repo.prune() == {"snapshots": 0, "events": 0, "hosts": 0}


# --- 동시성 충돌 ----------------------------------------------------------

def test_conflict_during_ingest_is_retried_once(repo, service, monkeypatch):
    real = repo.insert_snapshot
    calls = {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConflictError("simulated unique violation")
        return real(*a, **kw)

    monkeypatch.setattr(repo, "insert_snapshot", flaky)
    res = service.ingest(make_snapshot(packages=[dpkg("bash", "1")]))
    assert res.status == "baseline" and calls["n"] == 2
    assert len(repo.host_detail("h1")["packages"]) == 1  # 첫 시도는 롤백돼 흔적이 없다


def test_persistent_conflict_surfaces(repo, service, monkeypatch):
    monkeypatch.setattr(repo, "insert_snapshot", lambda *a, **k: (_ for _ in ()).throw(ConflictError("x")))
    with pytest.raises(ConflictError):
        service.ingest(make_snapshot())
    assert repo.list_hosts() == []  # 부분 적재 없음


# --- PostgreSQL 전용: 실제 동시 적재 ---------------------------------------

@pytest.mark.skipif(not __import__("os").environ.get("SWINV_TEST_DB_URL"),
                    reason="SWINV_TEST_DB_URL(PostgreSQL) 필요 — SQLite 인메모리는 단일 커넥션이라 경합이 없다")
def test_concurrent_identical_ingest_converges_without_errors(repo, clock):
    """에이전트 재전송이 겹쳐 같은 스냅샷이 동시에 들어와도 500 없이 baseline 1 + duplicate 로 수렴한다.

    한 번의 시도로는 스레드가 연결을 맺는 시간 차 때문에 경합이 안 날 수 있어, 연결을 미리 데우고
    호스트를 바꿔가며 여러 라운드 반복한다.
    """
    import threading

    from swinventory.server.services.ingest import IngestService

    service = IngestService(repo, clock=clock)
    threads_per_round, rounds = 8, 25
    errors: list[Exception] = []
    statuses: dict[str, list[str]] = {}

    for rnd in range(rounds):
        host_id = f"race-{rnd}"
        statuses[host_id] = []
        barrier = threading.Barrier(threads_per_round)

        def worker(host_id=host_id, barrier=barrier):
            try:
                repo.ping()  # 풀 연결을 미리 확보
                barrier.wait()
                statuses[host_id].append(service.ingest(make_snapshot(
                    host_id=host_id, packages=[dpkg("bash", "5.1"), dpkg("vim", "9")])).status)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(threads_per_round)]
        [t.start() for t in threads]
        [t.join() for t in threads]

    assert not errors, errors[:3]
    for host_id, result in statuses.items():
        assert sorted(result) == ["baseline"] + ["duplicate"] * (threads_per_round - 1), (host_id, result)
        assert len(repo.host_detail(host_id)["packages"]) == 2


# --- 화면(정적 파일)·보안 헤더 ---------------------------------------------

def test_ui_is_served_without_auth_and_api_still_wins(client):
    r = client.get("/")
    assert r.status_code == 200 and "swinventory" in r.text and "/app.js" in r.text
    assert client.get("/app.js").status_code == 200 and client.get("/style.css").status_code == 200
    assert client.get("/healthz").json() == {"status": "ok"}      # 정적 마운트가 API 를 가리지 않는다
    assert client.get("/v1/hosts").status_code == 401             # 데이터 API 는 여전히 인증 필요


def test_security_headers(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in csp
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    api = client.get("/v1/hosts", headers=RD)
    assert api.headers["cache-control"] == "no-store"            # 인벤토리 응답을 캐시하지 않는다
    assert "content-security-policy" not in client.get("/docs").headers  # Swagger 는 CDN 스크립트를 쓴다


def test_ui_source_never_uses_innerhtml(client):
    """에이전트가 보낸 호스트명·패키지명은 신뢰할 수 없다 — 화면은 textContent 로만 렌더링한다."""
    import re

    js = client.get("/app.js").text
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)       # 주석은 검사 대상이 아니다(설명에 단어가 나올 수 있음)
    js = re.sub(r"(?m)(?<![:\"'])//.*$", "", js)
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert banned not in js, banned
