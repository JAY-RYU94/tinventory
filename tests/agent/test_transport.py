import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from swinventory.agent.transport.base import PermanentTransportError, SendOutcome, TransportError
from swinventory.agent.transport.http import HttpPoster, HttpResponse, HttpsTransport, UrllibPoster
from swinventory.agent.transport.jsonfile import JsonFileTransport
from swinventory.agent.transport.spool import SqliteSpool
from swinventory.agent.transport.spooling import SpoolingTransport
from swinventory.agent.transport.base import BaseTransport
from swinventory.common.models import Snapshot


def snap(n: int) -> Snapshot:
    return Snapshot(host_id="h", hostname="web01", collected_at=f"2026-11-05T00:00:{n:02d}+00:00",
                    agent_version="0.1.0", collected=["os"])


class FakePoster(HttpPoster):
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def post(self, url, body, headers, timeout):
        self.requests.append((url, body, headers, timeout))
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def ok():
    return HttpResponse(200, b'{"status":"applied"}')


# --- HttpsTransport -------------------------------------------------------

def test_https_posts_json_with_bearer_token():
    poster = FakePoster(ok())
    t = HttpsTransport("https://inv.example.com:8443/", "secret-token", poster, timeout=7)
    assert t.send(snap(1)) is SendOutcome.SENT
    url, body, headers, timeout = poster.requests[0]
    assert url == "https://inv.example.com:8443/v1/ingest"
    assert headers["Authorization"] == "Bearer secret-token"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body) == snap(1).to_dict() and timeout == 7


@pytest.mark.parametrize("status", [401, 403, 404, 408, 429, 500, 502, 503])
def test_retryable_statuses(status):
    t = HttpsTransport("https://x", "tok", FakePoster(HttpResponse(status, b"nope")))
    with pytest.raises(TransportError) as ei:
        t.send(snap(1))
    assert not isinstance(ei.value, PermanentTransportError)


@pytest.mark.parametrize("status", [400, 413, 422])
def test_permanent_statuses(status):
    t = HttpsTransport("https://x", "tok", FakePoster(HttpResponse(status, b"bad")))
    with pytest.raises(PermanentTransportError):
        t.send(snap(1))


def test_network_error_is_retryable_and_never_leaks_token():
    t = HttpsTransport("https://x", "super-secret", FakePoster(ConnectionRefusedError("refused")))
    with pytest.raises(TransportError) as ei:
        t.send(snap(1))
    assert "super-secret" not in str(ei.value) and not isinstance(ei.value, PermanentTransportError)


def test_error_message_truncates_body():
    t = HttpsTransport("https://x", "tok", FakePoster(HttpResponse(500, b"x" * 5000)))
    with pytest.raises(TransportError) as ei:
        t.send(snap(1))
    assert len(str(ei.value)) < 400


# --- UrllibPoster(실제 로컬 HTTP 서버) -------------------------------------

class _Handler(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Handler.seen.append((self.path, self.headers.get("Authorization"), body))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()
        elif self.path == "/bad":
            self.send_response(422)
            self.end_headers()
            self.wfile.write(b"invalid")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture
def local_server():
    _Handler.seen = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


def test_urllib_poster_roundtrip_and_status_passthrough(local_server):
    p = UrllibPoster()
    r = p.post(local_server + "/v1/ingest", b'{"a":1}', {"Authorization": "Bearer t"}, 5)
    assert (r.status, r.body) == (200, b"ok")
    assert _Handler.seen[0] == ("/v1/ingest", "Bearer t", b'{"a":1}')
    assert p.post(local_server + "/bad", b"{}", {}, 5).status == 422  # 4xx 도 예외가 아니라 응답


def test_urllib_poster_does_not_follow_redirects(local_server):
    r = UrllibPoster().post(local_server + "/redirect", b"{}", {"Authorization": "Bearer t"}, 5)
    assert r.status == 302
    assert len(_Handler.seen) == 1  # Location 으로 토큰을 들고 따라가지 않았다


def test_urllib_poster_unreachable_raises_oserror():
    with pytest.raises(OSError):
        UrllibPoster().post("http://127.0.0.1:1/x", b"{}", {}, 2)


# --- JsonFileTransport ----------------------------------------------------

def test_json_file_transport_writes_atomically(tmp_path):
    t = JsonFileTransport(tmp_path / "out")
    assert t.send(snap(1)) is SendOutcome.SENT
    t.send(snap(2))
    files = sorted(p.name for p in (tmp_path / "out").iterdir())
    assert len(files) == 2 and all(f.endswith(".json") for f in files)  # .tmp 잔여물 없음
    first = json.loads((tmp_path / "out" / files[0]).read_text())
    assert Snapshot.from_dict(first) == snap(1)


# --- SqliteSpool ----------------------------------------------------------

def test_spool_oldest_first_and_delete(tmp_path):
    sp = SqliteSpool(tmp_path / "s.db", max_items=10)
    for n in (3, 1, 2):
        sp.put(snap(n))
    assert [i.snapshot.collected_at[-8:-6] for i in sp.oldest(10)] == ["01", "02", "03"]
    first = sp.oldest(1)[0]
    sp.delete(first.id)
    assert sp.count() == 2


def test_spool_cap_drops_oldest(tmp_path):
    sp = SqliteSpool(tmp_path / "s.db", max_items=3)
    for n in range(1, 6):
        sp.put(snap(n))
    assert sp.count() == 3
    assert [i.snapshot.collected_at for i in sp.oldest(10)][0].endswith("03+00:00")


def test_spool_reject_moves_to_dead_letter_and_corrupt_is_skipped(tmp_path):
    sp = SqliteSpool(tmp_path / "s.db", max_items=10)
    sp.put(snap(1))
    sp.put(snap(2))
    sp.reject(sp.oldest(1)[0].id, "422")
    assert sp.count() == 1 and sp.rejected_count() == 1
    import sqlite3
    with sqlite3.connect(tmp_path / "s.db") as c:
        c.execute("INSERT INTO spool(collected_at, payload, created_at) VALUES('0','{broken','0')")
    assert [i.snapshot.collected_at[-8:-6] for i in sp.oldest(10)] == ["02"]  # 깨진 항목은 격리
    assert sp.rejected_count() == 2


def test_spool_file_is_private(tmp_path):
    SqliteSpool(tmp_path / "d" / "s.db", max_items=3).put(snap(1))
    assert (tmp_path / "d" / "s.db").stat().st_mode & 0o077 == 0


# --- SpoolingTransport ----------------------------------------------------

class ScriptedTransport(BaseTransport):
    """호출마다 steps 의 다음 결과(None=성공, 예외 인스턴스=실패)를 적용하고 성공한 것만 sent 에 기록."""

    def __init__(self, *steps):
        self.steps, self.sent, self.calls = list(steps), [], 0

    def send(self, snapshot):
        self.calls += 1
        step = self.steps.pop(0) if self.steps else None
        if step is not None:
            raise step
        self.sent.append(snapshot.collected_at[-8:-6])
        return SendOutcome.SENT


def make(tmp_path, *steps, max_items=10):
    inner = ScriptedTransport(*steps)
    sp = SqliteSpool(tmp_path / "s.db", max_items=max_items)
    return SpoolingTransport(inner, sp), inner, sp


def test_failure_spools_and_next_send_flushes_oldest_first(tmp_path):
    t, inner, sp = make(tmp_path, TransportError("down"), TransportError("down"))
    assert t.send(snap(1)) is SendOutcome.SPOOLED
    assert t.send(snap(2)) is SendOutcome.SPOOLED
    assert sp.count() == 2
    assert t.send(snap(3)) is SendOutcome.SENT
    assert inner.sent == ["01", "02", "03"] and sp.count() == 0


def test_flush_stops_at_first_retryable_failure_and_keeps_order(tmp_path):
    t, inner, sp = make(tmp_path, TransportError("d"), TransportError("d"), None, TransportError("d"))
    t.send(snap(1))
    t.send(snap(2))  # 둘 다 스풀됨
    # 다음 회차: 01 은 성공, 02 에서 실패 → 03 은 02 뒤에 스풀
    assert t.send(snap(3)) is SendOutcome.SPOOLED
    assert inner.sent == ["01"]
    assert [i.snapshot.collected_at[-8:-6] for i in sp.oldest(10)] == ["02", "03"]


def test_permanent_error_during_flush_is_dead_lettered_and_flush_continues(tmp_path):
    t, inner, sp = make(tmp_path, TransportError("d"), TransportError("d"),
                        PermanentTransportError("422"))
    t.send(snap(1))
    t.send(snap(2))
    assert t.send(snap(3)) is SendOutcome.SENT
    assert inner.sent == ["02", "03"] and sp.rejected_count() == 1 and sp.count() == 0


def test_permanent_error_on_current_snapshot_is_raised_not_spooled(tmp_path):
    t, inner, sp = make(tmp_path, PermanentTransportError("422"))
    with pytest.raises(PermanentTransportError):
        t.send(snap(1))
    assert sp.count() == 0


def test_explicit_flush_reports_drained(tmp_path):
    t, inner, sp = make(tmp_path, TransportError("d"), TransportError("still down"))
    t.send(snap(1))
    assert t.flush() is False and sp.count() == 1
    assert t.flush() is True and sp.count() == 0
