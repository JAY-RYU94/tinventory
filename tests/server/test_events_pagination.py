"""이력 API의 페이지 범위와 전체 CSV 내보내기를 검증한다."""
import csv
import io

from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from swinventory.server.domain import ChangeEvent, EventType
from swinventory.server.timeutil import normalize_ts
from tests.server.conftest import T0, make_snapshot

RD = {"Authorization": "Bearer read-tok"}
ING = {"Authorization": "Bearer ing-tok"}


def test_event_pages_report_total_and_csv_exports_all_matching_rows(repo, clock):
    client = TestClient(create_app(repo, ApiSettings(ingest_tokens=("ing-tok",), read_tokens=("read-tok",)), clock=clock))
    snap = make_snapshot(host_id="events-1", hostname="events01")
    assert client.post("/v1/ingest", headers=ING, json=snap.to_dict()).status_code == 200
    occurred = normalize_ts(T0)
    repo.add_events("events-1", None, occurred, [
        ChangeEvent(EventType.PACKAGE_INSTALLED, "package", f"pkg-{number:04d}", None, "1.0")
        for number in range(1005)
    ])

    first = client.get("/v1/events", headers=RD, params={"page": 1, "page_size": 200})
    assert first.status_code == 200
    assert first.json()["total"] == 1005 and len(first.json()["items"]) == 200
    last = client.get("/v1/events", headers=RD, params={"page": 6, "page_size": 200})
    assert last.json()["total"] == 1005 and len(last.json()["items"]) == 5

    legacy = client.get("/v1/events", headers=RD, params={"limit": 1000})
    assert isinstance(legacy.json(), list) and len(legacy.json()) == 1000
    assert legacy.headers["X-Total-Count"] == "1005" and legacy.headers["X-Result-Truncated"] == "true"

    exported = client.get("/v1/events", headers=RD, params={"format": "csv", "limit": 10})
    rows = list(csv.reader(io.StringIO(exported.text)))
    assert exported.status_code == 200 and exported.headers["X-Total-Count"] == "1005"
    assert len(rows) == 1006  # header + 모든 이벤트
