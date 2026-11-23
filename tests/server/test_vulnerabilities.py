"""CISA/NVD 피드 검증, 신선도 보존과 설치 근거 기반 CVE 조회 계약."""
import pytest
from fastapi.testclient import TestClient

from swinventory.common.models import PackageRecord
from swinventory.server.app import ApiSettings, create_app
from swinventory.server.vulnerabilities import KEV_URL, NVD_URL, VulnerabilityFeedService
from tests.server.conftest import make_snapshot
from tests.server.test_api import AD, ING, RD

PASSWORD = "vulnerability-test-password"
KEY = "vulnerability-test-key-" + "y" * 40


class FakeFetcher:
    def __init__(self, *, cves=None, total=None, fail_nvd=False):
        self.cves = cves if cves is not None else [_nvd("CVE-2026-4242")]
        self.total = total if total is not None else len(self.cves)
        self.fail_nvd = fail_nvd
        self.calls = []

    def get_json(self, url, *, params=None, headers=None, timeout=15.0):
        self.calls.append((url, dict(params or {}), dict(headers or {}), timeout))
        if url == KEV_URL:
            return {"catalogVersion": "2026.11.05", "dateReleased": "2026-11-05T00:00:00Z",
                    "count": 1, "vulnerabilities": [{
                        "cveID": "CVE-2026-4242", "vendorProject": "Example", "product": "CorpDesk",
                        "vulnerabilityName": "Remote code execution", "dateAdded": "2026-11-04",
                        "shortDescription": "A vulnerability in CorpDesk.", "requiredAction": "Apply vendor update.",
                        "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Unknown",
                        "notes": "https://vendor.example/advisory"}]}
        assert url == NVD_URL
        if self.fail_nvd:
            import httpx
            request = httpx.Request("GET", url)
            response = httpx.Response(503, request=request)
            raise httpx.HTTPStatusError("unavailable", request=request, response=response)
        start = int((params or {}).get("startIndex", "0"))
        return {"totalResults": self.total, "vulnerabilities": self.cves[start:start + 200]}


def _nvd(cve_id):
    return {"cve": {"id": cve_id, "descriptions": [{"lang": "en", "value": "NVD description"}],
        "published": "2026-11-03T12:00:00.000Z", "lastModified": "2026-11-04T12:00:00.000Z",
        "vulnStatus": "Analyzed", "metrics": {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov",
            "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                         "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/" + cve_id, "tags": ["Third Party Advisory"]}],
        "configurations": [{"operator": "OR", "nodes": [{"cpeMatch": [{"vulnerable": True,
            "criteria": "cpe:2.3:a:example:corpdesk:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.2.4"}]}]}]}}


def _client(repo, clock):
    return TestClient(create_app(repo, ApiSettings(ingest_tokens=("ing-tok",), read_tokens=("read-tok",),
        admin_tokens=("adm-tok",)), clock=clock, env={"SWINV_JWT_SECRET": KEY}))


def _user(client, username, role):
    response = client.post("/v1/users", headers=AD,
        json={"username": username, "password": PASSWORD, "role": role})
    assert response.status_code == 201, response.text
    return response.json()


def _session(client, username):
    response = client.post("/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def test_kev_nvd_sync_retains_official_metadata_and_exact_install_evidence(repo, clock):
    client = _client(repo, clock)
    client.post("/v1/ingest", headers=ING, json=make_snapshot(host_id="desk-1",
        packages=[PackageRecord("dpkg", "CorpDesk", "1.2.3", "amd64")]).to_dict())
    user = _user(client, "vuln-admin", "admin")
    admin = _session(client, "vuln-admin")
    feeds = VulnerabilityFeedService(repo, clock, FakeFetcher(), nvd_api_key="secret-nvd-key")
    result = feeds.sync()
    assert [item["state"] for item in result["feeds"]] == ["ok", "ok"]
    kev = client.get("/v1/vulnerabilities", headers=RD, params={"kev": "true"})
    assert kev.status_code == 200, kev.text
    row = kev.json()["items"][0]
    assert row["cve_id"] == "CVE-2026-4242" and row["impact_status"] == "not_assessed"
    assert row["cvss_score"] == "9.8" and row["cvss_severity"] == "CRITICAL"
    assert client.get("/v1/vulnerabilities", headers=RD, params={"impact": "not_assessed"}).json()["total"] == 1
    assert client.get("/v1/vulnerabilities/CVE-2026-4242", headers=RD).json()["kev"]["due_date"] == "2026-12-01"

    match = {"cve_id": "CVE-2026-4242", "source": "dpkg", "name": "CorpDesk", "arch": "amd64",
        "status": "affected_confirmed", "evidence": "공급자 보안 공지 SA-2026-9에서 설치 버전 확인",
        "conditions": "1.2.4 이전 버전", "affected_versions": ["1.2.3"]}
    saved = client.put("/v1/vulnerabilities/matches", headers=admin, json=match)
    assert saved.status_code == 200, saved.text
    confirmed = client.get("/v1/vulnerabilities", headers=RD, params={"impact": "confirmed"}).json()
    assert confirmed["total"] == 1
    assert (confirmed["items"][0]["host_count"], confirmed["items"][0]["install_count"]) == (1, 1)
    detail = client.get("/v1/vulnerabilities/CVE-2026-4242", headers=RD).json()
    assert detail["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] == "1.2.4"
    assert detail["matches"][0]["installations"][0]["host_id"] == "desk-1"
    assert detail["matches"][0]["installations"][0]["version"] == "1.2.3"
    scoped = client.get("/v1/vulnerabilities", headers=RD, params={"host": "desk-1"})
    assert scoped.status_code == 200 and scoped.json()["total"] == 1
    assert (scoped.json()["items"][0]["host_count"], scoped.json()["items"][0]["install_count"]) == (1, 1)
    assert client.get("/v1/vulnerabilities", headers=RD, params={"host": "other-host"}).json()["total"] == 0
    assert client.put("/v1/vulnerabilities/matches", headers=RD, json=match).status_code == 403
    assert client.post("/v1/vulnerabilities/sync", headers=RD).status_code == 403
    assert "secret-nvd-key" not in str(repo.vulnerability_feed_status())

    # NVD 장애 때 마지막 성공 기준 시각·메타데이터를 지우지 않는다.
    before = {r["source"]: r for r in repo.vulnerability_feed_status()}["nvd"]["last_success_at"]
    failed = VulnerabilityFeedService(repo, clock, FakeFetcher(fail_nvd=True)).sync_nvd_page()
    assert failed["state"] == "failed"
    after = {r["source"]: r for r in repo.vulnerability_feed_status()}["nvd"]
    assert after["state"] == "failed" and after["last_success_at"] == before
    assert client.get("/v1/vulnerabilities/CVE-2026-4242", headers=RD).status_code == 200


def test_nvd_pages_are_resumable_and_failure_does_not_claim_full_coverage(repo, clock):
    values = [_nvd(f"CVE-2026-{number:04d}") for number in range(200)]
    values.append(_nvd("CVE-2026-9000"))
    fetcher = FakeFetcher(cves=values, total=201)
    service = VulnerabilityFeedService(repo, clock, fetcher)
    first = service.sync_nvd_page()
    assert first == {"source": "nvd", "state": "partial", "records": 200, "total": 201,
                     "next_start_index": 200, "scope": "modified_window_120d"}
    assert repo.vulnerability_feed_status()[0]["state"] == "partial"
    second = service.sync_nvd_page()
    assert second["state"] == "ok" and second["records"] == 201
    assert len(fetcher.calls) == 2
    assert fetcher.calls[1][1]["startIndex"] == "200"
    assert repo.vulnerability_detail("CVE-2026-9000") is not None
