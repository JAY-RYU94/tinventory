"""CISA KEV와 NVD 2.0의 제한된 동기화. 네트워크 호출은 교체 가능한 클라이언트 뒤에 둔다."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol

import httpx

from swinventory.server.repo.base import InventoryRepository
from swinventory.server.timeutil import normalize_ts

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SAFE_FEED_ERRORS = {
    "timeout", "network_error", "invalid_feed",
    "외부 피드가 리다이렉트했습니다.",
    "외부 피드 응답이 20MB 한도를 넘었습니다.",
    "외부 피드 JSON 형식이 올바르지 않습니다.",
    "KEV catalog metadata/count mismatch", "KEV row is malformed",
    "KEV row ID/date is malformed", "NVD page metadata is malformed",
    "NVD CVE row is malformed", "NVD CVE ID is malformed",
}


class JsonFetcher(Protocol):
    def get_json(self, url: str, *, params: Mapping[str, str] | None = None,
                 headers: Mapping[str, str] | None = None, timeout: float = 15.0) -> dict[str, Any]: ...


class HttpxJsonFetcher:
    """기본 외부 클라이언트. 리다이렉트는 따르지 않고 응답 크기·시간을 제한한다."""

    def get_json(self, url: str, *, params: Mapping[str, str] | None = None,
                 headers: Mapping[str, str] | None = None, timeout: float = 15.0) -> dict[str, Any]:
        response = httpx.get(url, params=params, headers=headers, timeout=timeout, follow_redirects=False)
        if 300 <= response.status_code < 400:
            raise ValueError("외부 피드가 리다이렉트했습니다.")
        response.raise_for_status()
        if len(response.content) > 20 * 1024 * 1024:
            raise ValueError("외부 피드 응답이 20MB 한도를 넘었습니다.")
        value = response.json()
        if not isinstance(value, dict):
            raise ValueError("외부 피드 JSON 형식이 올바르지 않습니다.")
        return value


def _text(value: Any, limit: int = 2000) -> str:
    if not isinstance(value, str):
        return ""
    return _CONTROL.sub("", value).strip()[:limit]


def _date(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return normalize_ts(value)
    except ValueError:
        return None


def _safe_feed_error(exc: Exception) -> str:
    """공급자·DB 예외의 원문을 숨기고 미리 정한 진단만 상태에 남긴다."""
    message = exc.args[0] if exc.args and isinstance(exc.args[0], str) else ""
    if type(exc) is RuntimeError and (message in _SAFE_FEED_ERRORS or re.fullmatch(r"HTTP [1-5][0-9]{2}", message)):
        return message
    if type(exc) is ValueError and message in _SAFE_FEED_ERRORS:
        return message
    return "sync_failed"


def _record_failed(repo: InventoryRepository, source: str, attempted: str, error: str) -> None:
    """실패 상태 쓰기도 안전한 예외로 감싸 SQL/바인드 값이 로그로 새지 않게 한다."""
    try:
        repo.record_vulnerability_feed(source, "failed", attempted, None, error, "", 0)
    except Exception:
        raise RuntimeError("feed_status_write_failed") from None


def _retry(fetcher: JsonFetcher, url: str, *, params=None, headers=None) -> dict[str, Any]:
    last: Exception | None = None
    for attempt in range(3):
        try:
            return fetcher.get_json(url, params=params, headers=headers, timeout=15.0)
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError, ValueError) as exc:
            last = exc
            retryable = not isinstance(exc, httpx.HTTPStatusError) or exc.response.status_code == 429 or exc.response.status_code >= 500
            if not retryable or attempt == 2:
                break
            time.sleep(0.4 * (2 ** attempt))
    if isinstance(last, httpx.HTTPStatusError):
        raise RuntimeError(f"HTTP {last.response.status_code}") from None
    if isinstance(last, httpx.TimeoutException):
        raise RuntimeError("timeout") from None
    if isinstance(last, httpx.NetworkError):
        raise RuntimeError("network_error") from None
    raise RuntimeError("invalid_feed") from None


class VulnerabilityFeedService:
    def __init__(self, repo: InventoryRepository, clock, fetcher: JsonFetcher | None = None,
                 nvd_api_key: str | None = None):
        self.repo = repo
        self.clock = clock
        self.fetcher = fetcher or HttpxJsonFetcher()
        self.nvd_api_key = nvd_api_key or ""

    def sync_kev(self) -> dict[str, Any]:
        attempted = normalize_ts(self.clock())
        try:
            payload = _retry(self.fetcher, KEV_URL)
            version = _text(payload.get("catalogVersion"), 32)
            date_released = _date(payload.get("dateReleased"))
            entries = payload.get("vulnerabilities")
            if not version or not isinstance(entries, list) or payload.get("count") != len(entries):
                raise ValueError("KEV catalog metadata/count mismatch")
            rows = []
            seen = set()
            for item in entries:
                if not isinstance(item, dict):
                    raise ValueError("KEV row is malformed")
                cve_id = _text(item.get("cveID"), 32)
                date_added, due_date = _text(item.get("dateAdded"), 10), _text(item.get("dueDate"), 10)
                if not _CVE.fullmatch(cve_id) or cve_id in seen or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_added) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", due_date):
                    raise ValueError("KEV row ID/date is malformed")
                seen.add(cve_id)
                notes = _text(item.get("notes"), 2000)
                references = [part.strip() for part in notes.split(";") if part.strip().startswith("https://")]
                rows.append(dict(cve_id=cve_id, vendor=_text(item.get("vendorProject"), 255),
                    product=_text(item.get("product"), 512), vulnerability_name=_text(item.get("vulnerabilityName"), 512),
                    date_added=date_added, due_date=due_date, ransomware_use=_text(item.get("knownRansomwareCampaignUse"), 16),
                    required_action=_text(item.get("requiredAction"), 4000), notes=notes,
                    description=_text(item.get("shortDescription"), 4000), references=references, modified_at=date_released))
            self.repo.replace_cisa_kev(rows, version, attempted)
            self.repo.record_vulnerability_feed("cisa_kev", "ok", attempted, attempted, "", version, len(rows))
            return {"source": "cisa_kev", "state": "ok", "records": len(rows), "data_version": version}
        except Exception as exc:  # noqa: BLE001 — 기존 성공 데이터를 보존하고 공개 가능한 분류만 남긴다
            error = _safe_feed_error(exc)
            _record_failed(self.repo, "cisa_kev", attempted, error)
            return {"source": "cisa_kev", "state": "failed", "error": error}

    def sync_nvd_page(self) -> dict[str, Any]:
        attempted = normalize_ts(self.clock())
        statuses = {r["source"]: r for r in self.repo.vulnerability_feed_status()}
        previous = statuses.get("nvd") or {}
        try:
            cursor_data = {}
            if previous.get("data_version"):
                try:
                    candidate = json.loads(previous["data_version"])
                    if (isinstance(candidate, dict)
                            and candidate.get("scope") == "modified_window_120d"
                            and type(candidate.get("start_index")) is int and candidate["start_index"] >= 0
                            and type(candidate.get("synced")) is int and candidate["synced"] >= 0
                            and isinstance(candidate.get("window_start"), str)
                            and isinstance(candidate.get("window_end"), str)):
                        cursor_data = candidate
                except (ValueError, TypeError):
                    cursor_data = {}
            if not cursor_data:
                now = self.clock().astimezone(timezone.utc)
                start = previous.get("last_success_at")
                start_dt = datetime.fromisoformat(start.replace("Z", "+00:00")) if start else now - timedelta(days=120)
                if start_dt.tzinfo is None:
                    start_dt = start_dt.replace(tzinfo=timezone.utc)
                start_dt = min(max(start_dt - timedelta(minutes=2), now - timedelta(days=120)), now - timedelta(seconds=1))
                cursor_data = {"scope": "modified_window_120d", "window_start": normalize_ts(start_dt),
                               "window_end": normalize_ts(now), "start_index": 0, "synced": 0}
            params = {"startIndex": str(int(cursor_data.get("start_index", 0))), "resultsPerPage": "200",
                      "lastModStartDate": cursor_data["window_start"], "lastModEndDate": cursor_data["window_end"]}
            headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
            payload = _retry(self.fetcher, NVD_URL, params=params, headers=headers)
            total = payload.get("totalResults")
            rows = payload.get("vulnerabilities")
            if not isinstance(total, int) or total < 0 or not isinstance(rows, list) or len(rows) > 200:
                raise ValueError("NVD page metadata is malformed")
            normalized = [self._nvd_row(item) for item in rows]
            self.repo.upsert_nvd_vulnerabilities(normalized, attempted)
            next_index = int(cursor_data.get("start_index", 0)) + len(rows)
            synced = int(cursor_data.get("synced", 0)) + len(rows)
            if next_index < total:
                next_cursor = {**cursor_data, "start_index": next_index, "synced": synced, "total_results": total}
                version = json.dumps(next_cursor, sort_keys=True)
                self.repo.record_vulnerability_feed("nvd", "partial", attempted, None, "", version, synced)
                return {"source": "nvd", "state": "partial", "records": synced, "total": total,
                        "next_start_index": next_index, "scope": cursor_data["scope"]}
            version = json.dumps({"scope": cursor_data["scope"], "window_start": cursor_data["window_start"],
                                  "window_end": cursor_data["window_end"], "complete": True}, sort_keys=True)
            self.repo.record_vulnerability_feed("nvd", "ok", attempted, attempted, "", version, synced)
            return {"source": "nvd", "state": "ok", "records": synced, "total": total,
                    "scope": cursor_data["scope"]}
        except Exception as exc:  # noqa: BLE001 — 실패한 source 의 기존 CVE 행은 삭제하지 않는다
            error = _safe_feed_error(exc)
            _record_failed(self.repo, "nvd", attempted, error)
            return {"source": "nvd", "state": "failed", "error": error}

    def sync(self) -> dict[str, Any]:
        """한 요청에서 KEV 전체와 NVD 한 페이지를 갱신한다. NVD 페이지는 이어서 동기화한다."""
        return {"feeds": [self.sync_kev(), self.sync_nvd_page()]}

    @staticmethod
    def _nvd_row(item: Any) -> dict[str, Any]:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            raise ValueError("NVD CVE row is malformed")
        cve = item["cve"]
        cve_id = _text(cve.get("id"), 32)
        if not _CVE.fullmatch(cve_id):
            raise ValueError("NVD CVE ID is malformed")
        descriptions = cve.get("descriptions") or []
        english = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
        if not isinstance(english, str):
            english = descriptions[0].get("value", "") if descriptions else ""
        metrics = cve.get("metrics") or {}
        cvss_score = cvss_severity = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            candidates = metrics.get(key) or []
            if candidates:
                chosen = next((m for m in candidates if m.get("type") == "Primary"), candidates[0])
                data = chosen.get("cvssData") or {}
                cvss_score = str(data.get("baseScore")) if data.get("baseScore") is not None else None
                cvss_severity = _text(data.get("baseSeverity") or chosen.get("baseSeverity"), 24) or None
                break
        return {"cve_id": cve_id, "description": _text(english, 4000),
                "published_at": _date(cve.get("published")), "modified_at": _date(cve.get("lastModified")),
                "cvss_score": cvss_score, "cvss_severity": cvss_severity,
                "cvss_metrics": metrics, "nvd_status": _text(cve.get("vulnStatus"), 32),
                "references": cve.get("references") if isinstance(cve.get("references"), list) else [],
                "configurations": cve.get("configurations") if isinstance(cve.get("configurations"), list) else []}
