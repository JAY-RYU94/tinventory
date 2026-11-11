"""네트워크 조회 공통 로직(API·AI 리포트가 같은 판정을 쓴다)."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from swinventory.common.net import bind_exposure
from swinventory.common.ports import notable_reason, service_name


def annotate_port(row: dict[str, Any]) -> dict[str, Any]:
    """바인딩 주소 기준의 노출 판정. 방화벽 규칙은 알 수 없으므로 'notable' 은 확인 후보일 뿐이다."""
    exposure = bind_exposure(row["bind"])
    reason = notable_reason(row["proto"], row["port"])
    row.update(service=service_name(row["port"]), exposure=exposure, notable=bool(reason) and exposure != "loopback",
               notable_reason=reason if exposure != "loopback" else "")
    return row


def matches_exposure(row: dict[str, Any], exposure: str | None) -> bool:
    return exposure is None or (row["exposure"] != "loopback" if exposure == "exposed" else row["exposure"] == exposure)


def ip_conflicts(ips: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """같은 IP 를 둘 이상의 호스트가 쓰는 경우."""
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in ips:
        by_ip[r["ip"]].append(r)
    return {ip: rows for ip, rows in by_ip.items() if len({r["host_id"] for r in rows}) > 1}
