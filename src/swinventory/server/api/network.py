from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from fastapi import APIRouter, Depends, Query, Response

from swinventory.common.ports import notable_reason, service_name
from swinventory.server.api.csvutil import csv_response
from swinventory.server.api.params import FORMAT, parse_tags
from swinventory.server.netview import annotate_port, ip_conflicts, matches_exposure
from swinventory.server.assets import AssetService
from swinventory.server.repo.base import InventoryRepository

_EXPOSURE = Query(None, pattern="^(any|specific|loopback|exposed)$",
                  description="any=모든 인터페이스 바인딩, specific=특정 주소, loopback=이 호스트만, exposed=loopback 이 아닌 전부")
_PROTO = Query(None, pattern="^(tcp|udp)$")
_IP_SEARCH = ("ip", "mac", "hostname", "interface", "asset_no")      # IP 목록 q 가 보는 열(화면 검색창 안내와 같다). asset_no 는 annotate 로 붙는다


def build_router(repo: InventoryRepository, require_read: Callable[..., None], assets: AssetService) -> APIRouter:
    router = APIRouter(prefix="/v1/network", dependencies=[Depends(require_read)])

    @router.get("/ips", response_model=None)
    def ips(q: str | None = Query(None, max_length=200), tag: list[str] = Query(default=[]),
            conflicts: bool = Query(False, description="true 면 다른 호스트도 쓰는 IP(duplicate)의 행만. false 는 필터가 아니다"),
            fmt: str = FORMAT) -> Response | list[dict]:
        """IP·MAC 인벤토리. q 는 IP·MAC·호스트명·인터페이스·자산번호 부분 일치(대소문자 무시). duplicate=같은 IP 를 다른 호스트도 쓴다."""
        tags = parse_tags(tag)
        rows = repo.list_ips(tags)
        shared = ip_conflicts(repo.list_ips() if tags else rows)   # 충돌은 태그와 무관하게 전체 기준으로 판정
        out = [{**{k: v for k, v in r.items() if k != "address"}, "cidr": r["address"], "duplicate": r["ip"] in shared} for r in rows]
        if conflicts:
            out = [r for r in out if r["duplicate"]]
        assets.annotate(out)
        needle = (q or "").strip().lower()   # 자산번호는 annotate 로 붙는 열이라 q 는 그 뒤에 거른다. 값이 None(MAC·자산이 없음)이면 빈 문자열로 본다('none' 글자가 맞으면 안 된다)
        if needle:
            out = [r for r in out if any(needle in str(r.get(k) or "").lower() for k in _IP_SEARCH)]
        if fmt == "csv":
            return csv_response(out, ["ip", "cidr", "family", "interface", "mac", "state", "hostname", "host_id", "asset_no", "kind", "duplicate"], "ips.csv")
        return out

    @router.get("/ip-conflicts")
    def conflicts() -> list[dict]:
        return [{"ip": ip, "hosts": [{"host_id": r["host_id"], "hostname": r["hostname"], "interface": r["interface"]} for r in rows]}
                for ip, rows in sorted(ip_conflicts(repo.list_ips()).items())]

    @router.get("/ports")
    def ports_summary(proto: str | None = _PROTO, exposure: str | None = _EXPOSURE, tag: list[str] = Query(default=[])) -> list[dict]:
        """(프로토콜, 포트)별 호스트 수. exposed_count=루프백이 아닌 주소에 바인딩한 호스트 수."""
        groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for r in map(annotate_port, repo.list_ports(parse_tags(tag))):
            if (proto is None or r["proto"] == proto) and matches_exposure(r, exposure):
                groups[(r["proto"], r["port"])].append(r)
        out = [{"proto": p, "port": n, "service": service_name(n), "host_count": len({r["host_id"] for r in rows}),
                "exposed_count": len({r["host_id"] for r in rows if r["exposure"] != "loopback"}),
                "notable": any(r["notable"] for r in rows), "notable_reason": notable_reason(p, n)}
               for (p, n), rows in groups.items()]
        return sorted(out, key=lambda r: (-r["host_count"], r["port"], r["proto"]))

    @router.get("/listening", response_model=None)
    def listening(proto: str | None = _PROTO, port: int | None = Query(None, ge=1, le=65535), exposure: str | None = _EXPOSURE,
                  notable: bool | None = None, tag: list[str] = Query(default=[]),
                  q: str | None = Query(None, max_length=200, description="포트·서비스·프로토콜 부분 일치 — 화면의 포트 검색(\"<포트> <서비스> <프로토콜>\")과 같은 규칙"),
                  fmt: str = FORMAT) -> Response | list[dict]:
        """호스트×리슨 포트 평면 목록(감사·내보내기용)."""
        needle = (q or "").strip().lower()
        rows = [r for r in map(annotate_port, repo.list_ports(parse_tags(tag)))
                if (proto is None or r["proto"] == proto) and (port is None or r["port"] == port)
                and matches_exposure(r, exposure) and (notable is None or r["notable"] is notable)
                and (not needle or needle in f"{r['port']} {r['service']} {r['proto']}".lower())]
        assets.annotate(rows)
        if fmt == "csv":
            return csv_response(rows, ["hostname", "host_id", "asset_no", "kind", "proto", "port", "service", "bind", "exposure", "notable", "notable_reason"],
                                "listening-ports.csv")
        return rows

    return router
