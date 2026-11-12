from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from swinventory.common.versioning import version_key
from swinventory.server.api.csvutil import csv_response
from swinventory.server.api.models import has_control
from swinventory.server.netview import annotate_port, ip_conflicts
from swinventory.server import containerview
from swinventory.server.assets import AssetService
from swinventory.server.api.params import FORMAT as _FORMAT
from swinventory.server.api.params import parse_tags as _parse_tags
from swinventory.server.policy import KernelPolicy
from swinventory.server.repo.base import InventoryRepository
from swinventory.server.timeutil import normalize_ts

_HOST_SEARCH = ("hostname", "host_id", "os_name", "asset_no", "domain")       # 호스트 목록 q 가 보는 열(IP 는 따로 본다)
_KERNEL_SEARCH = ("hostname", "host_id", "asset_no")                          # 커널 호스트 목록 q 가 보는 열
_HOST_CSV = ["hostname", "host_id", "asset_no", "kind", "domain", "ips", "os_name", "running", "kernel_compliant", "reboot_required",
             "status", "last_seen", "tags"]


def _has_text(row: dict[str, Any], keys: tuple[str, ...], needle: str) -> bool:
    """소문자 needle 이 row[keys] 중 하나에 부분 일치하는가. 값이 None(자산이 없는 asset_no 등)이면 빈 문자열로 본다."""
    return any(needle in str(row.get(k) or "").lower() for k in keys)


def _host_matches(host: dict[str, Any], needle: str) -> bool:
    return _has_text(host, _HOST_SEARCH, needle) or any(needle in ip.lower() for ip in host["ips"])


def build_router(repo: InventoryRepository, require_read: Callable[..., None],
                 require_admin: Callable[..., None], clock: Callable[[], datetime],
                 stale_after_hours: float, load_policy: Callable[[], KernelPolicy], assets: AssetService) -> APIRouter:
    router = APIRouter(prefix="/v1")
    read = [Depends(require_read)]

    def stale_before() -> str:
        return normalize_ts(clock() - timedelta(hours=stale_after_hours))

    def with_status(host: dict[str, Any], cutoff: str) -> dict[str, Any]:
        """status: stale(수집이 끊김) > error(마지막 수집에 실패한 수집기가 있음) > ok."""
        host["stale"] = host["last_seen"] < cutoff
        host["status"] = "stale" if host["stale"] else ("error" if host["last_errors"] else "ok")
        return host

    def with_compliance(row: dict[str, Any], policy: KernelPolicy) -> dict[str, Any]:
        """커널 하한선 판정(실행 중 커널 기준). 정책이 없거나 커널 정보가 없으면 compliant 는 None."""
        row["min_kernel"], row["compliant"] = policy.evaluate(row.get("os_family"), row.get("running"))
        return row

    @router.get("/overview", dependencies=read)
    def overview() -> dict:
        data = repo.overview(stale_before())
        data["stale_after_hours"] = stale_after_hours
        book = assets.book()
        assets.annotate(data["recent_events"], book)
        data["containers"] = containerview.summary(repo.list_k8s_nodes(), repo.list_containers())
        data["assets"] = book.summary()                                                    # 자산 미등록·미수집 카드용
        policy = load_policy()
        data["policy_active"] = policy.active
        ips, ports = repo.list_ips(), [annotate_port(r) for r in repo.list_ports()]
        data["ip_conflict_count"] = len(ip_conflicts(ips))                               # 같은 IP 를 둘 이상의 호스트가 쓰는 IP 수
        data["notable_exposed_host_count"] = len({r["host_id"] for r in ports if r["notable"]})   # 주의 포트를 비루프백 주소로 연 호스트 수
        data["noncompliant_count"] = sum(
            1 for h in repo.list_hosts() if policy.evaluate(h["os_family"], h["running"])[1] is False) if policy.active else 0
        return data

    @router.get("/hosts", dependencies=read, response_model=None)
    def hosts(tag: list[str] = Query(default=[]), ip: str | None = Query(None, max_length=64, description="이 IP 를 가진 호스트(정확히 일치)"),
              q: str | None = Query(None, max_length=200, description="호스트명·호스트 ID·OS 이름·자산번호·도메인·IP 부분 일치(대소문자 무시)"),
              status: str | None = Query(None, pattern="^(ok|error|stale)$", description="ok=정상, error=마지막 수집에 실패한 수집기가 있음, stale=수집이 끊김"),
              fmt: str = _FORMAT) -> Response | list[dict]:
        cutoff, policy = stale_before(), load_policy()
        out = []
        for h in repo.list_hosts(_parse_tags(tag)):
            if ip is not None and ip not in h["ips"]:
                continue
            with_status(h, cutoff)
            h["min_kernel"], h["kernel_compliant"] = policy.evaluate(h["os_family"], h["running"])
            out.append(h)
        assets.annotate(out)
        needle = (q or "").strip().lower()   # 자산번호·도메인은 annotate 로 붙는 열이라 q·status 는 그 뒤에 거른다
        out = [h for h in out if (status is None or h["status"] == status) and (not needle or _host_matches(h, needle))]
        if fmt == "csv":
            return csv_response([{**h, "ips": ";".join(h["ips"])} for h in out], _HOST_CSV, "hosts.csv")   # CSV 에서만 ips 를 ';' 로 잇는다
        return out

    @router.get("/hosts/{host_id}", dependencies=read)
    def host(host_id: str) -> dict:
        detail = repo.host_detail(host_id)
        if detail is None:
            raise HTTPException(404, "host not found")
        with_status(detail["host"], stale_before())
        detail["ports"] = [annotate_port(p) for p in detail["ports"]]
        detail["asset"] = assets.book().host_view(host_id)
        if detail["kernel"]:
            minimum, compliant = load_policy().evaluate(detail["host"]["os_family"], detail["kernel"]["running"])
            detail["kernel"].update(min_kernel=minimum, compliant=compliant)
        return detail

    @router.put("/hosts/{host_id}/tags", dependencies=[Depends(require_admin)])
    def put_tags(host_id: str, tags: dict[str, str]) -> dict:
        if any(not k or len(k) > 64 or len(v) > 255 or ":" in k for k, v in tags.items()):
            raise HTTPException(422, "tag key 1~64자(':' 불가), value 255자 이하")
        if any(has_control(k) or has_control(v) for k, v in tags.items()):
            raise HTTPException(422, "tag 에 제어문자를 넣을 수 없다")
        if not repo.set_tags(host_id, tags):
            raise HTTPException(404, "host not found")
        return {"tags": tags}

    @router.delete("/hosts/{host_id}", dependencies=[Depends(require_admin)])
    def delete_host(host_id: str) -> dict:
        """폐기된 서버 정리. 같은 host_id 로 다시 수집되면 새 호스트(기준선)로 등록된다."""
        if not repo.delete_host(host_id):
            raise HTTPException(404, "host not found")
        return {"deleted": host_id}

    @router.get("/kernels", dependencies=read)
    def kernels() -> list[dict]:
        return repo.kernel_distribution()

    @router.get("/kernels/hosts", dependencies=read, response_model=None)
    def kernel_hosts(reboot_required: bool | None = None, running: str | None = None, compliant: bool | None = None,
                     tag: list[str] = Query(default=[]), q: str | None = Query(None, max_length=200, description="호스트명·호스트 ID·자산번호 부분 일치(대소문자 무시)"),
                     fmt: str = _FORMAT) -> Response | list[dict]:
        policy = load_policy()
        rows = [with_compliance(r, policy) for r in
                repo.kernel_hosts(reboot_required=reboot_required, running=running, tags=_parse_tags(tag))]
        assets.annotate(rows)
        needle = (q or "").strip().lower()
        if needle:  # 자산번호는 annotate 로 붙는 열이라 그 뒤에 거른다
            rows = [r for r in rows if _has_text(r, _KERNEL_SEARCH, needle)]
        if compliant is not None:  # 판정 대상이 아닌 호스트(None)는 어느 쪽 필터에도 포함하지 않는다
            rows = [r for r in rows if r["compliant"] is compliant]
        if fmt == "csv":
            return csv_response(rows, ["host_id", "hostname", "os_family", "running", "min_kernel", "compliant",
                                       "latest_installed", "reboot_required", "asset_no", "kind", "domain", "tags"], "kernels-hosts.csv")
        return rows

    @router.get("/software", dependencies=read)
    def software(q: str = Query(min_length=1), limit: int = Query(100, ge=1, le=1000)) -> list[dict]:
        return repo.software_search(q, limit)

    @router.get("/software-hosts", dependencies=read)
    def software_hosts(q: str = Query("", max_length=200), host: str | None = Query(None, max_length=128)) -> list[dict]:
        return assets.annotate(repo.software_hosts(q.strip(), host))

    @router.get("/software/{name:path}", dependencies=read, response_model=None)
    def software_detail(name: str, version: str | None = Query(None, max_length=256, description="이 버전을 가진 호스트만(정확히 일치)"),
                        below: str | None = Query(None, max_length=256, description="이 버전보다 낮은 호스트만(숫자·문자 토큰 비교, 같은 버전은 제외)"),
                        host: str | None = Query(None, max_length=128), fmt: str = _FORMAT) -> Response | dict:
        """version·below 는 hosts 만 거른다 — versions(분포)는 선택한 host 범위 전체다(미선택 시 모든 서버). 한 호스트에 여러 버전이 공존하면 버전(행) 단위로 거르고,
        일치하는 행이 없어도 패키지가 있으면 200(빈 hosts)이다. 404 는 패키지가 아예 없을 때만."""
        detail = repo.software_detail(name)
        if detail is None:
            raise HTTPException(404, "package not found")
        if host is not None:
            detail["hosts"] = [row for row in detail["hosts"] if row["host_id"] == host]
            detail["versions"] = [{"version": value, "host_count": 1}
                                  for value in sorted({row["version"] for row in detail["hosts"]}, key=version_key, reverse=True)]
        version, below = version or None, below or None   # 빈 값은 필터가 아니다
        limit = version_key(below) if below is not None else None
        detail["hosts"] = [h for h in detail["hosts"]
                           if (version is None or h["version"] == version) and (limit is None or version_key(h["version"]) < limit)]
        detail["filter"] = {"version": version, "below": below}
        assets.annotate(detail["hosts"])
        if fmt == "csv":
            return csv_response(detail["hosts"], ["host_id", "hostname", "version", "arch", "source", "asset_no", "kind", "domain"],
                                "software-hosts.csv")
        return detail

    @router.get("/events", dependencies=read, response_model=None)
    def events(host: str | None = None, type: str | None = None, since: str | None = None,
               limit: int = Query(100, ge=1, le=1000), fmt: str = _FORMAT) -> Response | list[dict]:
        try:
            since_ts = normalize_ts(since) if since else None
        except ValueError:
            raise HTTPException(422, "since 는 ISO-8601 형식이어야 한다") from None
        rows = assets.annotate(repo.list_events(host_id=host, event_type=type, since=since_ts, limit=limit))
        if fmt == "csv":
            return csv_response(rows, ["id", "occurred_at", "hostname", "host_id", "asset_no", "kind", "event_type",
                                       "subject_key", "old_value", "new_value"], "events.csv")
        return rows

    return router
