"""리포트의 근거가 되는 집계(facts). LLM 은 이 숫자만 근거로 서술하고, 계산은 서버가 한다.

호스트명·태그·오류 문자열은 에이전트/관리자가 넣은 신뢰할 수 없는 값이라 정제하고 목록에는 상한을 둔다
(총계는 정확히 유지하고 목록만 자른다).
"""
from __future__ import annotations

import unicodedata
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from swinventory.server.netview import annotate_port, ip_conflicts
from swinventory.server.policy import KernelPolicy
from swinventory.server.repo.base import InventoryRepository
from swinventory.server.timeutil import normalize_ts

NO_TEAM = "(태그 없음)"
CAP_HOSTS, CAP_STALE_ERR, CAP_DIST, CAP_SPREAD, CAP_KERNEL_CHANGES = 50, 30, 15, 20, 20


def clean(value: Any, limit: int = 200) -> str:
    """제어문자(널·ESC 등)를 제거하고 길이를 제한한다."""
    text = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def build_facts(repo: InventoryRepository, policy: KernelPolicy, *, now: datetime,
                stale_after_hours: float, since_days: int = 7) -> dict[str, Any]:
    cutoff = normalize_ts(now - timedelta(hours=stale_after_hours))
    since = normalize_ts(now - timedelta(days=since_days))
    hosts = repo.list_hosts()

    team_of = lambda h: clean(h["tags"].get("team") or NO_TEAM, 64)  # noqa: E731
    rows, totals = [], {"hosts": len(hosts), "ok": 0, "error": 0, "stale": 0, "reboot_required": 0}
    by_team: dict[str, dict[str, int]] = defaultdict(lambda: {"hosts": 0, "noncompliant": 0, "reboot_required": 0, "stale": 0, "error": 0})
    os_counts: dict[str, int] = defaultdict(int)
    for h in hosts:
        status = "stale" if h["last_seen"] < cutoff else ("error" if h["last_errors"] else "ok")
        minimum, compliant = policy.evaluate(h["os_family"], h["running"])
        totals[status] += 1
        totals["reboot_required"] += bool(h["reboot_required"])
        team = by_team[team_of(h)]
        team["hosts"] += 1
        team["noncompliant"] += compliant is False
        team["reboot_required"] += bool(h["reboot_required"])
        team["stale"] += status == "stale"
        team["error"] += status == "error"
        os_counts[clean(h["os_name"] or "(알 수 없음)", 80)] += 1
        rows.append((h, status, minimum, compliant))

    by_name = lambda r: r[0]["hostname"]  # noqa: E731
    noncompliant = sorted((r for r in rows if r[3] is False), key=by_name)
    reboot = sorted((r for r in rows if r[0]["reboot_required"]), key=by_name)
    errors = sorted((r for r in rows if r[1] == "error"), key=by_name)
    stale = sorted((r for r in rows if r[1] == "stale"), key=by_name)

    ports = [annotate_port(r) for r in repo.list_ports()]
    conflicts = ip_conflicts(repo.list_ips())
    exposed_notable: dict[tuple[str, int], dict[str, Any]] = {}
    for r in ports:
        if r["notable"]:
            e = exposed_notable.setdefault((r["proto"], r["port"]), {"proto": r["proto"], "port": r["port"], "service": r["service"],
                                                                    "reason": r["notable_reason"], "hosts": set()})
            e["hosts"].add(r["host_id"])
    reporting = {h["host_id"] for h in hosts if h["ips"]} | {r["host_id"] for r in ports}
    network = {
        "hosts_reporting": len(reporting), "hosts_without_network_data": len(hosts) - len(reporting),
        "ip_conflict_count": len(conflicts),
        "ip_conflicts": [{"ip": ip, "hosts": sorted({clean(r["hostname"]) for r in rows})[:5]}
                         for ip, rows in sorted(conflicts.items())[:20]],
        "notable_exposed_host_count": len({r["host_id"] for r in ports if r["notable"]}),
        "notable_exposed_ports": [{"proto": e["proto"], "port": e["port"], "service": e["service"], "reason": e["reason"],
                                   "host_count": len(e["hosts"])}
                                  for e in sorted(exposed_notable.values(), key=lambda e: (-len(e["hosts"]), e["port"]))[:20]],
        "note": "노출 판정은 바인딩 주소 기준이며 방화벽 규칙은 반영하지 않는다",
    }
    return {
        "generated_at": normalize_ts(now),
        "network": network,
        "stale_after_hours": stale_after_hours,
        "totals": totals,
        "kernel_policy": {"active": policy.active, "rules": policy.to_dicts(), "noncompliant_count": len(noncompliant)},
        "noncompliant_hosts": [{"hostname": clean(h["hostname"]), "os_family": h["os_family"], "running": clean(h["running"]),
                                "min_kernel": minimum, "team": team_of(h)} for h, _s, minimum, _c in noncompliant[:CAP_HOSTS]],
        "noncompliant_hosts_truncated": len(noncompliant) > CAP_HOSTS,
        "reboot_required_hosts": [{"hostname": clean(h["hostname"]), "running": clean(h["running"]),
                                   "latest_installed": clean(h["latest_installed"]), "team": team_of(h)}
                                  for h, *_ in reboot[:CAP_HOSTS]],
        "reboot_required_hosts_truncated": len(reboot) > CAP_HOSTS,
        "error_hosts": [{"hostname": clean(h["hostname"]), "errors": {clean(k, 64): clean(v) for k, v in h["last_errors"].items()}}
                        for h, *_ in errors[:CAP_STALE_ERR]],
        "stale_hosts": [{"hostname": clean(h["hostname"]), "last_seen": h["last_seen"]} for h, *_ in stale[:CAP_STALE_ERR]],
        "kernel_distribution": [{"version": clean(k["version"]), "host_count": k["host_count"]}
                                for k in repo.kernel_distribution()[:CAP_DIST]],
        "os_distribution": [{"os": name, "host_count": n}
                            for name, n in sorted(os_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:CAP_DIST]],
        "package_version_spread": [{"name": clean(p["name"], 120), "version_count": p["version_count"], "host_count": p["host_count"]}
                                   for p in repo.package_version_spread(3, CAP_SPREAD)],
        "by_team": dict(sorted(by_team.items(), key=lambda kv: (-kv[1]["noncompliant"], -kv[1]["hosts"], kv[0]))[:30]),
        "recent_events": {
            "since_days": since_days,
            "counts": repo.count_events_by_type(since),
            "kernel_changes": [{"hostname": clean(e["hostname"]), "from": clean(e["old_value"]), "to": clean(e["new_value"]),
                                "at": e["occurred_at"]} for e in repo.list_events(event_type="kernel_changed", since=since,
                                                                                   limit=CAP_KERNEL_CHANGES)],
        },
    }
