"""자산 대장 ↔ 수집 호스트 연결과 '다른 목록에 붙는 자산 열' 계산(순수 로직, DB·HTTP 비의존).

연결은 저장하지 않고 읽을 때마다 계산한다 — 호스트가 나중에 수집되거나 시리얼·IP 가 바뀌어도 어긋난 연결이 남지 않는다.
증거 우선순위: 명시 연결(관리자가 지정) > 시리얼 > 호스트명 > IP.
**모호하면 연결하지 않는다**(클론된 VM 의 같은 시리얼, 같은 짧은 이름 등). 잘못 묶는 것보다 '미수집'으로 남는 편이 안전하다.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from swinventory.common.hardware import domain_of, normalize_serial
from swinventory.common.models import HardwareInfo

KNOWN_KINDS = ("physical", "virtual")


def canonical_ip(value: str | None) -> str:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return ""


@dataclass(frozen=True)
class _Host:
    host_id: str
    hostname: str
    names: frozenset[str]      # hostname·fqdn 소문자
    shorts: frozenset[str]     # 첫 라벨
    domain: str
    serial: str                # 정규화된 시리얼
    ips: frozenset[str]        # 정규형 IP
    hw: HardwareInfo | None


class AssetBook:
    def __init__(self, assets: Iterable[dict[str, Any]], hosts: Iterable[dict[str, Any]],
                 hardware: dict[str, HardwareInfo], ips: dict[str, set[str]]):
        self._assets = sorted((dict(a) for a in assets), key=lambda a: a["id"])
        self._asset_by_id = {a["id"]: a for a in self._assets}
        self._hosts: dict[str, _Host] = {}
        for h in hosts:
            hw = hardware.get(h["host_id"])
            names = {h["hostname"].lower(), (hw.fqdn if hw else "").lower()} - {""}
            self._hosts[h["host_id"]] = _Host(
                h["host_id"], h["hostname"], frozenset(names), frozenset(n.split(".")[0] for n in names),
                (hw.domain if hw and hw.domain else domain_of(h["hostname"])).lower(), normalize_serial(hw.serial if hw else ""),
                frozenset(filter(None, (canonical_ip(i) for i in ips.get(h["host_id"], ())))), hw)
        self._link: dict[int, tuple[str, str]] = {}
        self._of_host: dict[str, int] = {}
        self._resolve()

    # --- 연결 -------------------------------------------------------------
    def _claim(self, asset_id: int, host_id: str, by: str) -> None:
        self._link[asset_id] = (host_id, by)
        self._of_host[host_id] = asset_id

    def _pair(self, matcher: Callable[[dict[str, Any], _Host], bool], by: str) -> None:
        """아직 연결되지 않은 자산·호스트 사이에서 서로 유일하게 맞는 쌍만 연결한다."""
        assets = [a for a in self._assets if a["id"] not in self._link]
        hosts = [h for h in self._hosts.values() if h.host_id not in self._of_host]
        cands: dict[int, list[str]] = {a["id"]: [h.host_id for h in hosts if matcher(a, h)] for a in assets}
        back: dict[str, list[int]] = {}
        for aid, hids in cands.items():
            for hid in hids:
                back.setdefault(hid, []).append(aid)
        for aid, hids in cands.items():
            if len(hids) == 1 and len(back[hids[0]]) == 1:
                self._claim(aid, hids[0], by)

    def _resolve(self) -> None:
        for a in self._assets:  # 명시 연결: 호스트가 사라졌으면(삭제) 무시한다
            hid = a.get("host_id")
            if hid and hid in self._hosts and hid not in self._of_host:
                self._claim(a["id"], hid, "explicit")
        self._pair(lambda a, h: bool(h.serial) and normalize_serial(a.get("serial")) == h.serial, "serial")
        self._pair(self._name_matches, "hostname")
        self._pair(lambda a, h: bool(canonical_ip(a.get("ip"))) and canonical_ip(a.get("ip")) in h.ips, "ip")

    @staticmethod
    def _name_matches(a: dict[str, Any], h: _Host) -> bool:
        name = (a.get("hostname") or "").strip().lower().rstrip(".")
        if not name:
            return False
        if "." in name:                       # 이미 FQDN 이면 그대로 비교
            return name in h.names
        domain = (a.get("domain") or "").strip().lower()
        if domain and h.domain and domain != h.domain:
            return False
        return name in h.shorts

    def link_of_asset(self, asset_id: int) -> tuple[str, str] | None:
        return self._link.get(asset_id)

    # --- 판정 -------------------------------------------------------------
    def _detected_kind(self, host_id: str) -> str:
        h = self._hosts.get(host_id)
        return h.hw.kind if h and h.hw else "unknown"

    def _flags(self, asset: dict[str, Any], host: _Host) -> list[str]:
        flags = []
        detected = self._detected_kind(host.host_id)
        if asset["kind"] in KNOWN_KINDS and detected in KNOWN_KINDS and asset["kind"] != detected:
            flags.append("kind_mismatch")
        a_serial = normalize_serial(asset.get("serial"))
        if a_serial and host.serial and a_serial != host.serial:
            flags.append("serial_mismatch")
        a_ip = canonical_ip(asset.get("ip"))
        if a_ip and host.ips and a_ip not in host.ips:
            flags.append("ip_mismatch")
        return flags

    def _parent(self, asset: dict[str, Any] | None) -> tuple[int | None, str | None, str | None]:
        pid = asset.get("parent_asset_id") if asset else None
        parent = self._asset_by_id.get(pid) if pid else None
        if not parent:
            return None, None, None
        link = self._link.get(parent["id"])
        label = self._hosts[link[0]].hostname if link else (parent.get("hostname") or "")
        return parent["id"], parent["asset_no"], label

    def host_view(self, host_id: str) -> dict[str, Any]:
        """호스트 하나에 붙는 자산 열. 자산이 없어도 수집된 값(감지)이 채워진다."""
        host = self._hosts.get(host_id)
        hw = host.hw if host else None
        aid = self._of_host.get(host_id)
        asset = self._asset_by_id.get(aid) if aid else None
        pid, pno, plabel = self._parent(asset)
        detected_kind = hw.kind if hw else "unknown"
        return {
            "asset_id": asset["id"] if asset else None,
            "asset_no": asset["asset_no"] if asset else None,
            "kind": asset["kind"] if asset else detected_kind,
            "kind_source": "asset" if asset else "detected",
            "virt": hw.virt if hw else "",
            "domain": (asset.get("domain") if asset else "") or (hw.domain if hw else ""),
            "serial": (asset.get("serial") if asset else "") or (hw.serial if hw else ""),
            "parent_asset_id": pid, "parent_asset_no": pno, "parent_hostname": plabel,
            "match_by": self._link[aid][1] if asset else None,
            "flags": self._flags(asset, host) if asset and host else [],
        }

    # --- 통합 목록·요약 ---------------------------------------------------
    def rows(self) -> list[dict[str, Any]]:
        vm_count: dict[int, int] = {}
        for a in self._assets:
            if a.get("parent_asset_id"):
                vm_count[a["parent_asset_id"]] = vm_count.get(a["parent_asset_id"], 0) + 1
        out: list[dict[str, Any]] = []
        for a in self._assets:
            link = self._link.get(a["id"])
            host = self._hosts[link[0]] if link else None
            view = self.host_view(link[0]) if link else None
            pid, pno, plabel = self._parent(a)
            hw = host.hw if host else None
            out.append({
                "status": "linked" if link else "uncollected", "asset": a,
                "host_id": link[0] if link else None, "hostname": host.hostname if host else (a.get("hostname") or ""),
                "kind": a["kind"], "kind_source": "asset", "virt": hw.virt if hw else "",
                "domain": a.get("domain") or (hw.domain if hw else ""), "serial": a.get("serial") or (hw.serial if hw else ""),
                "ip": a.get("ip") or (sorted(host.ips)[0] if host and host.ips else ""), "ips": sorted(host.ips) if host else [],
                "match_by": link[1] if link else None, "flags": view["flags"] if view else [],
                "parent_asset_id": pid, "parent_asset_no": pno, "parent_hostname": plabel, "vm_count": vm_count.get(a["id"], 0),
            })
        for host in self._hosts.values():
            if host.host_id in self._of_host:
                continue
            view = self.host_view(host.host_id)
            out.append({
                "status": "unregistered", "asset": None, "host_id": host.host_id, "hostname": host.hostname,
                "kind": view["kind"], "kind_source": "detected", "virt": view["virt"], "domain": view["domain"],
                "serial": view["serial"], "ip": sorted(host.ips)[0] if host.ips else "", "ips": sorted(host.ips),
                "match_by": None, "flags": [], "parent_asset_id": None, "parent_asset_no": None, "parent_hostname": None, "vm_count": 0,
            })
        return out

    def summary(self) -> dict[str, int]:
        rows = self.rows()
        count = lambda pred: sum(1 for r in rows if pred(r))  # noqa: E731
        return {
            "assets": len(self._assets),
            "linked": count(lambda r: r["status"] == "linked"),
            "uncollected": count(lambda r: r["status"] == "uncollected"),
            "unregistered": count(lambda r: r["status"] == "unregistered"),
            "physical": count(lambda r: r["kind"] == "physical"),
            "virtual": count(lambda r: r["kind"] == "virtual"),
            "kind_mismatch": count(lambda r: "kind_mismatch" in r["flags"]),
            "ip_mismatch": count(lambda r: "ip_mismatch" in r["flags"]),
            "serial_mismatch": count(lambda r: "serial_mismatch" in r["flags"]),
        }
