#!/usr/bin/env python3
"""데모/화면 검증용 가상 인벤토리를 DB 에 적재한다(에이전트 없이 서버 적재 경로를 그대로 탄다).

    python3 scripts/seed_demo.py --db sqlite:///demo.db
    SWINV_DB_URL=sqlite:///demo.db SWINV_READ_TOKENS=r uvicorn swinventory.server.main:create_app_from_env --factory

호스트 28대(장비 정보·자산 대장·쿠버네티스 노드 2개 클러스터·도커 서버 포함): 커널 분포, 재부팅 필요, 수집 오류, 수집 끊김, IP·MAC·열린 포트(IP 충돌·노출 포트 포함), 두 회차의 변경 이력, 태그, 그리고
화면이 에이전트 입력을 안전하게 그리는지 보기 위한 XSS 호스트명 1대를 만든다.
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone

from swinventory.common.models import ContainerRecord, HardwareInfo, K8sNodeInfo, KernelInfo, ListeningPort, NetworkInterface, OsInfo, PackageRecord, Snapshot
from swinventory.server.repo.sql import SqlInventoryRepository
from swinventory.server.services.ingest import IngestService

DEB_PKGS = ["bash", "openssl", "libssl3", "curl", "nginx", "python3", "git", "vim", "sudo", "openssh-server",
            "systemd", "libc6", "zlib1g", "tar", "gzip", "rsyslog", "cron", "postgresql-client-14"]
RPM_PKGS = ["bash", "openssl", "openssl-libs", "curl", "nginx", "python3", "git", "vim-minimal", "sudo",
            "openssh-server", "systemd", "glibc", "zlib", "tar", "gzip", "rsyslog", "cronie"]
VERSIONS = {"openssl": ["3.0.2", "3.0.11", "3.0.13"], "nginx": ["1.18.0", "1.24.0"], "curl": ["7.81.0", "8.5.0"],
            "sudo": ["1.9.9", "1.9.15"], "python3": ["3.10.12", "3.11.2"]}
DEB_KERNELS = ["5.15.0-91-generic", "5.15.0-100-generic", "5.15.0-105-generic", "6.5.0-35-generic"]
RPM_KERNELS = ["5.14.0-362.8.1.el9_3.x86_64", "5.14.0-427.13.1.el9_4.x86_64", "5.14.0-503.14.1.el9_5.x86_64"]


def pick_version(rng: random.Random, name: str) -> str:
    return rng.choice(VERSIONS.get(name, ["1.0.0", "1.1.0"]))


def network_for(idx: int, family: str, round_no: int, xss: bool):
    """호스트별 IP·MAC·열린 포트. 충돌(idx 9 가 idx 8 과 같은 IP)과 노출 포트, 2회차 변경을 섞는다."""
    ip = f"10.20.0.{idx + 10}"
    if idx == 9:
        ip = "10.20.0.18"                                   # idx 8 과 같은 IP → 충돌
    mac = f"aa:bb:cc:00:00:{idx:02x}"
    if round_no == 1:
        if idx == 4:
            ip = "10.20.0.200"                              # IP 변경
        if idx == 6:
            mac = "aa:bb:cc:99:99:99"                       # MAC 변경(NIC 교체)
    name = '<img src=x onerror=alert(1)>' if xss else "eth0"
    ifaces = [NetworkInterface(name, mac, "up", (f"{ip}/24",)), NetworkInterface("eth1", f"aa:bb:dd:00:00:{idx:02x}", "down", ())]
    ports = [ListeningPort("tcp", 22, "0.0.0.0"), ListeningPort("tcp", 22, "::"), ListeningPort("udp", 123, "0.0.0.0")]
    if idx % 4 in (0, 1):
        ports += [ListeningPort("tcp", 80, "0.0.0.0"), ListeningPort("tcp", 443, "0.0.0.0")]
    if idx % 4 == 2:
        ports += [ListeningPort("tcp", 5432, "127.0.0.1" if idx % 8 == 2 else ip)]     # DB: 일부는 로컬 전용, 일부는 사내 주소로 노출
    if idx in (3, 11):
        ports.append(ListeningPort("tcp", 23, "0.0.0.0"))                              # telnet
    if idx == 7:
        ports.append(ListeningPort("tcp", 6379, "0.0.0.0"))                            # redis
    if round_no == 1:
        if idx % 6 == 0:
            ports.append(ListeningPort("tcp", 8080, "0.0.0.0"))                        # 새로 열림
        if idx == 8:
            ports = [p for p in ports if p.port != 443]                                # 닫힘
    return ifaces, sorted(set(ports), key=lambda p: (p.proto, p.port, p.bind))


def hardware_for(idx: int, hostname: str) -> HardwareInfo | None:
    """idx%5==0 은 물리 서버, idx==13 은 장비 정보를 못 읽은 호스트(옛 에이전트), 나머지는 VMware VM."""
    if idx == 13:
        return None
    fqdn = hostname if not hostname.startswith("<") else ""     # 호스트명이 이미 FQDN(*.corp.example)
    if idx % 5 == 0:
        return HardwareInfo("physical", "", "Dell Inc.", "PowerEdge R740", f"SN{idx:05d}X", fqdn, "corp.example")
    return HardwareInfo("virtual", "vmware", "VMware, Inc.", "VMware7,1", f"VMware-56 4d {idx:02x} 7e", fqdn, "corp.example")


CLUSTER_A, CLUSTER_B = "a1" * 32, "b2" * 32


def containers_for(idx: int, round_no: int, xss: bool):
    """idx%4==0 → 운영 클러스터(A) 노드, idx%4==1 → 개발 클러스터(B) 노드, idx%6==2 → 일반 도커 서버. 2회차에는 일부 이미지 태그가 바뀐다."""
    def rec(runtime, name, image, state="running", pod="", namespace=""):
        cid = f"{idx:02x}{abs(hash((name, pod))) % 10**10:010x}"[:12]
        return ContainerRecord(runtime, cid, name, image, "sha256:" + "ab" * 32, "", state, "2026-11-05T09:00:00+00:00", pod, namespace)
    if idx % 4 in (0, 1):
        cluster = CLUSTER_A if idx % 4 == 0 else CLUSTER_B
        web = "nginx:1.25" if round_no == 0 or idx % 8 not in (0, 1) else "nginx:1.26"     # 일부 노드만 2회차에 롤아웃
        pod = f"web-{idx:02d}" if not xss else "<img src=x onerror=alert(1)>"
        items = [rec("containerd", "web", web, pod=pod, namespace="prod" if cluster == CLUSTER_A else "dev"),
                 rec("containerd", "coredns", "registry.k8s.io/coredns/coredns:v1.11.1", pod=f"coredns-{idx:02d}", namespace="kube-system"),
                 rec("containerd", "migrate", "team/migrate:0.9", state="exited", pod=f"migrate-{idx:02d}", namespace="prod")]
        if idx % 4 == 0:
            items.append(rec("containerd", "api", "team/api:2.0" if idx % 8 else "team/api:2.1", pod=f"api-{idx:02d}", namespace="prod"))
        k8s = K8sNodeInfo(cluster, "https://k8s-a.corp.example:6443" if cluster == CLUSTER_A else "https://k8s-b.corp.example:6443",
                          "v1.29.3" if idx % 8 else "v1.29.4", "containerd")
        return items, k8s
    if idx % 6 == 2:
        return [rec("docker", "postgres", "postgres:16"), rec("docker", "redis", "redis:7"), rec("docker", "legacy", "alpine:3.18", state="exited")], None
    return None, None


def make_snapshot(rng, host_id, hostname, family, at, *, kernel_idx, newest_idx, errors=None, bump=False,
                  idx=0, round_no=0, xss=False):
    kernels = DEB_KERNELS if family == "debian" else RPM_KERNELS
    source, names = ("dpkg", DEB_PKGS) if family == "debian" else ("rpm", RPM_PKGS)
    pkg_rng = random.Random(host_id)  # 호스트마다 고정된 구성
    pkgs = [PackageRecord(source, n, pick_version(pkg_rng, n), "amd64" if family == "debian" else "x86_64") for n in names]
    if bump:  # 두 번째 회차: 일부 패키지 버전이 바뀌고 하나가 새로 설치된다
        pkgs = [PackageRecord(p.source, p.name, "9.9.9" if p.name in ("openssl", "curl") else p.version, p.arch) for p in pkgs]
        pkgs.append(PackageRecord(source, "htop", "3.2.2", pkgs[0].arch))
    if family == "rhel":  # 다중 버전 공존: kernel-core 는 항상 설치된 커널 수만큼 있다
        pkgs += [PackageRecord("rpm", "kernel-core", k.rsplit(".", 1)[0], "x86_64") for k in kernels[: newest_idx + 1]]
    installed = tuple(kernels[: newest_idx + 1])
    running = kernels[kernel_idx]
    collected = ["os", "kernel", f"software.{source}", "network.interfaces", "network.ports"]
    hardware = hardware_for(idx, hostname)
    if hardware is not None:
        collected.append("hardware")
    containers, k8s = containers_for(idx, round_no, xss)
    if containers is not None:
        collected.append("containers")
    ifaces, ports = network_for(idx, family, round_no, xss)
    if errors:
        collected.remove(f"software.{source}")
        pkgs = []
    return Snapshot(
        host_id=host_id, hostname=hostname, collected_at=at.isoformat(), agent_version="0.1.0",
        os=OsInfo(family, "Ubuntu 22.04.4 LTS" if family == "debian" else "Rocky Linux 9.4 (Blue Onyx)",
                  "22.04" if family == "debian" else "9.4"),
        kernel=KernelInfo(running, installed, kernel_idx < newest_idx),
        packages=pkgs, interfaces=ifaces, ports=ports, hardware=hardware, containers=containers or [], k8s=k8s, collected=collected, errors=errors or {})


def seed(db_url: str, now: datetime) -> int:
    rng = random.Random(42)
    repo = SqlInventoryRepository.from_url(db_url)
    clock = {"now": now}
    service = IngestService(repo, clock=lambda: clock["now"])
    teams, envs = ["infra", "payments", "data", "web"], ["prod", "stage", "dev"]
    hosts = []
    for i in range(1, 29):
        family = "debian" if i % 3 else "rhel"
        prefix = ["web", "api", "db", "batch"][i % 4]
        hosts.append((f"{i:032x}", f"{prefix}{i:02d}.corp.example", family))
    hosts[5] = (hosts[5][0], '<img src=x onerror=alert(1)>', "debian")  # XSS 페이로드: 텍스트로만 보여야 한다

    for round_no, ago in enumerate((timedelta(hours=26), timedelta(hours=1))):
        for idx, (host_id, name, family) in enumerate(hosts):
            at = now - ago
            if idx == 27 and round_no == 1:
                continue  # 마지막 호스트는 2회차부터 수집이 끊긴다
            newest = len(DEB_KERNELS if family == "debian" else RPM_KERNELS) - 1
            kernel_idx = rng.choice(range(newest + 1)) if round_no == 0 else None
            if round_no == 1:  # 일부는 재부팅해서 커널이 바뀌고, 일부는 새 커널만 깔린 채 재부팅 미적용
                prev = seed.running.get(host_id, 0)
                kernel_idx = newest if idx % 5 == 0 else prev
            seed.running[host_id] = kernel_idx
            errors = {f"software.{'dpkg' if family == 'debian' else 'rpm'}": "CommandError: dpkg-query exited 2: database locked"} if idx in (3, 11) and round_no == 1 else None
            clock["now"] = at
            service.ingest(make_snapshot(rng, host_id, name, family, at, kernel_idx=kernel_idx, newest_idx=newest, errors=errors,
                                         bump=round_no == 1 and idx % 4 == 0, idx=idx, round_no=round_no, xss=idx == 5))
    clock["now"] = now
    for idx, (host_id, *_rest) in enumerate(hosts):
        repo.set_tags(host_id, {"team": teams[idx % 4], "env": envs[idx % 3]})
    seed_assets(repo, hosts, now)
    return len(hosts)


def seed_assets(repo, hosts, now: datetime) -> None:
    """자산 대장: 시리얼·호스트명·명시 연결로 연결되는 장비, 수집 안 된 자산, 대장과 수집값이 다른 자산, 미등록 호스트를 섞는다."""
    at = now.isoformat()
    parents: dict[int, int] = {}
    for idx in (0, 5, 10, 15):                       # 물리 서버: 시리얼로 연결(대장 시리얼은 소문자·공백 차이를 둔다)
        host_id, name, _ = hosts[idx]
        parents[idx] = repo.create_asset({"asset_no": f"P-{1000 + idx}", "kind": "physical", "serial": f"sn{idx:05d}x",
                                          "hostname": "", "domain": "corp.example", "ip": "", "parent_asset_id": None,
                                          "host_id": None, "note": "랙 A3" if idx == 0 else ""}, at)
    for idx in (1, 2, 3, 4, 6, 7, 8, 11):            # VM: 호스트명으로 연결, 상위 물리 서버 지정
        host_id, name, _ = hosts[idx]
        repo.create_asset({"asset_no": f"V-{2000 + idx}", "kind": "virtual", "serial": "", "hostname": name.split(".")[0],
                           "domain": "corp.example", "ip": "", "parent_asset_id": parents[(0, 5, 10, 15)[idx % 4]],
                           "host_id": None, "note": ""}, at)
    host_id, name, _ = hosts[9]                      # 대장은 '물리', 수집은 VM → 구분 불일치 + IP 불일치(대장 IP 가 다름)
    repo.create_asset({"asset_no": "P-1099", "kind": "physical", "serial": "", "hostname": name.split(".")[0],
                       "domain": "", "ip": "10.99.99.99", "parent_asset_id": None, "host_id": None, "note": "이관 예정"}, at)
    repo.create_asset({"asset_no": "V-2900", "kind": "virtual", "serial": "VMWARE-RETIRED-01", "hostname": "legacy-batch",
                       "domain": "corp.example", "ip": "10.20.9.9", "parent_asset_id": parents[0], "host_id": None,
                       "note": "폐기 예정 — 에이전트 미설치"}, at)           # 수집 안 됨
    repo.create_asset({"asset_no": "P-1098", "kind": "physical", "serial": "UNPLUGGED-77", "hostname": "",
                       "domain": "", "ip": "", "parent_asset_id": None, "host_id": None, "note": "<img src=x onerror=alert(1)>"}, at)


seed.running = {}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="sqlite:///demo.db")
    args = ap.parse_args()
    print(f"{seed(args.db, datetime.now(timezone.utc))} hosts seeded into {args.db}")
