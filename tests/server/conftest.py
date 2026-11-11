import os
from datetime import datetime, timedelta, timezone

import pytest

from swinventory.common.models import ContainerRecord, HardwareInfo, K8sNodeInfo, KernelInfo, ListeningPort, NetworkInterface, OsInfo, PackageRecord, Snapshot
from swinventory.server.repo.sql import SqlInventoryRepository
from swinventory.server.services.ingest import IngestService

T0 = datetime(2026, 11, 5, 0, 0, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)


@pytest.fixture
def clock():
    return Clock()


TEST_DB_URL = os.environ.get("SWINV_TEST_DB_URL")  # 예: postgresql+psycopg://u:p@127.0.0.1:55432/swinv_test


@pytest.fixture
def repo():
    """기본은 SQLite 인메모리. SWINV_TEST_DB_URL 이 있으면 그 DB(PostgreSQL 등)로 같은 테스트를 돌린다."""
    if not TEST_DB_URL:
        yield SqlInventoryRepository.from_url("sqlite://")
        return
    from sqlalchemy.engine import make_url

    # 매 테스트마다 모든 테이블을 DROP 하므로 운영 DB 를 가리키면 치명적이다 — 이름에 test 가 없으면 거부.
    if "test" not in (make_url(TEST_DB_URL).database or "").lower():
        pytest.exit(f"SWINV_TEST_DB_URL 의 DB 이름에 'test' 가 있어야 한다: {TEST_DB_URL}", returncode=2)
    from swinventory.server.repo.schema import metadata

    r = SqlInventoryRepository.from_url(TEST_DB_URL)
    metadata.drop_all(r._engine)
    metadata.create_all(r._engine)
    yield r
    r._engine.dispose()


@pytest.fixture
def service(repo, clock):
    return IngestService(repo, clock=clock)


def make_snapshot(*, host_id="h1", at=T0, packages=(), sources=("dpkg",), kernel="5.15-91",
                  installed=None, reboot=False, errors=None, collected=None, os_=True,
                  hostname="web01", os_family="debian", interfaces=None, ports=None, hardware=None, containers=None, k8s=None) -> Snapshot:
    if collected is None:
        collected = ["os", "kernel", *[f"software.{s}" for s in sources]]
        # interfaces/ports 를 넘기면 그 수집기가 성공한 것으로 본다(빈 목록도 '성공, 없음'이다). None 이면 수집 안 함.
        collected += (["network.interfaces"] if interfaces is not None else []) + (["network.ports"] if ports is not None else [])
        collected += ["hardware"] if hardware is not None else []
        collected += ["containers"] if containers is not None else []
    inst = tuple(installed) if installed is not None else (kernel,)
    return Snapshot(
        host_id=host_id, hostname=hostname, collected_at=at.isoformat(), agent_version="0.1.0",
        os=OsInfo(os_family, "Ubuntu 22.04" if os_family == "debian" else "Rocky Linux 9.4", "22.04") if os_ else None,
        kernel=KernelInfo(kernel, inst, reboot) if kernel else None,
        packages=list(packages), interfaces=list(interfaces or []), ports=list(ports or []), hardware=hardware, containers=list(containers or []), k8s=k8s,
        collected=list(collected), errors=dict(errors or {}),
    )


def dpkg(name, version, arch="amd64"):
    return PackageRecord("dpkg", name, version, arch)


def rpm(name, version, arch="x86_64"):
    return PackageRecord("rpm", name, version, arch)


def iface(name="eth0", mac="02:42:ac:11:00:02", addresses=("10.0.0.5/24",), state="up"):
    return NetworkInterface(name, mac, state, tuple(addresses))


def port(proto, number, bind="0.0.0.0"):
    return ListeningPort(proto, number, bind)


def hw(kind="physical", serial="", fqdn="", virt="", vendor="Dell Inc.", model="PowerEdge R740"):
    from swinventory.common.hardware import domain_of
    return HardwareInfo(kind, virt, vendor, model, serial, fqdn, domain_of(fqdn))


def ctr(name="app", image="nginx:1.25", *, cid=None, state="running", pod="", namespace="", runtime="containerd", digest=""):
    return ContainerRecord(runtime, cid or (name + "-" + image).replace(":", "")[:12].ljust(12, "0"), name, image,
                           "sha256:" + "c" * 64, digest, state, "2026-11-06T10:00:00+00:00", pod, namespace)


def k8s(cluster="a" * 64, api="https://10.0.0.1:6443", version="v1.29.3", runtime="containerd"):
    return K8sNodeInfo(cluster, api, version, runtime)
