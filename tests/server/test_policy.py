import pytest
from fastapi.testclient import TestClient

from swinventory.server.app import ApiSettings, create_app
from swinventory.server.policy import KernelPolicy, KernelRule, PolicyError
from tests.server.conftest import T0, dpkg, make_snapshot

ING, RD, AD = ({"Authorization": f"Bearer {t}"} for t in ("ing", "rd", "adm"))


# --- 정책 단위 ------------------------------------------------------------

def test_min_for_prefers_specific_family_over_wildcard():
    p = KernelPolicy([KernelRule("*", "4.0"), KernelRule("debian", "5.15.0-100")])
    assert p.min_for("debian") == "5.15.0-100" and p.min_for("rhel") == "4.0" and p.min_for("windows") == "4.0"
    assert KernelPolicy([KernelRule("rhel", "5.14")]).min_for("debian") is None


@pytest.mark.parametrize("running,compliant", [
    ("5.15.0-91-generic", False), ("5.15.0-99-generic", False),
    ("5.15.0-100-generic", True), ("5.15.0-105-generic", True), ("6.5.0-35-generic", True),
])
def test_numeric_not_lexicographic_comparison(running, compliant):
    assert KernelPolicy([KernelRule("debian", "5.15.0-100")]).evaluate("debian", running) == ("5.15.0-100", compliant)


def test_rhel_and_windows_versions():
    p = KernelPolicy([KernelRule("rhel", "5.14.0-427"), KernelRule("windows", "10.0.22631.3155")])
    assert p.evaluate("rhel", "5.14.0-362.8.1.el9_3.x86_64")[1] is False
    assert p.evaluate("rhel", "5.14.0-503.14.1.el9_5.x86_64")[1] is True
    assert p.evaluate("windows", "10.0.22631.3085")[1] is False
    assert p.evaluate("windows", "10.0.22631.3155")[1] is True


def test_no_rule_or_no_kernel_means_not_evaluated():
    p = KernelPolicy([KernelRule("debian", "5.15")])
    assert p.evaluate("rhel", "5.14.0") == (None, None)
    assert p.evaluate("debian", None) == ("5.15", None)
    assert not KernelPolicy().active and p.active


@pytest.mark.parametrize("rules", [
    [{"os_family": "debian", "min_kernel": "5.15"}, {"os_family": "debian", "min_kernel": "5.16"}],  # 중복
    [{"os_family": "freebsd", "min_kernel": "13"}],
    [{"os_family": "debian", "min_kernel": ""}],
    [{"os_family": "debian", "min_kernel": "abc"}],            # 숫자가 없는 버전
    [{"os_family": "debian", "min_kernel": "5" * 200}],
    [{"os_family": "debian"}],
])
def test_invalid_rules_rejected(rules):
    with pytest.raises(PolicyError):
        KernelPolicy.from_dicts(rules)


def test_json_roundtrip_and_corrupt_storage_is_empty_policy():
    p = KernelPolicy.from_dicts([{"os_family": "rhel", "min_kernel": " 5.14.0-427 "}])
    assert KernelPolicy.from_json(p.to_json()).rules == (KernelRule("rhel", "5.14.0-427"),)
    assert not KernelPolicy.from_json("{broken").active and not KernelPolicy.from_json(None).active


# --- API ------------------------------------------------------------------

@pytest.fixture
def client(repo, clock):
    s = ApiSettings(ingest_tokens=("ing",), read_tokens=("rd",), admin_tokens=("adm",))
    return TestClient(create_app(repo, s, clock=clock))


def push(client, **kw):
    r = client.post("/v1/ingest", json=make_snapshot(**kw).to_dict(), headers=ING)
    assert r.status_code == 200, r.text


def set_policy(client, rules):
    r = client.put("/v1/settings/kernel-policy", json={"rules": rules}, headers=AD)
    assert r.status_code == 200, r.text


def seed(client):
    push(client, host_id="old", hostname="old01", kernel="5.15.0-91-generic")
    push(client, host_id="ok", hostname="ok01", kernel="5.15.0-105-generic")
    push(client, host_id="rh", hostname="rh01", kernel="5.14.0-362.8.1.el9_3.x86_64", os_family="rhel", sources=("rpm",))
    push(client, host_id="nokern", hostname="nk01", kernel=None)


def test_policy_roundtrip_and_permissions(client):
    assert client.get("/v1/settings/kernel-policy", headers=RD).json() == {"rules": []}
    rules = [{"os_family": "debian", "min_kernel": "5.15.0-100"}, {"os_family": "rhel", "min_kernel": "5.14.0-427"}]
    assert client.put("/v1/settings/kernel-policy", json={"rules": rules}, headers=RD).status_code == 403
    assert client.put("/v1/settings/kernel-policy", json={"rules": rules}).status_code == 401
    set_policy(client, rules)
    assert client.get("/v1/settings/kernel-policy", headers=RD).json() == {"rules": rules}
    set_policy(client, [])
    assert client.get("/v1/settings/kernel-policy", headers=RD).json() == {"rules": []}


def test_invalid_policy_is_422_and_leaves_previous_policy(client):
    set_policy(client, [{"os_family": "debian", "min_kernel": "5.15"}])
    r = client.put("/v1/settings/kernel-policy", json={"rules": [{"os_family": "x", "min_kernel": "1"}]}, headers=AD)
    assert r.status_code == 422
    assert client.get("/v1/settings/kernel-policy", headers=RD).json()["rules"][0]["min_kernel"] == "5.15"


def test_kernel_hosts_compliance_and_filter(client):
    seed(client)
    rows = {r["host_id"]: r for r in client.get("/v1/kernels/hosts", headers=RD).json()}
    assert all(r["compliant"] is None and r["min_kernel"] is None for r in rows.values())  # 정책 없음

    set_policy(client, [{"os_family": "debian", "min_kernel": "5.15.0-100"}, {"os_family": "rhel", "min_kernel": "5.14.0-427"}])
    rows = {r["host_id"]: r for r in client.get("/v1/kernels/hosts", headers=RD).json()}
    assert {k: v["compliant"] for k, v in rows.items()} == {"old": False, "ok": True, "rh": False}
    assert rows["old"]["min_kernel"] == "5.15.0-100" and rows["old"]["os_family"] == "debian"
    bad = client.get("/v1/kernels/hosts", params={"compliant": "false"}, headers=RD).json()
    assert sorted(r["host_id"] for r in bad) == ["old", "rh"]
    good = client.get("/v1/kernels/hosts", params={"compliant": "true"}, headers=RD).json()
    assert [r["host_id"] for r in good] == ["ok"]


def test_overview_and_hosts_expose_compliance(client):
    seed(client)
    o = client.get("/v1/overview", headers=RD).json()
    assert o["policy_active"] is False and o["noncompliant_count"] == 0
    set_policy(client, [{"os_family": "debian", "min_kernel": "5.15.0-100"}])
    o = client.get("/v1/overview", headers=RD).json()
    assert o["policy_active"] is True and o["noncompliant_count"] == 1
    hosts = {h["host_id"]: h for h in client.get("/v1/hosts", headers=RD).json()}
    assert hosts["old"]["kernel_compliant"] is False and hosts["ok"]["kernel_compliant"] is True
    assert hosts["rh"]["kernel_compliant"] is None            # rhel 규칙 없음
    detail = client.get("/v1/hosts/old", headers=RD).json()
    assert detail["kernel"]["min_kernel"] == "5.15.0-100" and detail["kernel"]["compliant"] is False


def test_policy_change_applies_immediately_without_new_snapshots(client):
    seed(client)
    set_policy(client, [{"os_family": "debian", "min_kernel": "5.15.0-100"}])
    assert client.get("/v1/overview", headers=RD).json()["noncompliant_count"] == 1
    set_policy(client, [{"os_family": "debian", "min_kernel": "5.15.0-91"}])   # 하한선을 낮추면 바로 준수
    assert client.get("/v1/overview", headers=RD).json()["noncompliant_count"] == 0


def test_csv_has_compliance_columns(client):
    import csv, io

    seed(client)
    set_policy(client, [{"os_family": "debian", "min_kernel": "5.15.0-100"}])
    r = client.get("/v1/kernels/hosts", params={"format": "csv"}, headers=RD)
    rows = {x["host_id"]: x for x in csv.DictReader(io.StringIO(r.content.decode("utf-8-sig")))}
    assert rows["old"]["compliant"] == "false" and rows["old"]["min_kernel"] == "5.15.0-100"
    assert rows["ok"]["compliant"] == "true" and rows["rh"]["compliant"] == ""
