"""장비 정보의 순수 규칙(VM/물리 판정, 시리얼 정리, 도메인 추출). 에이전트·서버가 공유한다 — 표준 라이브러리만 사용."""
from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# 제조사가 채우지 않고 내보내는 자리표시자 — 시리얼로 쓰면 서로 다른 장비가 같은 값으로 묶인다
_PLACEHOLDER_SERIALS = frozenset({
    "none", "n/a", "na", "unknown", "default string", "to be filled by o.e.m.", "not specified", "not applicable",
    "system serial number", "chassis serial number", "serial number", "null", "ffffffff", "0123456789",
})
_ZEROS = re.compile(r"^[0\s-]+$")
_NORMALIZE = re.compile(r"[\s-]+")

# (정규식, virt 이름). 위에서부터 처음 맞는 것. vendor·model·bios_vendor 를 이어 붙인 문자열에 적용한다.
_VIRT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple((re.compile(p, re.I), n) for p, n in (
    (r"vmware", "vmware"),
    (r"virtualbox|innotek", "virtualbox"),
    (r"microsoft corporation.*virtual machine|hyper-v", "hyperv"),
    (r"\bxen\b|hvm domu", "xen"),
    (r"amazon ec2|\bamazon\b.*\bhvm\b", "aws"),
    (r"google compute engine|\bgoogle\b.*compute", "gcp"),
    (r"openstack", "openstack"),
    (r"parallels", "parallels"),
    (r"nutanix", "ahv"),
    (r"qemu|\bkvm\b|red hat.*kvm|bochs", "kvm"),
))


def clean_text(value: str | None) -> str:
    """제어문자를 없애고 양끝 공백을 다듬는다(DMI 문자열은 펌웨어가 채운 신뢰할 수 없는 입력)."""
    return _CONTROL.sub("", value or "").strip()


def clean_serial(value: str | None) -> str:
    text = clean_text(value)
    if not text or text.lower() in _PLACEHOLDER_SERIALS or _ZEROS.match(text):
        return ""
    return text


def normalize_serial(value: str | None) -> str:
    """시리얼 비교용 정규형(대소문자·공백·하이픈 무시). 자리표시자는 빈 값."""
    return _NORMALIZE.sub("", clean_serial(value)).upper()


def domain_of(fqdn: str | None) -> str:
    """FQDN 에서 첫 라벨을 뺀 도메인(소문자). 점이 없거나 비면 빈 값."""
    host, dot, rest = (fqdn or "").strip().rstrip(".").partition(".")      # 선행 점(호스트 라벨 없음)은 도메인이 아니다
    return rest.strip(".").lower() if dot and host else ""


def classify_virtualization(*, vendor: str = "", model: str = "", bios_vendor: str = "", hypervisor_flag: bool = False,
                            detected: str | None = None, container: str | None = None) -> tuple[str, str]:
    """(kind, virt). 우선순위: 컨테이너 > 감지 도구(systemd-detect-virt) > DMI 문자열 > CPU hypervisor 플래그.
    근거가 하나도 없으면 'unknown' — DMI 를 못 읽은 장비를 물리로 단정하지 않는다."""
    if container and container != "none":
        return "container", container
    if detected and detected != "none":
        return "virtual", detected
    haystack = f"{vendor} {model} {bios_vendor}".strip()
    for pattern, name in _VIRT_PATTERNS:
        if pattern.search(haystack):
            return "virtual", name
    if hypervisor_flag:
        return "virtual", "unknown"
    return ("physical", "") if haystack else ("unknown", "")
