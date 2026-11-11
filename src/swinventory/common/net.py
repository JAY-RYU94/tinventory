"""IP·바인딩 주소 헬퍼(agent·server 공유, 표준 라이브러리만)."""
from __future__ import annotations

import ipaddress


def ip_of(address: str) -> str:
    """'10.0.0.5/24' → '10.0.0.5'."""
    return address.split("/", 1)[0]


def bind_exposure(bind: str) -> str:
    """바인딩 주소 기준 노출 범위. any=모든 인터페이스(0.0.0.0/::/*), loopback=이 호스트에서만, specific=특정 주소.

    주의: 방화벽 규칙은 알 수 없다 — 'any'/'specific' 은 외부에서 접근 가능한 후보일 뿐 실제 도달 가능성은 아니다.
    """
    if bind == "*":
        return "any"
    try:
        ip = ipaddress.ip_address(bind)
    except ValueError:
        return "specific"
    if ip.is_unspecified:
        return "any"
    return "loopback" if ip.is_loopback else "specific"
