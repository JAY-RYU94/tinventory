"""포트 번호 → 서비스 이름(표시용)과 '주의 포트'(바인딩이 루프백이 아닐 때 눈여겨볼 관리·데이터·평문 프로토콜)."""
from __future__ import annotations

SERVICE_NAMES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog/rsh", 587: "submission", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker-api", 2376: "docker-api-tls", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 5000: "http-alt", 5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9090: "http-alt", 9200: "elasticsearch",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
}

# (proto, port) → 이유. 방화벽 규칙을 알 수 없으므로 '노출 확정'이 아니라 '확인 후보'다.
NOTABLE_PORTS: dict[tuple[str, int], str] = {
    ("tcp", 21): "평문 FTP", ("tcp", 23): "평문 Telnet", ("udp", 69): "TFTP(인증 없음)", ("tcp", 135): "Windows RPC",
    ("tcp", 139): "NetBIOS", ("tcp", 445): "SMB", ("tcp", 514): "r-서비스(rsh)", ("udp", 161): "SNMP",
    ("tcp", 1433): "MSSQL", ("tcp", 1521): "Oracle", ("tcp", 2049): "NFS", ("tcp", 2375): "Docker API(평문)",
    ("tcp", 3306): "MySQL", ("tcp", 3389): "RDP", ("tcp", 5432): "PostgreSQL", ("tcp", 5900): "VNC",
    ("tcp", 5984): "CouchDB", ("tcp", 6379): "Redis", ("tcp", 9200): "Elasticsearch", ("tcp", 11211): "Memcached",
    ("udp", 11211): "Memcached", ("tcp", 27017): "MongoDB",
}


def service_name(port: int) -> str:
    return SERVICE_NAMES.get(port, "")


def notable_reason(proto: str, port: int) -> str:
    return NOTABLE_PORTS.get((proto, port), "")
