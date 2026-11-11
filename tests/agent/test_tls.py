"""실제 TLS 경로: 사설 CA(ca_file), 호스트명 검증, mTLS(client_cert/client_key).

openssl 로 CA·서버·클라이언트 인증서를 만들어 진짜 HTTPS 서버에 붙는다. openssl 이 없으면 건너뛴다.
"""
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from swinventory.agent.transport.base import PermanentTransportError, SendOutcome, TransportError
from swinventory.agent.transport.http import HttpsTransport, UrllibPoster
from swinventory.common.models import Snapshot

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl 필요")

SNAP = Snapshot(host_id="h", hostname="web01", collected_at="2026-11-05T00:00:00+00:00",
                agent_version="0.1.0", collected=["os"])


def sh(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """Python 3.13+ 는 VERIFY_X509_STRICT 가 기본이라 CA 에 basicConstraints/keyUsage, 하위 인증서에 AKI 가 있어야 한다."""
    d = tmp_path_factory.mktemp("pki")
    (d / "ca.cnf").write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n[dn]\nCN=test-ca\n"
        "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n")
    # 'localhost' 는 SAN 에서 일부러 뺀다(호스트명 검증이 꺼져 있지 않은지 확인하기 위해)
    (d / "server.ext").write_text(
        "subjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n")
    (d / "client.ext").write_text(
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
        "authorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n")
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
       "-days", "2", "-config", "ca.cnf", cwd=d)
    for name in ("server", "client"):
        sh("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
           "-subj", f"/CN={name}", cwd=d)
        sh("openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
           "-CAcreateserial", "-out", f"{name}.pem", "-days", "2", "-extfile", f"{name}.ext", cwd=d)
    return d


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def serve(pki, require_client_cert):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki / "server.pem", pki / "server.key")
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(pki / "ca.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def tls_server(pki):
    srv = serve(pki, require_client_cert=False)
    yield f"https://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def mtls_server(pki):
    srv = serve(pki, require_client_cert=True)
    yield f"https://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


def transport(url, **poster_kw):
    return HttpsTransport(url, "secret-token", UrllibPoster(**poster_kw), timeout=5)


def test_private_ca_is_trusted_via_ca_file(tls_server, pki):
    assert transport(tls_server, ca_file=str(pki / "ca.pem")).send(SNAP) is SendOutcome.SENT


def test_unknown_ca_is_rejected_as_retryable_error(tls_server):
    with pytest.raises(TransportError) as ei:
        transport(tls_server).send(SNAP)  # 시스템 CA 에 없는 사설 CA
    assert not isinstance(ei.value, PermanentTransportError)
    assert "secret-token" not in str(ei.value)


def test_hostname_verification_is_not_disabled(tls_server, pki):
    port = tls_server.rsplit(":", 1)[1]
    with pytest.raises(TransportError) as ei:  # 인증서 SAN 은 IP:127.0.0.1 뿐이라 'localhost' 는 불일치
        transport(f"https://localhost:{port}", ca_file=str(pki / "ca.pem")).send(SNAP)
    assert "hostname" in str(ei.value).lower() or "verify" in str(ei.value).lower()


def test_mtls_with_client_cert_succeeds(mtls_server, pki):
    t = transport(mtls_server, ca_file=str(pki / "ca.pem"),
                  client_cert=str(pki / "client.pem"), client_key=str(pki / "client.key"))
    assert t.send(SNAP) is SendOutcome.SENT


def test_mtls_without_client_cert_is_rejected(mtls_server, pki):
    with pytest.raises(TransportError):
        transport(mtls_server, ca_file=str(pki / "ca.pem")).send(SNAP)


def test_bad_client_cert_path_fails_at_construction(pki):
    """설정 오류는 CLI 가 exit 2 로 보고할 수 있게 생성 시점에 드러나야 한다."""
    with pytest.raises(OSError):
        UrllibPoster(ca_file=str(pki / "ca.pem"), client_cert="/nonexistent/c.pem", client_key="/nonexistent/c.key")
