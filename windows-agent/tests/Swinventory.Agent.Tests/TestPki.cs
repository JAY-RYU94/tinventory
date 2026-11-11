using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Swinventory.Agent.Tests;

/// <summary>테스트용 사설 PKI(CA·서버·클라이언트)와 SslStream 기반 최소 HTTPS 서버.</summary>
internal sealed class TestPki : IDisposable
{
    public string Dir { get; } = Fx.TempDir();
    public string CaPem => Path.Combine(Dir, "ca.pem");
    public string ClientPem => Path.Combine(Dir, "client.pem");
    public string ClientKey => Path.Combine(Dir, "client.key");
    public X509Certificate2 Server { get; }
    private readonly X509Certificate2 _ca;

    public TestPki()
    {
        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=test-ca", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        _ca = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        File.WriteAllText(CaPem, _ca.ExportCertificatePem());

        Server = Issue("CN=server", serverAuth: true, san: sb => sb.AddIpAddress(IPAddress.Loopback), keyOut: null);      // SAN 은 IP 127.0.0.1 만(localhost 없음)
        var clientCert = Issue("CN=client", serverAuth: false, san: null, keyOut: ClientKey);
        File.WriteAllText(ClientPem, clientCert.ExportCertificatePem());
    }

    private X509Certificate2 Issue(string subject, bool serverAuth, Action<SubjectAlternativeNameBuilder>? san, string? keyOut)
    {
        var key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
            { new(serverAuth ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        if (san is not null)
        {
            var sb = new SubjectAlternativeNameBuilder();
            san(sb);
            req.CertificateExtensions.Add(sb.Build());
        }
        using var issued = req.Create(_ca.CopyWithPrivateKeyIfNeeded(), DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(8));
        if (keyOut is not null) File.WriteAllText(keyOut, key.ExportPkcs8PrivateKeyPem());
        return issued.CopyWithPrivateKey(key);
    }

    public HttpsServer Serve(bool requireClientCert) => new(Server, _ca, requireClientCert);

    public void Dispose()
    {
        Server.Dispose();
        _ca.Dispose();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}

internal static class PkiExtensions
{
    // CA 개인키는 자체서명 생성 시 핸들이 닫히므로 서명용으로 다시 만들지 않고 CA 인증서가 키를 들고 있게 한다.
    public static X509Certificate2 CopyWithPrivateKeyIfNeeded(this X509Certificate2 ca) => ca;
}

internal sealed class HttpsServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly Thread _thread;
    private volatile bool _stop;
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public int Handled;

    public HttpsServer(X509Certificate2 cert, X509Certificate2 ca, bool requireClientCert)
    {
        _listener.Start();
        _thread = new Thread(() =>
        {
            while (!_stop)
            {
                try { Handle(_listener.AcceptTcpClient(), cert, ca, requireClientCert); }
                catch (Exception) when (_stop) { return; }
                catch (Exception) { /* 핸드셰이크 실패 등 — 다음 연결로 */ }
            }
        }) { IsBackground = true };
        _thread.Start();
    }

    private void Handle(TcpClient tcp, X509Certificate2 cert, X509Certificate2 ca, bool requireClientCert)
    {
        using (tcp)
        using (var ssl = new SslStream(tcp.GetStream(), false, (_, c, chain, _) =>
               {
                   if (!requireClientCert) return true;
                   if (c is null) return false;
                   using var ch = new X509Chain();
                   ch.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                   ch.ChainPolicy.CustomTrustStore.Add(ca);
                   ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                   return ch.Build(new X509Certificate2(c));
               }))
        {
            ssl.AuthenticateAsServer(cert, requireClientCert, false);
            var buf = new List<byte>();
            var one = new byte[1];
            while (!(buf.Count >= 4 && buf[^4] == '\r' && buf[^3] == '\n' && buf[^2] == '\r' && buf[^1] == '\n'))
            {
                if (ssl.Read(one, 0, 1) == 0) return;
                buf.Add(one[0]);
            }
            var head = Encoding.ASCII.GetString(buf.ToArray());
            var len = head.Split("\r\n").Where(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                .Select(l => int.Parse(l.Split(':')[1].Trim())).FirstOrDefault();
            var body = new byte[len];
            for (var read = 0; read < len;) { var n = ssl.Read(body, read, len - read); if (n == 0) break; read += n; }
            Interlocked.Increment(ref Handled);
            ssl.Write(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"));
            ssl.Flush();
        }
    }

    public void Dispose()
    {
        _stop = true;
        _listener.Stop();
    }
}
