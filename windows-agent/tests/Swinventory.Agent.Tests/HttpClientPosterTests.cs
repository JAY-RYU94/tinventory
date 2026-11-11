using System.Net;
using System.Net.Sockets;
using System.Text;
using Swinventory.Agent.Transport;

namespace Swinventory.Agent.Tests;

public class HttpClientPosterTests : IDisposable
{
    private readonly HttpListener _http = new();
    private readonly string _base;
    private readonly List<(string Path, string? Auth, string Body)> _seen = new();
    private readonly Thread _thread;
    private volatile bool _stop;

    public HttpClientPosterTests()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        _base = $"http://127.0.0.1:{port}";
        _http.Prefixes.Add(_base + "/");
        _http.Start();
        _thread = new Thread(() =>
        {
            while (!_stop)
            {
                HttpListenerContext ctx;
                try { ctx = _http.GetContext(); } catch (Exception) { return; }
                using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
                lock (_seen) _seen.Add((ctx.Request.Url!.AbsolutePath, ctx.Request.Headers["Authorization"], reader.ReadToEnd()));
                switch (ctx.Request.Url!.AbsolutePath)
                {
                    case "/redirect": ctx.Response.StatusCode = 302; ctx.Response.RedirectLocation = _base + "/target"; break;
                    case "/bad": ctx.Response.StatusCode = 422; Write(ctx, "invalid"); break;
                    default: ctx.Response.StatusCode = 200; Write(ctx, "ok"); break;
                }
                ctx.Response.Close();
            }
        }) { IsBackground = true };
        _thread.Start();
    }

    private static void Write(HttpListenerContext ctx, string text) { var b = Encoding.UTF8.GetBytes(text); ctx.Response.OutputStream.Write(b); }
    public void Dispose() { _stop = true; _http.Close(); }

    private static readonly IReadOnlyDictionary<string, string> Hdr = new Dictionary<string, string> { ["Authorization"] = "Bearer t", ["Content-Type"] = "application/json" };

    [Fact]
    public void Roundtrip_sends_headers_and_body_and_passes_4xx_through_as_responses()
    {
        var p = new HttpClientPoster(null, null, null);
        var r = p.Post(new Uri(_base + "/v1/ingest"), Encoding.UTF8.GetBytes("{\"a\":1}"), Hdr, TimeSpan.FromSeconds(5));
        Assert.Equal((200, "ok"), (r.Status, Encoding.UTF8.GetString(r.Body)));
        lock (_seen) Assert.Equal(("/v1/ingest", "Bearer t", "{\"a\":1}"), _seen[0]);
        Assert.Equal(422, p.Post(new Uri(_base + "/bad"), Array.Empty<byte>(), Hdr, TimeSpan.FromSeconds(5)).Status);
    }

    [Fact]
    public void Redirects_are_not_followed_so_the_bearer_token_cannot_leak_to_another_location()
    {
        var r = new HttpClientPoster(null, null, null).Post(new Uri(_base + "/redirect"), Array.Empty<byte>(), Hdr, TimeSpan.FromSeconds(5));
        Assert.Equal(302, r.Status);
        lock (_seen) Assert.DoesNotContain(_seen, s => s.Path == "/target");
    }

    [Fact]
    public void Unreachable_server_raises_an_io_style_exception()
    {
        var p = new HttpClientPoster(null, null, null);
        Assert.ThrowsAny<Exception>(() => p.Post(new Uri("http://127.0.0.1:1/x"), Array.Empty<byte>(), Hdr, TimeSpan.FromSeconds(2)));
    }

    [Fact]
    public void Timeout_is_enforced()
    {
        var slow = new TcpListener(IPAddress.Loopback, 0);          // 연결은 받지만 응답하지 않는 서버
        slow.Start();
        try
        {
            var url = new Uri($"http://127.0.0.1:{((IPEndPoint)slow.LocalEndpoint).Port}/x");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Assert.ThrowsAny<Exception>(() => new HttpClientPoster(null, null, null).Post(url, Array.Empty<byte>(), Hdr, TimeSpan.FromMilliseconds(500)));
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
        }
        finally { slow.Stop(); }
    }
}

public class TlsTests
{
    private static readonly IReadOnlyDictionary<string, string> Hdr = new Dictionary<string, string> { ["Authorization"] = "Bearer t" };

    private static int Post(string url, HttpClientPoster p) => p.Post(new Uri(url), Encoding.UTF8.GetBytes("{}"), Hdr, TimeSpan.FromSeconds(5)).Status;

    [Fact]
    public void Private_ca_is_trusted_via_ca_file()
    {
        using var pki = new TestPki();
        using var srv = pki.Serve(false);
        Assert.Equal(200, Post($"https://127.0.0.1:{srv.Port}/", new HttpClientPoster(pki.CaPem, null, null)));
    }

    [Fact]
    public void Unknown_ca_is_rejected()
    {
        using var pki = new TestPki();
        using var srv = pki.Serve(false);
        Assert.ThrowsAny<Exception>(() => Post($"https://127.0.0.1:{srv.Port}/", new HttpClientPoster(null, null, null)));
    }

    [Fact]
    public void Hostname_verification_is_not_disabled_when_a_custom_ca_is_used()
    {
        using var pki = new TestPki();
        using var srv = pki.Serve(false);
        // 인증서 SAN 은 IP 127.0.0.1 뿐이라 'localhost' 는 이름 불일치여야 한다
        Assert.ThrowsAny<Exception>(() => Post($"https://localhost:{srv.Port}/", new HttpClientPoster(pki.CaPem, null, null)));
    }

    [Fact]
    public void Mtls_with_client_certificate_succeeds_and_without_is_rejected()
    {
        using var pki = new TestPki();
        using var srv = pki.Serve(true);
        Assert.Equal(200, Post($"https://127.0.0.1:{srv.Port}/", new HttpClientPoster(pki.CaPem, pki.ClientPem, pki.ClientKey)));
        Assert.ThrowsAny<Exception>(() => Post($"https://127.0.0.1:{srv.Port}/", new HttpClientPoster(pki.CaPem, null, null)));
    }

    [Fact]
    public void Missing_ca_or_client_files_fail_at_construction_so_the_cli_can_report_a_config_error()
    {
        Assert.ThrowsAny<Exception>(() => new HttpClientPoster("/nonexistent/ca.pem", null, null));
        Assert.ThrowsAny<Exception>(() => new HttpClientPoster(null, "/nonexistent/c.pem", "/nonexistent/c.key"));
    }
}
