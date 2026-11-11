using System.Text.Json;
using Swinventory.Agent;
using Swinventory.Agent.Collectors;
using Swinventory.Agent.Runtime;
using Swinventory.Agent.Transport;

namespace Swinventory.Agent.Tests;

public class DoctorTests : IDisposable
{
    private readonly string _dir = Fx.TempDir();
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private static (CliRuntime Rt, StringWriter Out, StringWriter Err) Rt(IHttpPoster? poster, bool windows = true, bool registry = true)
    {
        var reg = new FakeRegistry();
        if (registry)
            reg.Add(WindowsKeys.CurrentVersion, 64, new() { ["CurrentBuildNumber"] = "22631", ["UBR"] = 3085, ["ProductName"] = "Windows 11 Pro" })
               .Add(WindowsKeys.Uninstall, 64).Add(WindowsKeys.Uninstall + @"\{A}", 64, new() { ["DisplayName"] = "Git", ["DisplayVersion"] = "2.45.0" });
        var probe = new FakeProbe();
        probe.Tcp.Add(new ProbeEndpoint("0.0.0.0", 135));
        probe.InterfaceList.Add(new ProbeInterface("Ethernet", "Ethernet", "Up", Convert.FromHexString("00155D010203"), new[] { new ProbeAddress("10.1.2.3", 24) }));
        var runner = new FakeCommandRunner().Add(WindowsCommands.Hotfix, 0, "[{\"HotFixID\":\"KB1\"}]");
        var o = new StringWriter();
        var e = new StringWriter();
        return (new CliRuntime(reg, runner, probe, poster, windows, _ => { }, new Dictionary<string, string>(), o, e, () => Fx.Now, () => "WIN-SRV01"), o, e);
    }

    private string Config(object cfg)
    {
        var path = Path.Combine(_dir, "agent.json");
        File.WriteAllText(path, JsonSerializer.Serialize(cfg));
        return path;
    }

    private static string[] Lines(StringWriter w) => w.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
    /// <summary>"PASS 점검이름  상세" 형식에서 점검 이름이 needle 로 시작하는 줄(상세 문구에 우연히 들어 있는 단어에 걸리지 않게).</summary>
    private static string Line(StringWriter w, string name) => Lines(w).Single(l => l.Length > 5 && l[5..].StartsWith(name, StringComparison.Ordinal));

    [Fact]
    public void Healthy_windows_host_with_working_server_passes_every_check_and_exits_zero()
    {
        var poster = new FakePoster(FakePoster.Status(422, "{\"detail\":[]}"));      // 서버가 토큰을 받아들이고 빈 본문만 거절한 정상 상태
        var (rt, o, _) = Rt(poster);
        var cfg = Config(new { server_url = "https://inv.example.com", token = "tok", spool_path = Path.Combine(_dir, "sp") });
        Assert.Equal(0, Cli.Run(new[] { "doctor", "--config", cfg }, rt));
        Assert.All(Lines(o).Where(l => l.StartsWith("PASS") || l.StartsWith("FAIL") || l.StartsWith("SKIP")), l => Assert.StartsWith("PASS", l));
        Assert.Contains("연결·토큰 정상", Line(o, "서버 연결"));
        var req = poster.Requests.Single();
        Assert.Equal("https://inv.example.com/v1/ingest", req.Url.ToString());
        Assert.Equal("Bearer tok", req.Headers["Authorization"]);
        Assert.Equal("{}", System.Text.Encoding.UTF8.GetString(req.Body));              // 서버에 아무것도 저장하지 않는 빈 본문
    }

    [Fact]
    public void Rejected_token_fails_with_a_clear_message_and_never_prints_the_token()
    {
        foreach (var status in new[] { 401, 403 })
        {
            var (rt, o, e) = Rt(new FakePoster(FakePoster.Status(status, "unauthorized super-secret-token")));
            var cfg = Config(new { server_url = "https://inv.example.com", token = "super-secret-token" });
            Assert.Equal(1, Cli.Run(new[] { "doctor", "--config", cfg }, rt));
            Assert.StartsWith("FAIL", Line(o, "서버 연결"));
            Assert.Contains("토큰", Line(o, "서버 연결"));
            Assert.DoesNotContain("super-secret-token", o + e.ToString());
        }
    }

    [Fact]
    public void Unreachable_server_and_server_errors_fail()
    {
        var (rt, o, _) = Rt(new FakePoster(new HttpRequestException("connection refused")));
        Assert.Equal(1, Cli.Run(new[] { "doctor", "--config", Config(new { server_url = "https://inv.example.com", token = "t" }) }, rt));
        Assert.Contains("연결", Line(o, "서버 연결"));
        var (rt2, o2, _) = Rt(new FakePoster(FakePoster.Status(503)));
        Assert.Equal(1, Cli.Run(new[] { "doctor", "--config", Config(new { server_url = "https://inv.example.com", token = "t" }) }, rt2));
        Assert.StartsWith("FAIL", Line(o2, "서버 연결"));
    }

    [Fact]
    public void Connection_errors_whose_message_contains_the_token_do_not_leak_it_into_the_output()
    {
        // 프록시·HTTP 라이브러리 오류 메시지에 요청 헤더(토큰)가 섞여 나오는 경우
        var (rt, o, e) = Rt(new FakePoster(new HttpRequestException("proxy rejected 'Authorization: Bearer leaky-token-123'")));
        Assert.Equal(1, Cli.Run(new[] { "doctor", "--config", Config(new { server_url = "https://inv.example.com", token = "leaky-token-123" }) }, rt));
        Assert.StartsWith("FAIL", Line(o, "서버 연결"));
        Assert.DoesNotContain("leaky-token-123", o + e.ToString());
    }

    [Fact]
    public void Without_a_server_configured_the_server_check_is_skipped_and_local_checks_still_run()
    {
        var (rt, o, _) = Rt(null);
        Assert.Equal(0, Cli.Run(new[] { "doctor" }, rt));
        Assert.StartsWith("SKIP", Line(o, "서버 연결"));
        Assert.StartsWith("PASS", Line(o, "네트워크 API"));
        Assert.StartsWith("PASS", Line(o, "JSON"));
    }

    [Fact]
    public void Non_windows_skips_registry_and_powershell_checks_but_still_checks_network_and_json()
    {
        var (rt, o, _) = Rt(null, windows: false);
        Assert.Equal(0, Cli.Run(new[] { "doctor" }, rt));
        Assert.StartsWith("SKIP", Line(o, "레지스트리"));
        Assert.StartsWith("SKIP", Line(o, "PowerShell"));
        Assert.StartsWith("PASS", Line(o, "네트워크 API"));
    }

    [Fact]
    public void Unreadable_registry_fails_the_registry_checks()
    {
        var (rt, o, _) = Rt(null, registry: false);
        Assert.Equal(1, Cli.Run(new[] { "doctor" }, rt));
        Assert.StartsWith("FAIL", Line(o, "레지스트리 읽기(OS"));
    }

    [Fact]
    public void Invalid_config_is_reported_as_a_failed_config_check()
    {
        var (rt, o, e) = Rt(null);
        var cfg = Config(new { server_url = "http://inv.example.com", token = "tok-xyz" });
        Assert.Equal(1, Cli.Run(new[] { "doctor", "--config", cfg }, rt));
        Assert.StartsWith("FAIL", Line(o, "설정"));
        Assert.Contains("https", Line(o, "설정"));
        Assert.DoesNotContain("tok-xyz", o + e.ToString());
    }

    [Fact]
    public void Missing_tls_files_fail_the_tls_check()
    {
        var (rt, o, _) = Rt(null);
        var cfg = Config(new { server_url = "https://inv.example.com", token = "t", ca_file = Path.Combine(_dir, "missing-ca.pem") });
        Assert.Equal(1, Cli.Run(new[] { "doctor", "--config", cfg }, rt));
        Assert.StartsWith("FAIL", Line(o, "TLS"));
    }
}
