using System.Text.Json;
using Swinventory.Agent;
using Swinventory.Agent.Collectors;
using Swinventory.Agent.Runtime;
using Swinventory.Agent.Transport;

namespace Swinventory.Agent.Tests;

public class CliTests : IDisposable
{
    private readonly string _dir = Fx.TempDir();
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private sealed record Env(CliRuntime Runtime, StringWriter Out, StringWriter Err, List<TimeSpan> Sleeps);

    private Env Rt(IHttpPoster? poster = null, bool windows = true, bool machineGuid = true, Dictionary<string, string>? env = null)
    {
        var reg = new FakeRegistry()
            .Add(WindowsKeys.CurrentVersion, 64, new() { ["CurrentBuildNumber"] = "22631", ["UBR"] = 3085, ["ProductName"] = "Windows 11 Pro", ["DisplayVersion"] = "23H2" })
            .Add(WindowsKeys.Uninstall, 64)
            .Add(WindowsKeys.Uninstall + @"\{A}", 64, new() { ["DisplayName"] = "Git", ["DisplayVersion"] = "2.45.0" });
        if (machineGuid) reg.Add(@"SOFTWARE\Microsoft\Cryptography", 64, new() { ["MachineGuid"] = "GUID-1" });
        var runner = new FakeCommandRunner().Add(WindowsCommands.Hotfix, 0, "[{\"HotFixID\":\"KB1\"}]");
        var probe = new FakeProbe();
        probe.Tcp.Add(new ProbeEndpoint("0.0.0.0", 135));
        var o = new StringWriter();
        var e = new StringWriter();
        var sleeps = new List<TimeSpan>();
        return new Env(new CliRuntime(reg, runner, probe, poster, windows, sleeps.Add, env ?? new Dictionary<string, string>(), o, e,
            () => Fx.Now, () => "WIN-SRV01"), o, e, sleeps);
    }

    private string Config(object cfg)
    {
        var path = Path.Combine(_dir, "agent.json");
        File.WriteAllText(path, JsonSerializer.Serialize(cfg));
        return path;
    }

    [Fact]
    public void Print_outputs_the_snapshot_json_without_sending()
    {
        var e = Rt();
        Assert.Equal(0, Cli.Run(new[] { "print" }, e.Runtime));
        using var doc = JsonDocument.Parse(e.Out.ToString());
        Assert.Equal("GUID-1", doc.RootElement.GetProperty("host_id").GetString());
        Assert.Equal("WIN-SRV01", doc.RootElement.GetProperty("hostname").GetString());
        Assert.Equal("windows", doc.RootElement.GetProperty("os").GetProperty("family").GetString());
        Assert.Equal(6, doc.RootElement.GetProperty("collected").GetArrayLength());
    }

    [Fact]
    public void Collect_to_json_dir_writes_one_file()
    {
        var e = Rt();
        var outDir = Path.Combine(_dir, "out");
        Assert.Equal(0, Cli.Run(new[] { "collect", "--json-dir", outDir }, e.Runtime));
        Assert.Single(Directory.GetFiles(outDir));
    }

    [Fact]
    public void Collect_over_https_uses_the_token_file_and_default_endpoint()
    {
        var tok = Path.Combine(_dir, "token");
        File.WriteAllText(tok, "tok-123\r\n");              // 메모장 등이 붙인 CRLF 도 제거돼야 한다
        var cfg = Config(new { server_url = "https://inv.example.com", token_file = tok, spool_path = Path.Combine(_dir, "spool") });
        var poster = new FakePoster(FakePoster.Ok());
        var e = Rt(poster);
        Assert.Equal(0, Cli.Run(new[] { "collect", "--config", cfg }, e.Runtime));
        var req = poster.Requests.Single();
        Assert.Equal("https://inv.example.com/v1/ingest", req.Url.ToString());
        Assert.Equal("Bearer tok-123", req.Headers["Authorization"]);
        Assert.Contains("\"host_id\":\"GUID-1\"", System.Text.Encoding.UTF8.GetString(req.Body));
    }

    [Fact]
    public void Server_down_spools_and_exits_zero_then_flush_delivers()
    {
        var cfg = Config(new { server_url = "https://inv.example.com", token = "t", spool_path = Path.Combine(_dir, "spool") });
        Assert.Equal(0, Cli.Run(new[] { "collect", "--config", cfg }, Rt(new FakePoster(FakePoster.Status(503))).Runtime));
        Assert.Single(Directory.GetFiles(Path.Combine(_dir, "spool")));
        var good = new FakePoster(FakePoster.Ok());
        Assert.Equal(0, Cli.Run(new[] { "flush", "--config", cfg }, Rt(good).Runtime));
        Assert.Single(good.Requests);
        Assert.Empty(Directory.GetFiles(Path.Combine(_dir, "spool")));
    }

    [Fact]
    public void Flush_exit_code_when_still_failing_and_permanent_rejection_exit_code()
    {
        var cfg = Config(new { server_url = "https://inv.example.com", token = "t", spool_path = Path.Combine(_dir, "spool") });
        Cli.Run(new[] { "collect", "--config", cfg }, Rt(new FakePoster(FakePoster.Status(503))).Runtime);
        Assert.Equal(5, Cli.Run(new[] { "flush", "--config", cfg }, Rt(new FakePoster(FakePoster.Status(503))).Runtime));
        var cfg2 = Config(new { server_url = "https://inv.example.com", token = "t", spool_path = Path.Combine(_dir, "spool2") });
        Assert.Equal(4, Cli.Run(new[] { "collect", "--config", cfg2 }, Rt(new FakePoster(FakePoster.Status(422))).Runtime));
    }

    [Fact]
    public void Config_errors_exit_2()
    {
        Assert.Equal(2, Cli.Run(new[] { "collect" }, Rt().Runtime));                                                                   // 목적지 없음
        var http = Config(new { server_url = "http://inv.example.com", token = "t" });
        Assert.Equal(2, Cli.Run(new[] { "collect", "--config", http }, Rt().Runtime));                                                 // 평문 http 거부
        var notoken = Config(new { server_url = "https://inv.example.com" });
        Assert.Equal(2, Cli.Run(new[] { "collect", "--config", notoken }, Rt().Runtime));                                              // 토큰 없음
        Assert.Equal(2, Cli.Run(new[] { "collect", "--config", Path.Combine(_dir, "missing.json") }, Rt().Runtime));                   // 파일 없음
        var unknown = Config(new { server_url = "https://x", token = "t", bogus = 1 });
        Assert.Equal(2, Cli.Run(new[] { "collect", "--config", unknown }, Rt().Runtime));                                              // 알 수 없는 키
    }

    [Fact]
    public void Config_error_messages_never_contain_the_token()
    {
        var cfg = Config(new { server_url = "http://inv.example.com", token = "super-secret-token" });
        var e = Rt();
        Cli.Run(new[] { "collect", "--config", cfg }, e.Runtime);
        Assert.DoesNotContain("super-secret-token", e.Err.ToString());
    }

    [Fact]
    public void Not_windows_exits_3_with_a_clear_message()
    {
        var e = Rt(windows: false);
        Assert.Equal(3, Cli.Run(new[] { "print" }, e.Runtime));
        Assert.Contains("Windows", e.Err.ToString());
    }

    [Fact]
    public void Env_overrides_config_and_flags_override_env()
    {
        var cfg = AgentConfig.Load(null, new Dictionary<string, string> { ["SWINV_SERVER_URL"] = "https://a", ["SWINV_TOKEN"] = "t", ["SWINV_SPOOL_PATH"] = "/tmp/x" },
            new Dictionary<string, string?>());
        Assert.Equal(("https://a", "t", "/tmp/x"), (cfg.ServerUrl, cfg.Token, cfg.SpoolPath));
        var cfg2 = AgentConfig.Load(null, new Dictionary<string, string> { ["SWINV_SERVER_URL"] = "https://a" },
            new Dictionary<string, string?> { ["server_url"] = "https://b" });
        Assert.Equal("https://b", cfg2.ServerUrl);
    }

    [Fact]
    public void Insecure_http_flag_is_allowed_for_dev_only_when_explicit()
    {
        var cfg = AgentConfig.Load(null, new Dictionary<string, string>(),
            new Dictionary<string, string?> { ["server_url"] = "http://127.0.0.1:8000", ["token"] = "t", ["allow_insecure_http"] = "true" });
        cfg.Validate(false);
        Assert.Throws<ConfigException>(() => AgentConfig.Load(null, new Dictionary<string, string>(), new Dictionary<string, string?>()).Validate(false));
    }

    [Fact]
    public void Run_loop_sleeps_between_iterations_and_survives_a_failing_iteration()
    {
        var e = Rt();
        var outDir = Path.Combine(_dir, "out");
        Assert.Equal(0, Cli.Run(new[] { "run", "--interval", "600", "--max-runs", "3", "--json-dir", outDir }, e.Runtime));
        Assert.Equal(new[] { TimeSpan.FromSeconds(600), TimeSpan.FromSeconds(600) }, e.Sleeps);
        Assert.Equal(3, Directory.GetFiles(outDir).Length);

        var bad = Rt(machineGuid: false);
        Assert.Equal(1, Cli.Run(new[] { "run", "--interval", "5", "--max-runs", "2", "--json-dir", Path.Combine(_dir, "o2") }, bad.Runtime));
        Assert.Equal(new[] { TimeSpan.FromSeconds(5) }, bad.Sleeps);
        Assert.Contains("MachineGuid", bad.Err.ToString());
    }

    [Fact]
    public void Unknown_command_or_missing_command_prints_usage_and_exits_2()
    {
        Assert.Equal(2, Cli.Run(new[] { "bogus" }, Rt().Runtime));
        Assert.Equal(0, Cli.Run(new[] { "--help" }, Rt().Runtime));
    }
}
