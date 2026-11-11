using System.Net;
using System.Net.Sockets;
using Swinventory.Agent.Collectors;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;
using Swinventory.Agent.Transport;

namespace Swinventory.Agent.Tests;

/// <summary>Fake 가 아니라 실제 시스템 API 로 검증한다(Linux 컨테이너에서도 동작하는 관리형 API).</summary>
public class RealEnvironmentTests
{
    [Fact]
    public void System_probe_sees_real_tcp_listeners_with_their_bind_addresses()
    {
        using var any = new TcpListener(IPAddress.Any, 0);
        using var loop = new TcpListener(IPAddress.Loopback, 0);
        any.Start(); loop.Start();
        var anyPort = ((IPEndPoint)any.LocalEndpoint).Port;
        var loopPort = ((IPEndPoint)loop.LocalEndpoint).Port;

        var b = new SnapshotBuilder();
        var res = new WinPorts(new SystemNetworkProbe()).Collect(b);

        Assert.True(res.Ok, res.Error);
        Assert.Contains(b.Ports, p => p == new ListeningPort("tcp", anyPort, "0.0.0.0"));
        Assert.Contains(b.Ports, p => p == new ListeningPort("tcp", loopPort, "127.0.0.1"));
    }

    [Fact]
    public void System_probe_reports_real_interfaces_and_the_collector_excludes_loopback()
    {
        var probe = new SystemNetworkProbe();
        Assert.Contains(probe.Interfaces(), i => i.InterfaceType == "Loopback");
        var b = new SnapshotBuilder();
        var res = new WinInterfaces(probe).Collect(b);
        Assert.True(res.Ok, res.Error);
        Assert.DoesNotContain(b.Interfaces, i => i.Addresses.Any(a => a.StartsWith("127.", StringComparison.Ordinal)));
        Assert.All(b.Interfaces, i => Assert.True(i.Mac == "" || System.Text.RegularExpressions.Regex.IsMatch(i.Mac, "^([0-9a-f]{2}:){5}[0-9a-f]{2}$"), i.Mac));
        Assert.All(b.Interfaces.SelectMany(i => i.Addresses), a =>
        {
            var parts = a.Split('/');
            Assert.True(parts.Length == 2 && IPAddress.TryParse(parts[0], out _) && int.TryParse(parts[1], out var prefix) && prefix is >= 0 and <= 128, a);
        });
    }

    [Fact]
    public void Process_runner_passes_arguments_intact_and_reports_exit_codes()
    {
        if (OperatingSystem.IsWindows()) return;
        var r = new ProcessCommandRunner();
        var ok = r.Run(new[] { "echo", "a b", "c\"d" }, TimeSpan.FromSeconds(5));
        Assert.Equal((0, "a b c\"d"), (ok.ExitCode, ok.Stdout.Trim()));
        Assert.NotEqual(0, r.Run(new[] { "false" }, TimeSpan.FromSeconds(5)).ExitCode);
        Assert.Throws<FileNotFoundException>(() => r.Run(new[] { "definitely-not-a-command-xyz" }, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public void Process_runner_kills_a_command_that_exceeds_the_timeout()
    {
        if (OperatingSystem.IsWindows()) return;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.Throws<TimeoutException>(() => new ProcessCommandRunner().Run(new[] { "sleep", "30" }, TimeSpan.FromMilliseconds(500)));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10));
    }

    [Fact]
    public void Windows_registry_reader_is_only_usable_on_windows_and_says_so_elsewhere()
    {
        if (OperatingSystem.IsWindows()) return;
        Assert.Throws<PlatformNotSupportedException>(() => new WindowsRegistryReader().Values(WindowsKeys.CurrentVersion));
    }
}

/// <summary>C# 에이전트가 만든 스냅샷을 Python 서버 계약 테스트가 읽도록 파일로 내보낸다(SWINV_CONTRACT_OUT 디렉터리가 있을 때만).</summary>
public class ContractEmitTests
{
    [Fact]
    public void Emit_windows_snapshots_for_the_python_server_contract_test()
    {
        var dir = Environment.GetEnvironmentVariable("SWINV_CONTRACT_OUT");
        if (string.IsNullOrEmpty(dir)) return;
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "snapshot.windows.json"), SnapshotJson.Serialize(WindowsFixture.Snapshot(Fx.Now)));
        File.WriteAllText(Path.Combine(dir, "snapshot.windows.v2.json"), SnapshotJson.Serialize(WindowsFixture.Snapshot(Fx.Now.AddHours(1), second: true)));
    }
}

/// <summary>실제로 떠 있는 Python 서버에 HTTP 로 올린다(SWINV_E2E_SERVER·SWINV_E2E_TOKEN 이 있을 때만). 검증은 호출한 스크립트가 서버 API 로 한다.</summary>
public class ServerInteropTests
{
    [Fact]
    public void Post_windows_snapshots_to_a_real_server_over_http()
    {
        var url = Environment.GetEnvironmentVariable("SWINV_E2E_SERVER");
        var token = Environment.GetEnvironmentVariable("SWINV_E2E_TOKEN");
        if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(token)) return;
        using var poster = new HttpClientPoster(null, null, null);
        var transport = new HttpsTransport(url, token, poster, TimeSpan.FromSeconds(30));
        Assert.Equal(SendOutcome.Sent, transport.Send(WindowsFixture.Snapshot(Fx.Now)));
        Assert.Equal(SendOutcome.Sent, transport.Send(WindowsFixture.Snapshot(Fx.Now.AddHours(1), second: true)));
    }
}
