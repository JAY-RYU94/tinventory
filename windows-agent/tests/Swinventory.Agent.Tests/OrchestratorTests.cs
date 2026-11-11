using Swinventory.Agent.Collectors;
using Swinventory.Agent.Models;

namespace Swinventory.Agent.Tests;

public class OrchestratorTests
{
    private sealed class OkCollector(string name, Action<SnapshotBuilder> contribute) : ICollector
    {
        public string Name => name;
        public CollectorResult Collect(SnapshotBuilder b) { contribute(b); return new CollectorResult(name, true, null); }
    }

    private sealed class BadCollector(string name) : ICollector
    {
        public string Name => name;
        public CollectorResult Collect(SnapshotBuilder b) => new(name, false, "InvalidOperationException: boom");
    }

    private sealed class FakeProfile(params ICollector[] collectors) : IPlatformProfile
    {
        public string HostId() => "host-1";
        public IReadOnlyList<ICollector> Collectors() => collectors;
    }

    private static SnapshotOrchestrator Orch(IPlatformProfile p) => new(p, () => Fx.Now, () => "web01", "9.9");

    [Fact]
    public void One_failing_collector_does_not_stop_the_others_and_is_recorded()
    {
        var snap = Orch(new FakeProfile(
            new BadCollector("software.fake_bad"),
            new OkCollector("software.fake_ok", b => b.Packages.Add(new PackageRecord("fake_ok", "pkg", "1"))),
            new OkCollector("kernel", b => b.Kernel = new KernelInfo("1.0", new[] { "1.0" }, false)))).Collect();
        Assert.Equal(("host-1", "web01", "9.9", "2026-11-05T01:02:03+00:00"), (snap.HostId, snap.Hostname, snap.AgentVersion, snap.CollectedAt));
        Assert.Equal("InvalidOperationException: boom", snap.Errors["software.fake_bad"]);
        Assert.Equal(new[] { "software.fake_ok", "kernel" }, snap.Collected);
        Assert.Equal(new[] { "pkg" }, snap.Packages.Select(p => p.Name));
        Assert.NotNull(snap.Kernel);
        Assert.Null(snap.Os);
    }

    [Fact]
    public void Collected_at_is_utc_even_when_the_clock_has_an_offset()
    {
        var local = new DateTimeOffset(2026, 11, 5, 10, 2, 3, TimeSpan.FromHours(9));
        var snap = new SnapshotOrchestrator(new FakeProfile(), () => local, () => "h", "1").Collect();
        Assert.Equal("2026-11-05T01:02:03+00:00", snap.CollectedAt);
    }

    [Fact]
    public void Collector_that_throws_is_isolated_by_the_orchestrator_too()
    {
        var snap = Orch(new FakeProfile(new ThrowingCollector(), new OkCollector("os", b => b.Os = new OsInfo("windows", "w", "1")))).Collect();
        Assert.Contains("software.throws", snap.Errors.Keys);
        Assert.Contains("ArgumentException", snap.Errors["software.throws"]);
        Assert.NotNull(snap.Os);
    }

    private sealed class ThrowingCollector : ICollector
    {
        public string Name => "software.throws";
        public CollectorResult Collect(SnapshotBuilder b) => throw new ArgumentException("not caught inside");
    }

    [Fact]
    public void Windows_profile_collects_everything_from_fakes_and_host_id_comes_from_machine_guid()
    {
        var reg = new FakeRegistry()
            .Add(@"SOFTWARE\Microsoft\Cryptography", 64, new() { ["MachineGuid"] = "GUID-1" })
            .Add(WindowsKeys.CurrentVersion, 64, new() { ["CurrentBuildNumber"] = "22631", ["UBR"] = 3085, ["ProductName"] = "Windows 11 Pro", ["DisplayVersion"] = "23H2" })
            .Add(WindowsKeys.Uninstall, 64)
            .Add(WindowsKeys.Uninstall + @"\{A}", 64, new() { ["DisplayName"] = "Git", ["DisplayVersion"] = "2.45.0" });
        var runner = new FakeCommandRunner().Add(WindowsCommands.Hotfix, 0, "[{\"HotFixID\":\"KB1\"}]")
            .Add(HardwareCommands.System, 0, "{\"Manufacturer\":\"Dell Inc.\",\"Model\":\"PowerEdge R640\",\"Domain\":\"corp.example.com\",\"PartOfDomain\":true,\"DNSHostName\":\"WIN1\"}")
            .Add(HardwareCommands.Bios, 0, "{\"SerialNumber\":\"7XK2M3\"}");
        var probe = new FakeProbe();
        probe.Tcp.Add(new Runtime.ProbeEndpoint("0.0.0.0", 135));
        var profile = new WindowsProfile(reg, runner, probe);
        Assert.Equal("GUID-1", profile.HostId());
        var snap = Orch(profile).Collect();
        Assert.Empty(snap.Errors);
        Assert.Equal(new[] { "os", "kernel", "software.win_registry", "software.win_hotfix", "network.interfaces", "network.ports", "hardware" }, snap.Collected);
        Assert.Equal("10.0.22631.3085", snap.Kernel!.Running);
        Assert.Equal(new[] { "Git", "KB1" }, snap.Packages.Select(p => p.Name).Order());
        Assert.Single(snap.Ports);
        // 수집기가 성공해도 오케스트레이터가 스냅샷에 옮기지 않으면 서버는 장비 정보를 영영 받지 못한다
        Assert.Equal(("physical", "7XK2M3", "WIN1.corp.example.com"), (snap.Hardware!.Kind, snap.Hardware.Serial, snap.Hardware.Fqdn));
    }

    [Fact]
    public void Missing_machine_guid_is_a_clear_error()
    {
        var profile = new WindowsProfile(new FakeRegistry(), new FakeCommandRunner(), new FakeProbe());
        var ex = Assert.Throws<InvalidOperationException>(() => profile.HostId());
        Assert.Contains("MachineGuid", ex.Message);
    }
}
