using Swinventory.Agent.Collectors;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;

namespace Swinventory.Agent.Tests;

public class WindowsCollectorTests
{
    private static (CollectorResult Result, SnapshotBuilder Builder) Run(ICollector c)
    {
        var b = new SnapshotBuilder();
        return (c.Collect(b), b);
    }

    private static Dictionary<string, object?> V(params (string, object?)[] kv) => kv.ToDictionary(x => x.Item1, x => x.Item2);

    // --- 레지스트리 소프트웨어 --------------------------------------------------

    private static FakeRegistry UninstallRegistry()
    {
        var u = WindowsKeys.Uninstall;
        return new FakeRegistry()
            .Add(u, 64)
            .Add(u + @"\{A}", 64, V(("DisplayName", "Git"), ("DisplayVersion", "2.45.0")))
            .Add(u + @"\{B}", 64, V(("DisplayName", "Hidden Comp"), ("SystemComponent", 1)))
            .Add(u + @"\{C}", 64, V(("DisplayName", "OS Part"), ("ParentKeyName", "OperatingSystem")))
            .Add(u + @"\KB5034441", 64, V(("DisplayName", "Security Update for Windows (KB5034441)"), ("ReleaseType", "Security Update")))
            .Add(u + @"\{E}", 64, V(("DisplayVersion", "1.0")))                                   // DisplayName 없음
            .Add(u, 32)
            .Add(u + @"\{D}", 32, V(("DisplayName", "Legacy Tool"), ("DisplayVersion", "1.0")))
            .Add(u + @"\{A2}", 32, V(("DisplayName", "Git"), ("DisplayVersion", "2.45.0")));
    }

    [Fact]
    public void Registry_software_filters_system_components_updates_and_tags_architecture()
    {
        var c = new WinRegistrySoftware(UninstallRegistry());
        var (res, b) = Run(c);
        Assert.Equal("software.win_registry", c.Name);
        Assert.True(res.Ok);
        Assert.Equal(new[] { ("Git", "2.45.0", "x64"), ("Git", "2.45.0", "x86"), ("Legacy Tool", "1.0", "x86") },
            b.Packages.OrderBy(p => p.Name).ThenBy(p => p.Arch).Select(p => (p.Name, p.Version, p.Arch)));
        Assert.All(b.Packages, p => Assert.Equal("win_registry", p.Source));
    }

    [Fact]
    public void Registry_software_dedupes_identical_entries_and_handles_dword_flags_of_any_numeric_type()
    {
        var u = WindowsKeys.Uninstall;
        var reg = new FakeRegistry().Add(u, 64)
            .Add(u + @"\{1}", 64, V(("DisplayName", "Same"), ("DisplayVersion", "1")))
            .Add(u + @"\{2}", 64, V(("DisplayName", "Same"), ("DisplayVersion", "1")))
            .Add(u + @"\{3}", 64, V(("DisplayName", "Sys"), ("SystemComponent", 1L)));      // long/int 어느 쪽이든
        var (_, b) = Run(new WinRegistrySoftware(reg));
        Assert.Equal(new[] { "Same" }, b.Packages.Select(p => p.Name));
    }

    // --- 핫픽스 -----------------------------------------------------------------

    private static WinHotfixSoftware Hotfix(int exit, string stdout, string stderr = "") =>
        new(new FakeCommandRunner().Add(WindowsCommands.Hotfix, exit, stdout, stderr));

    [Fact]
    public void Hotfix_handles_single_object_array_and_empty_output()
    {
        var (r1, b1) = Run(Hotfix(0, "{\"HotFixID\":\"KB5034441\",\"InstalledOn\":null}"));
        Assert.True(r1.Ok);
        Assert.Equal(new[] { ("win_hotfix", "KB5034441") }, b1.Packages.Select(p => (p.Source, p.Name)));
        var (_, b2) = Run(Hotfix(0, "[{\"HotFixID\":\"KB1\"},{\"HotFixID\":\"KB2\"},{\"HotFixID\":\"KB1\"}]"));
        Assert.Equal(new[] { "KB1", "KB2" }, b2.Packages.Select(p => p.Name));
        var (r3, b3) = Run(Hotfix(0, "  \n"));
        Assert.True(r3.Ok);
        Assert.Empty(b3.Packages);
    }

    [Fact]
    public void Hotfix_failures_are_reported()
    {
        Assert.False(Run(Hotfix(1, "", "denied")).Result.Ok);
        Assert.False(Run(Hotfix(0, "not json")).Result.Ok);
        Assert.False(Run(new WinHotfixSoftware(new FakeCommandRunner())).Result.Ok);        // powershell 없음
    }

    // --- 커널·OS ----------------------------------------------------------------

    private static Dictionary<string, object?> Cv(params (string, object?)[] extra) =>
        V(new (string, object?)[] { ("CurrentBuildNumber", "22631"), ("UBR", 3085) }.Concat(extra).ToArray());

    [Fact]
    public void Kernel_version_is_10_0_build_ubr_and_reboot_keys_are_detected()
    {
        var plain = new FakeRegistry().Add(WindowsKeys.CurrentVersion, 64, Cv());
        var (res, b) = Run(new WinKernel(plain));
        Assert.True(res.Ok);
        Assert.Equal(new KernelInfo("10.0.22631.3085", new[] { "10.0.22631.3085" }, false), b.Kernel, KernelComparer.Instance);
        foreach (var key in new[] { WindowsKeys.RebootPending, WindowsKeys.RebootRequired })
        {
            var reg = new FakeRegistry().Add(WindowsKeys.CurrentVersion, 64, Cv()).Add(key, 64);
            Assert.True(Run(new WinKernel(reg)).Builder.Kernel!.RebootRequired, key);
        }
    }

    [Fact]
    public void Kernel_ubr_may_be_any_numeric_type_and_defaults_to_zero()
    {
        var reg = new FakeRegistry().Add(WindowsKeys.CurrentVersion, 64, V(("CurrentBuildNumber", "19045")));
        Assert.Equal("10.0.19045.0", Run(new WinKernel(reg)).Builder.Kernel!.Running);
        var reg2 = new FakeRegistry().Add(WindowsKeys.CurrentVersion, 64, V(("CurrentBuildNumber", "19045"), ("UBR", 4291L)));
        Assert.Equal("10.0.19045.4291", Run(new WinKernel(reg2)).Builder.Kernel!.Running);
    }

    [Fact]
    public void Kernel_and_os_fail_when_the_version_key_is_missing()
    {
        Assert.False(Run(new WinKernel(new FakeRegistry())).Result.Ok);
        Assert.False(Run(new WinOs(new FakeRegistry())).Result.Ok);
    }

    [Fact]
    public void Os_info_uses_product_name_and_display_version()
    {
        var reg = new FakeRegistry().Add(WindowsKeys.CurrentVersion, 64, Cv(("ProductName", "Windows Server 2022 Standard"), ("DisplayVersion", "21H2")));
        Assert.Equal(new OsInfo("windows", "Windows Server 2022 Standard", "21H2"), Run(new WinOs(reg)).Builder.Os);
        var reg2 = new FakeRegistry().Add(WindowsKeys.CurrentVersion, 64, Cv(("ProductName", "Windows Server 2016 Standard"), ("ReleaseId", "1607")));
        Assert.Equal("1607", Run(new WinOs(reg2)).Builder.Os!.Version);
    }

    // --- 네트워크(관리형 API 의 Fake) ----------------------------------------------

    private static byte[] Mac(string s) => Convert.FromHexString(s.Replace(":", ""));
    private static ProbeAddress A(string ip, int prefix) => new(ip, prefix);

    private static FakeProbe NetProbe()
    {
        var p = new FakeProbe();
        p.InterfaceList.AddRange(new[]
        {
            new ProbeInterface("Loopback Pseudo-Interface 1", "Loopback", "Up", null, new[] { A("127.0.0.1", 8), A("::1", 128) }),
            new ProbeInterface("Ethernet", "Ethernet", "Up", Mac("00:15:5D:01:02:03"),
                new[] { A("10.1.2.3", 24), A("fe80::1", 64), A("2001:db8::9", 64) }),
            new ProbeInterface("Ethernet 2", "Ethernet", "Down", Mac("00:15:5D:0A:0B:0C"), new[] { A("169.254.1.1", 16) }),
            new ProbeInterface("isatap.{ABC}", "Tunnel", "Down", Array.Empty<byte>(), Array.Empty<ProbeAddress>()),     // 식별 정보 없음
            new ProbeInterface("Wi-Fi", "Wireless80211", "NotPresent", Mac("AA-BB-CC-DD-EE-FF".Replace("-", ":")), Array.Empty<ProbeAddress>()),
            new ProbeInterface("OpenVPN", "Tunnel", "Unknown", Array.Empty<byte>(), new[] { A("10.8.0.2", 32) }),
        });
        return p;
    }

    [Fact]
    public void Interfaces_exclude_loopback_link_local_and_identity_less_tunnels_and_normalize_mac_and_state()
    {
        var c = new WinInterfaces(NetProbe());
        var (res, b) = Run(c);
        Assert.Equal("network.interfaces", c.Name);
        Assert.True(res.Ok);
        Assert.Equal(new[]
        {
            ("Ethernet", "00:15:5d:01:02:03", "up", "10.1.2.3/24,2001:db8::9/64"),
            ("Ethernet 2", "00:15:5d:0a:0b:0c", "down", ""),
            ("OpenVPN", "", "unknown", "10.8.0.2/32"),
            ("Wi-Fi", "aa:bb:cc:dd:ee:ff", "down", ""),
        }, b.Interfaces.Select(i => (i.Name, i.Mac, i.State, string.Join(',', i.Addresses))));
    }

    [Fact]
    public void Loopback_typed_interface_is_excluded_even_if_it_has_a_mac_and_a_global_address()
    {
        // 주소·MAC 필터와 독립적으로 InterfaceType 검사가 동작해야 한다(루프백 유형은 어떤 경우에도 인벤토리 대상이 아니다)
        var p = new FakeProbe();
        p.InterfaceList.Add(new ProbeInterface("odd-loopback", "Loopback", "Up", Mac("AA:BB:CC:00:00:01"), new[] { A("10.9.9.9", 24) }));
        p.InterfaceList.Add(new ProbeInterface("Ethernet", "Ethernet", "Up", Mac("AA:BB:CC:00:00:02"), new[] { A("10.1.1.1", 24) }));
        Assert.Equal(new[] { "Ethernet" }, Run(new WinInterfaces(p)).Builder.Interfaces.Select(i => i.Name));
    }

    [Fact]
    public void Ports_are_deduped_sorted_and_udp_ephemeral_ports_are_excluded_but_tcp_is_kept()
    {
        var p = new FakeProbe();
        p.Tcp.AddRange(new[] { new ProbeEndpoint("0.0.0.0", 135), new ProbeEndpoint("::", 135), new ProbeEndpoint("127.0.0.1", 5432),
            new ProbeEndpoint("0.0.0.0", 135), new ProbeEndpoint("0.0.0.0", 55000) });       // 중복·동적 범위 TCP 리스너
        p.Udp.AddRange(new[] { new ProbeEndpoint("0.0.0.0", 123), new ProbeEndpoint("0.0.0.0", 56000), new ProbeEndpoint("fe80::1%6", 5353) });
        var c = new WinPorts(p);
        var (res, b) = Run(c);
        Assert.Equal("network.ports", c.Name);
        Assert.True(res.Ok);
        Assert.Equal(new[] { ("tcp", 135, "0.0.0.0"), ("tcp", 135, "::"), ("tcp", 5432, "127.0.0.1"), ("tcp", 55000, "0.0.0.0"),
            ("udp", 123, "0.0.0.0"), ("udp", 5353, "fe80::1") }, b.Ports.Select(x => (x.Proto, x.Port, x.Bind)));
    }

    [Fact]
    public void Ipv4_mapped_addresses_are_normalized_to_ipv4()
    {
        var p = new FakeProbe();
        p.Tcp.Add(new ProbeEndpoint("::ffff:10.0.0.15", 8080));
        p.Tcp.Add(new ProbeEndpoint("10.0.0.15", 8080));
        Assert.Equal(new[] { ("tcp", 8080, "10.0.0.15") }, Run(new WinPorts(p)).Builder.Ports.Select(x => (x.Proto, x.Port, x.Bind)));
    }

    [Fact]
    public void Probe_failures_become_collector_errors()
    {
        var p = new FakeProbe { Fail = new InvalidOperationException("boom") };
        Assert.False(Run(new WinInterfaces(p)).Result.Ok);
        Assert.False(Run(new WinPorts(p)).Result.Ok);
    }
}

internal sealed class KernelComparer : IEqualityComparer<KernelInfo?>
{
    public static readonly KernelComparer Instance = new();
    public bool Equals(KernelInfo? a, KernelInfo? b) =>
        a is not null && b is not null && a.Running == b.Running && a.RebootRequired == b.RebootRequired && a.Installed.SequenceEqual(b.Installed);
    public int GetHashCode(KernelInfo? k) => k?.Running.GetHashCode() ?? 0;
}
