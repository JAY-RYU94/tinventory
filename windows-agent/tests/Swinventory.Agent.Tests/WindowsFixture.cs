using Swinventory.Agent;
using Swinventory.Agent.Collectors;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;

namespace Swinventory.Agent.Tests;

/// <summary>Windows 서버 한 대를 흉내 낸 Fake 환경. second=true 는 첫 수집 이후의 변화(패키지 설치·버전 변경, 포트 열림, IP 교체, 커널 업데이트)를 담는다.</summary>
internal static class WindowsFixture
{
    public const string HostId = "11111111-2222-3333-4444-555555555555";

    public static Snapshot Snapshot(DateTimeOffset at, bool second = false)
    {
        var reg = new FakeRegistry()
            .Add(@"SOFTWARE\Microsoft\Cryptography", 64, new() { ["MachineGuid"] = HostId })
            .Add(WindowsKeys.CurrentVersion, 64, new() { ["CurrentBuildNumber"] = "20348", ["UBR"] = second ? 2500 : 2461, ["ProductName"] = "Windows Server 2022 Standard", ["DisplayVersion"] = "21H2" })
            .Add(WindowsKeys.RebootPending, 64)
            .Add(WindowsKeys.Uninstall, 64)
            .Add(WindowsKeys.Uninstall + @"\{A}", 64, new() { ["DisplayName"] = "Git", ["DisplayVersion"] = second ? "2.46.0" : "2.45.0" })
            .Add(WindowsKeys.Uninstall + @"\{K}", 64, new() { ["DisplayName"] = "한글 프로그램", ["DisplayVersion"] = "1.2" })
            .Add(WindowsKeys.Uninstall, 32)
            .Add(WindowsKeys.Uninstall + @"\{D}", 32, new() { ["DisplayName"] = "Legacy Tool", ["DisplayVersion"] = "1.0" });
        var hotfixes = second ? "[{\"HotFixID\":\"KB5034441\"},{\"HotFixID\":\"KB5035857\"},{\"HotFixID\":\"KB5036000\"}]"
                              : "[{\"HotFixID\":\"KB5034441\"},{\"HotFixID\":\"KB5035857\"}]";
        var runner = new FakeCommandRunner().Add(WindowsCommands.Hotfix, 0, hotfixes)
            .Add(HardwareCommands.System, 0, "{\"Manufacturer\":\"Microsoft Corporation\",\"Model\":\"Virtual Machine\",\"Domain\":\"corp.example.com\",\"PartOfDomain\":true,\"DNSHostName\":\"WIN-SRV01\"}")
            .Add(HardwareCommands.Bios, 0, "{\"SerialNumber\":\"1234-5678-9012\"}");
        var probe = new FakeProbe();
        probe.InterfaceList.Add(new ProbeInterface("Ethernet", "Ethernet", "Up", Convert.FromHexString("00155D010203"),
            new[] { new ProbeAddress(second ? "10.1.2.4" : "10.1.2.3", 24), new ProbeAddress("2001:db8::9", 64) }));
        probe.Tcp.AddRange(new[] { new ProbeEndpoint("0.0.0.0", 135), new ProbeEndpoint("::", 135), new ProbeEndpoint("0.0.0.0", 3389), new ProbeEndpoint("127.0.0.1", 5432) });
        if (second) probe.Tcp.Add(new ProbeEndpoint("0.0.0.0", 8443));
        probe.Udp.Add(new ProbeEndpoint("0.0.0.0", 123));
        return new SnapshotOrchestrator(new WindowsProfile(reg, runner, probe), () => at, () => "WIN-SRV01", "0.2.0").Collect();
    }
}
