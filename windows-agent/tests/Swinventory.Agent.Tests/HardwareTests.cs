using System.Text.Json;
using Swinventory.Agent.Collectors;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;

namespace Swinventory.Agent.Tests;

public class HardwareTests
{
    private static JsonElement Vectors() =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "contracts", "hardware-vectors.json"))).RootElement;

    private static string S(JsonElement e, string name, string fallback = "") => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : fallback;

    [Fact]
    public void Shared_classify_vectors_match_the_python_rules()
    {
        var cases = Vectors().GetProperty("classify").EnumerateArray().ToList();
        Assert.True(cases.Count >= 20);                                          // 파일을 못 읽어 0건을 도는 일이 없게
        foreach (var c in cases)
        {
            var (kind, virt) = HardwareRules.Classify(S(c, "vendor"), S(c, "model"), S(c, "bios_vendor"),
                c.TryGetProperty("hypervisor_flag", out var f) && f.GetBoolean(),
                c.TryGetProperty("detected", out var d) ? d.GetString() : null, c.TryGetProperty("container", out var k) ? k.GetString() : null);
            var expect = c.GetProperty("expect").EnumerateArray().Select(x => x.GetString()).ToArray();
            Assert.True(new[] { kind, virt }.SequenceEqual(expect), $"{S(c, "vendor")}|{S(c, "model")}: {kind}/{virt} != {string.Join("/", expect)}");
        }
    }

    [Fact]
    public void Shared_serial_vectors_match_the_python_rules()
    {
        var cases = Vectors().GetProperty("serial").EnumerateArray().ToList();
        Assert.True(cases.Count >= 10);
        foreach (var c in cases)
        {
            Assert.Equal(S(c, "clean"), HardwareRules.CleanSerial(S(c, "raw")));
            Assert.Equal(S(c, "normalized"), HardwareRules.NormalizeSerial(S(c, "raw")));
        }
    }

    [Fact]
    public void Shared_domain_vectors_match_the_python_rules()
    {
        var cases = Vectors().GetProperty("domain").EnumerateArray().ToList();
        Assert.True(cases.Count >= 5);
        foreach (var c in cases) Assert.Equal(S(c, "domain"), HardwareRules.DomainOf(S(c, "fqdn")));
    }

    private static FakeCommandRunner Runner(string system, string bios, int biosExit = 0, int systemExit = 0) =>
        new FakeCommandRunner().Add(HardwareCommands.System, systemExit, system).Add(HardwareCommands.Bios, biosExit, bios);

    private static (CollectorResult Result, SnapshotBuilder Builder) Run(ICollector c)
    {
        var b = new SnapshotBuilder();
        return (c.Collect(b), b);
    }

    [Fact]
    public void Domain_joined_physical_server()
    {
        var (res, b) = Run(new WinHardware(Runner(
            "{\"Manufacturer\":\"Dell Inc.\",\"Model\":\"PowerEdge R640\",\"Domain\":\"corp.example.com\",\"PartOfDomain\":true,\"DNSHostName\":\"WIN-APP01\"}",
            "{\"SerialNumber\":\"7XK2M3\"}")));
        Assert.True(res.Ok);
        Assert.Equal(new HardwareInfo("physical", "", "Dell Inc.", "PowerEdge R640", "7XK2M3", "WIN-APP01.corp.example.com", "corp.example.com"), b.Hardware);
    }

    [Fact]
    public void Workgroup_machine_has_no_domain_and_hyperv_guest_is_virtual()
    {
        var (_, b) = Run(new WinHardware(Runner(
            "{\"Manufacturer\":\"Microsoft Corporation\",\"Model\":\"Virtual Machine\",\"Domain\":\"WORKGROUP\",\"PartOfDomain\":false,\"DNSHostName\":\"WIN-VM1\"}",
            "{\"SerialNumber\":\"1234-5678-9012\"}")));
        Assert.Equal(("virtual", "hyperv", "", "WIN-VM1"), (b.Hardware!.Kind, b.Hardware.Virt, b.Hardware.Domain, b.Hardware.Fqdn));
    }

    [Fact]
    public void Array_output_and_placeholder_serial()
    {
        var (_, b) = Run(new WinHardware(Runner(
            "[{\"Manufacturer\":\"HPE\",\"Model\":\"ProLiant\",\"Domain\":\"x\",\"PartOfDomain\":false,\"DNSHostName\":\"h\"}]",
            "[{\"SerialNumber\":\"To Be Filled By O.E.M.\"}]")));
        Assert.Equal(("physical", ""), (b.Hardware!.Kind, b.Hardware.Serial));
    }

    [Fact]
    public void Bios_failure_keeps_the_system_information()
    {
        var (res, b) = Run(new WinHardware(Runner(
            "{\"Manufacturer\":\"VMware, Inc.\",\"Model\":\"VMware7,1\",\"Domain\":\"x\",\"PartOfDomain\":false,\"DNSHostName\":\"h\"}", "", biosExit: 1)));
        Assert.True(res.Ok);
        Assert.Equal(("vmware", ""), (b.Hardware!.Virt, b.Hardware.Serial));
    }

    [Fact]
    public void Missing_bios_command_keeps_the_system_information()
    {
        var runner = new FakeCommandRunner().Add(HardwareCommands.System, 0,
            "{\"Manufacturer\":\"VMware, Inc.\",\"Model\":\"VMware7,1\",\"Domain\":\"x\",\"PartOfDomain\":false,\"DNSHostName\":\"h\"}");   // BIOS 명령은 미등록 → FileNotFoundException
        var (res, b) = Run(new WinHardware(runner));
        Assert.True(res.Ok);
        Assert.Equal("vmware", b.Hardware!.Virt);
    }

    [Fact]
    public void System_failure_fails_the_collector_without_a_partial_result()
    {
        var (res, b) = Run(new WinHardware(Runner("", "{}", systemExit: 1)));
        Assert.False(res.Ok);
        Assert.Null(b.Hardware);
    }

    [Fact]
    public void Control_characters_in_wmi_strings_are_stripped()
    {
        var (_, b) = Run(new WinHardware(Runner(
            "{\"Manufacturer\":\"Dell\\u0000 Inc.\",\"Model\":\"R740\\u001b[31m\",\"Domain\":\"x\",\"PartOfDomain\":false,\"DNSHostName\":\"h\"}", "{\"SerialNumber\":\"SN\\u00001\"}")));
        Assert.DoesNotContain('\0', b.Hardware!.Vendor + b.Hardware.Serial);
        Assert.DoesNotContain('\u001b', b.Hardware.Model);
    }
}
