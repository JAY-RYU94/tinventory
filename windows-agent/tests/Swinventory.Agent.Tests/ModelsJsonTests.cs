using System.Text.Json;
using Swinventory.Agent.Models;

namespace Swinventory.Agent.Tests;

public class ModelsJsonTests
{
    private static string Golden(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "golden", name));

    /// <summary>키 순서와 공백을 무시하고 JSON 의미가 같은지 비교한다.</summary>
    private static bool SameJson(string a, string b)
    {
        using var da = JsonDocument.Parse(a);
        using var db = JsonDocument.Parse(b);
        return Eq(da.RootElement, db.RootElement);
    }

    private static bool Eq(JsonElement a, JsonElement b)
    {
        if (a.ValueKind != b.ValueKind) return false;
        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var pa = a.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                var pb = b.EnumerateObject().ToDictionary(p => p.Name, p => p.Value);
                return pa.Count == pb.Count && pa.All(kv => pb.TryGetValue(kv.Key, out var o) && Eq(kv.Value, o));
            case JsonValueKind.Array:
                var la = a.EnumerateArray().ToList();
                var lb = b.EnumerateArray().ToList();
                return la.Count == lb.Count && la.Zip(lb).All(t => Eq(t.First, t.Second));
            default:
                return a.GetRawText() == b.GetRawText();
        }
    }

    [Fact]
    public void Golden_snapshot_roundtrips_to_the_same_json_as_the_python_server_contract()
    {
        var golden = Golden("snapshot.debian.json");
        var snap = SnapshotJson.Deserialize(golden);
        Assert.Equal("web01", snap.Hostname);
        Assert.Equal("5.15.0-91-generic", snap.Kernel!.Running);
        Assert.Equal(new[] { "10.0.0.5/24", "2001:db8::5/64" }, snap.Interfaces[0].Addresses);
        Assert.Equal(("tcp", 22, "::"), (snap.Ports[1].Proto, snap.Ports[1].Port, snap.Ports[1].Bind));
        Assert.True(SameJson(golden, SnapshotJson.Serialize(snap)), "직렬화 결과가 계약 골든과 다르다");
        Assert.Equal(new HardwareInfo("virtual", "vmware", "VMware, Inc.", "VMware7,1", "VMware-56 4d 5c 7e", "web01.corp.example.com", "corp.example.com"), snap.Hardware);
    }

    [Fact]
    public void Property_names_are_snake_case_and_null_sections_are_emitted_as_null()
    {
        var json = SnapshotJson.Serialize(Fx.Snap(1));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        foreach (var key in new[] { "host_id", "hostname", "collected_at", "agent_version", "os", "kernel", "packages", "interfaces", "ports", "hardware", "collected", "errors" })
            Assert.True(root.TryGetProperty(key, out _), key);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("os").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("kernel").ValueKind);
    }

    [Fact]
    public void Nested_names_match_the_contract()
    {
        var snap = Fx.Snap(1);
        snap.Kernel = new KernelInfo("10.0.1.2", new[] { "10.0.1.2" }, true);
        snap.Packages.Add(new PackageRecord("win_registry", "Git", "2.45.0", "x64"));
        snap.Interfaces.Add(new NetworkInterfaceInfo("Ethernet", "00:15:5d:01:02:03", "up", new[] { "10.1.2.3/24" }));
        snap.Ports.Add(new ListeningPort("tcp", 135, "0.0.0.0"));
        snap.Errors["software.win_hotfix"] = "boom";
        using var doc = JsonDocument.Parse(SnapshotJson.Serialize(snap));
        var r = doc.RootElement;
        Assert.True(r.GetProperty("kernel").GetProperty("reboot_required").GetBoolean());
        Assert.Equal("x64", r.GetProperty("packages")[0].GetProperty("arch").GetString());
        Assert.Equal("00:15:5d:01:02:03", r.GetProperty("interfaces")[0].GetProperty("mac").GetString());
        Assert.Equal(135, r.GetProperty("ports")[0].GetProperty("port").GetInt32());
        Assert.Equal("boom", r.GetProperty("errors").GetProperty("software.win_hotfix").GetString());
    }

    [Fact]
    public void Legacy_v1_snapshot_without_network_sections_still_loads()
    {
        var snap = SnapshotJson.Deserialize(Golden("snapshot.debian.v1-legacy.json"));
        Assert.Empty(snap.Interfaces);
        Assert.Empty(snap.Ports);
    }

    [Fact]
    public void Non_ascii_text_is_not_escaped_and_survives_a_roundtrip()
    {
        var snap = Fx.Snap(1);
        snap.Hostname = "서버-한글";
        var json = SnapshotJson.Serialize(snap);
        Assert.Contains("서버-한글", json);
        Assert.Equal("서버-한글", SnapshotJson.Deserialize(json).Hostname);
    }
}
