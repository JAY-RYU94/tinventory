using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Swinventory.Agent.Models;

// 서버와의 계약(contracts/snapshot.v1.schema.json)과 같은 모양이다. JSON 키는 snake_case.

public sealed record PackageRecord(string Source, string Name, string Version, string Arch = "");

public sealed record OsInfo(string Family, string Name, string Version);

public sealed record KernelInfo(string Running, IReadOnlyList<string> Installed, bool RebootRequired);

/// <summary>인터페이스 1개. Addresses 는 CIDR 문자열(10.0.0.5/24)이며 전역 주소만 담는다.</summary>
public sealed record NetworkInterfaceInfo(string Name, string Mac, string State, IReadOnlyList<string> Addresses);

/// <summary>리슨 중인 포트 = (프로토콜, 포트, 바인딩 주소).</summary>
public sealed record ListeningPort(string Proto, int Port, string Bind);

/// <summary>장비 정보. Kind: physical | virtual | container | unknown(판정 근거 없음 — 추측하지 않는다). Domain 은 FQDN 에서 호스트 이름을 뺀 부분이며 워크그룹명은 도메인이 아니다.</summary>
public sealed record HardwareInfo(string Kind = "unknown", string Virt = "", string Vendor = "", string Model = "", string Serial = "", string Fqdn = "", string Domain = "");

/// <summary>한 회차 수집 결과. Collected = 성공한 수집기, Errors = 실패한 수집기와 사유(서버는 성공한 source 만 동기화한다).</summary>
public sealed class Snapshot
{
    public string HostId { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string CollectedAt { get; set; } = "";
    public string AgentVersion { get; set; } = "";
    public OsInfo? Os { get; set; }
    public KernelInfo? Kernel { get; set; }
    public List<PackageRecord> Packages { get; set; } = new();
    public List<NetworkInterfaceInfo> Interfaces { get; set; } = new();
    public List<ListeningPort> Ports { get; set; } = new();
    public HardwareInfo? Hardware { get; set; }
    public List<string> Collected { get; set; } = new();
    public Dictionary<string, string> Errors { get; set; } = new();
}

[JsonSerializable(typeof(Snapshot))]
internal sealed partial class SnapshotJsonContext : JsonSerializerContext;

public static class SnapshotJson
{
    // 리플렉션 없는 source generator 직렬화(트리밍 안전). 한글이 \uXXXX 로 이스케이프되지 않게 한다(JSON 본문이라 HTML 이스케이프 불필요).
    private static readonly SnapshotJsonContext Context = new(new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNameCaseInsensitive = true,
    });

    public static string Serialize(Snapshot snapshot) => JsonSerializer.Serialize(snapshot, Context.Snapshot);

    public static Snapshot Deserialize(string json) =>
        JsonSerializer.Deserialize(json, Context.Snapshot) ?? throw new JsonException("빈 스냅샷");
}
