using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;

namespace Swinventory.Agent.Collectors;

public static class WindowsKeys
{
    public const string Uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    public const string CurrentVersion = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    public const string Cryptography = @"SOFTWARE\Microsoft\Cryptography";
    public const string RebootPending = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending";
    public const string RebootRequired = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";
}

public static class WindowsCommands
{
    // Win32_Product(WMI)는 느리고 MSI 복구를 유발하므로 쓰지 않는다.
    public static readonly IReadOnlyList<string> Hotfix = new[]
    {
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-HotFix | Select-Object HotFixID | ConvertTo-Json -Compress",
    };
}

/// <summary>수집기가 결과를 담는 곳. 성공한 수집기만 값을 채운다.</summary>
public sealed class SnapshotBuilder
{
    public OsInfo? Os { get; set; }
    public KernelInfo? Kernel { get; set; }
    public List<PackageRecord> Packages { get; } = new();
    public List<NetworkInterfaceInfo> Interfaces { get; } = new();
    public List<ListeningPort> Ports { get; } = new();
    public HardwareInfo? Hardware { get; set; }
}

public sealed record CollectorResult(string Name, bool Ok, string? Error);

public interface ICollector
{
    string Name { get; }
    CollectorResult Collect(SnapshotBuilder builder);
}

/// <summary>템플릿 메서드: Run(외부 접근) → Parse(순수 변환) → Contribute(결과 반영). 어떤 예외도 실패 결과로 바꿔 다른 수집기를 막지 않는다.</summary>
public abstract class CollectorBase<TRaw, TValue> : ICollector
{
    public abstract string Name { get; }
    protected abstract TRaw Run();
    protected abstract TValue Parse(TRaw raw);
    protected abstract void Contribute(SnapshotBuilder builder, TValue value);

    public CollectorResult Collect(SnapshotBuilder builder)
    {
        try
        {
            var value = Parse(Run());   // 반영은 성공이 확정된 뒤에만(부분 결과가 남지 않게)
            Contribute(builder, value);
            return new CollectorResult(Name, true, null);
        }
        catch (Exception ex)
        {
            return new CollectorResult(Name, false, $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}

internal static class Values
{
    public static string Str(IReadOnlyDictionary<string, object?> v, string key) => v.TryGetValue(key, out var o) ? Convert.ToString(o, CultureInfo.InvariantCulture)?.Trim() ?? "" : "";

    /// <summary>DWORD 는 int, QWORD 는 long 으로 온다 — 어느 쪽이든 정수로 읽는다.</summary>
    public static long Num(IReadOnlyDictionary<string, object?> v, string key, long fallback = 0)
    {
        if (!v.TryGetValue(key, out var o) || o is null) return fallback;
        try { return Convert.ToInt64(o, CultureInfo.InvariantCulture); } catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException) { return fallback; }
    }
}

public abstract class SoftwareCollector : CollectorBase<object, List<PackageRecord>>
{
    protected abstract string Source { get; }
    public override string Name => $"software.{Source}";
    protected override void Contribute(SnapshotBuilder b, List<PackageRecord> value) => b.Packages.AddRange(value);
}

public sealed class WinRegistrySoftware(IRegistryReader registry) : SoftwareCollector
{
    protected override string Source => "win_registry";
    private static readonly (int View, string Arch)[] Views = { (64, "x64"), (32, "x86") };
    private static readonly HashSet<string> UpdateTypes = new(StringComparer.OrdinalIgnoreCase)
        { "update", "hotfix", "security update", "update rollup", "service pack", "critical update" };
    private static readonly Regex KbKey = new(@"^KB\d+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    protected override object Run()
    {
        var entries = new List<(string Arch, string Sub, IReadOnlyDictionary<string, object?> Values)>();
        foreach (var (view, arch) in Views)
            foreach (var sub in registry.SubKeys(WindowsKeys.Uninstall, view))
                if (registry.Values($@"{WindowsKeys.Uninstall}\{sub}", view) is { } vals) entries.Add((arch, sub, vals));
        return entries;
    }

    protected override List<PackageRecord> Parse(object raw)
    {
        var seen = new Dictionary<(string, string, string), PackageRecord>();
        foreach (var (arch, sub, vals) in (List<(string Arch, string Sub, IReadOnlyDictionary<string, object?> Values)>)raw)
        {
            var name = Values.Str(vals, "DisplayName");
            if (name.Length == 0) continue;
            if (Values.Num(vals, "SystemComponent") == 1 || Values.Str(vals, "ParentKeyName").Length > 0) continue;
            if (UpdateTypes.Contains(Values.Str(vals, "ReleaseType")) || KbKey.IsMatch(sub)) continue;   // 업데이트 항목은 핫픽스 수집기가 맡는다
            var version = Values.Str(vals, "DisplayVersion");
            seen.TryAdd((name, version, arch), new PackageRecord(Source, name, version, arch));
        }
        return seen.Values.ToList();
    }
}

public sealed class WinHotfixSoftware(ICommandRunner runner) : SoftwareCollector
{
    protected override string Source => "win_hotfix";

    protected override object Run()
    {
        var res = runner.Run(WindowsCommands.Hotfix, TimeSpan.FromSeconds(120));
        if (res.ExitCode != 0) throw new InvalidOperationException($"powershell exited {res.ExitCode}: {(res.Stderr.Length > 0 ? res.Stderr : res.Stdout).Trim()}");
        return res.Stdout;
    }

    protected override List<PackageRecord> Parse(object raw)
    {
        var text = ((string)raw).Trim();
        if (text.Length == 0) return new();
        using var doc = JsonDocument.Parse(text);
        // PowerShell 은 1건이면 객체, 여러 건이면 배열을 낸다
        var items = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList() : new List<JsonElement> { doc.RootElement };
        return items.Select(i => i.TryGetProperty("HotFixID", out var id) ? id.GetString()?.Trim() : null)
            .Where(id => !string.IsNullOrEmpty(id)).Distinct().Select(id => new PackageRecord(Source, id!, "")).ToList();
    }
}

public sealed class WinKernel(IRegistryReader registry) : CollectorBase<(IReadOnlyDictionary<string, object?>? Values, bool Reboot), KernelInfo>
{
    public override string Name => "kernel";

    protected override (IReadOnlyDictionary<string, object?>? Values, bool Reboot) Run() =>
        (registry.Values(WindowsKeys.CurrentVersion), registry.KeyExists(WindowsKeys.RebootPending) || registry.KeyExists(WindowsKeys.RebootRequired));

    protected override KernelInfo Parse((IReadOnlyDictionary<string, object?>? Values, bool Reboot) raw)
    {
        if (raw.Values is null || Values.Str(raw.Values, "CurrentBuildNumber").Length == 0)
            throw new InvalidOperationException($"{WindowsKeys.CurrentVersion} 에서 CurrentBuildNumber 를 읽지 못했다");
        var running = $"10.0.{Values.Str(raw.Values, "CurrentBuildNumber")}.{Values.Num(raw.Values, "UBR")}";
        return new KernelInfo(running, new[] { running }, raw.Reboot);
    }

    protected override void Contribute(SnapshotBuilder b, KernelInfo value) => b.Kernel = value;
}

public sealed class WinOs(IRegistryReader registry) : CollectorBase<IReadOnlyDictionary<string, object?>?, OsInfo>
{
    public override string Name => "os";
    protected override IReadOnlyDictionary<string, object?>? Run() => registry.Values(WindowsKeys.CurrentVersion);

    protected override OsInfo Parse(IReadOnlyDictionary<string, object?>? raw)
    {
        if (raw is null) throw new InvalidOperationException($"{WindowsKeys.CurrentVersion} 를 읽지 못했다");
        var version = new[] { "DisplayVersion", "ReleaseId", "CurrentBuildNumber" }.Select(k => Values.Str(raw, k)).FirstOrDefault(s => s.Length > 0) ?? "";
        var product = Values.Str(raw, "ProductName");
        return new OsInfo("windows", product.Length > 0 ? product : "Windows", version);
    }

    protected override void Contribute(SnapshotBuilder b, OsInfo value) => b.Os = value;
}

internal static class NetUtil
{
    /// <summary>스코프 ID 제거, IPv4 매핑 주소(::ffff:a.b.c.d)는 IPv4 로 정규화.</summary>
    public static IPAddress Parse(string ip)
    {
        var address = IPAddress.Parse(ip.Split('%')[0]);
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    public static bool IsLinkLocal(IPAddress ip) =>
        ip.AddressFamily == AddressFamily.InterNetworkV6 ? ip.IsIPv6LinkLocal : ip.GetAddressBytes() is [169, 254, ..];

    public static string Mac(byte[]? bytes) =>
        bytes is { Length: 6 } && bytes.Any(b => b != 0) ? string.Join(':', bytes.Select(b => b.ToString("x2", CultureInfo.InvariantCulture))) : "";
}

public sealed class WinInterfaces(INetworkProbe probe) : CollectorBase<IReadOnlyList<ProbeInterface>, List<NetworkInterfaceInfo>>
{
    public override string Name => "network.interfaces";
    protected override IReadOnlyList<ProbeInterface> Run() => probe.Interfaces();

    protected override List<NetworkInterfaceInfo> Parse(IReadOnlyList<ProbeInterface> raw)
    {
        var result = new List<NetworkInterfaceInfo>();
        foreach (var pi in raw)
        {
            if (pi.InterfaceType == "Loopback") continue;
            // 전역 주소만(루프백·링크 로컬은 식별 정보가 아니고 잡음이다). IPv4 먼저, 같은 체계 안에서는 숫자순
            var addresses = pi.Addresses.Select(a => (Ip: NetUtil.Parse(a.Ip), a.PrefixLength))
                .Where(a => !IPAddress.IsLoopback(a.Ip) && !NetUtil.IsLinkLocal(a.Ip))
                .OrderBy(a => a.Ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ThenBy(a => Convert.ToHexString(a.Ip.GetAddressBytes()))
                .Select(a => $"{a.Ip}/{a.PrefixLength}").ToList();
            var mac = NetUtil.Mac(pi.Mac);
            if (mac.Length == 0 && addresses.Count == 0) continue;     // MAC 도 주소도 없는 가상 장치(isatap 등)는 식별 정보가 없는 잡음
            var state = pi.Status switch { "Up" => "up", "Down" or "NotPresent" or "LowerLayerDown" => "down", _ => "unknown" };
            result.Add(new NetworkInterfaceInfo(pi.Name, mac, state, addresses));
        }
        return result.OrderBy(i => i.Name, StringComparer.Ordinal).ToList();
    }

    protected override void Contribute(SnapshotBuilder b, List<NetworkInterfaceInfo> value) => b.Interfaces.AddRange(value);
}

public sealed class WinPorts(INetworkProbe probe, int ephemeralStart = 49152) : CollectorBase<(IReadOnlyList<ProbeEndpoint> Tcp, IReadOnlyList<ProbeEndpoint> Udp), List<ListeningPort>>
{
    public override string Name => "network.ports";
    protected override (IReadOnlyList<ProbeEndpoint> Tcp, IReadOnlyList<ProbeEndpoint> Udp) Run() => (probe.TcpListeners(), probe.UdpListeners());

    protected override List<ListeningPort> Parse((IReadOnlyList<ProbeEndpoint> Tcp, IReadOnlyList<ProbeEndpoint> Udp) raw)
    {
        var found = new HashSet<ListeningPort>();
        foreach (var e in raw.Tcp) found.Add(new ListeningPort("tcp", e.Port, NetUtil.Parse(e.Address).ToString()));
        // UDP 는 '리슨' 개념이 없다: 시스템이 클라이언트 소켓에 임시로 나눠주는 동적 포트 범위는 서비스가 아니라 제외한다(TCP 리스너는 실제 서비스라 유지)
        foreach (var e in raw.Udp.Where(e => e.Port < ephemeralStart)) found.Add(new ListeningPort("udp", e.Port, NetUtil.Parse(e.Address).ToString()));
        return found.OrderBy(p => p.Proto, StringComparer.Ordinal).ThenBy(p => p.Port).ThenBy(p => p.Bind, StringComparer.Ordinal).ToList();
    }

    protected override void Contribute(SnapshotBuilder b, List<ListeningPort> value) => b.Ports.AddRange(value);
}
