using System.Text.Json;
using System.Text.RegularExpressions;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;

namespace Swinventory.Agent.Collectors;

/// <summary>장비 정보의 순수 규칙. Python 의 common/hardware.py 와 같은 규칙이며 contracts/hardware-vectors.json 으로 서로 맞춘다.</summary>
public static partial class HardwareRules
{
    // 제조사가 채우지 않고 내보내는 자리표시자 — 시리얼로 쓰면 서로 다른 장비가 같은 값으로 묶인다
    private static readonly HashSet<string> PlaceholderSerials = new(StringComparer.Ordinal)
    {
        "none", "n/a", "na", "unknown", "default string", "to be filled by o.e.m.", "not specified", "not applicable",
        "system serial number", "chassis serial number", "serial number", "null", "ffffffff", "0123456789",
    };

    // 위에서부터 처음 맞는 것(vendor·model·bios_vendor 를 이어 붙인 문자열에 적용)
    private static readonly (Regex Pattern, string Name)[] VirtPatterns =
    {
        (Rx("vmware"), "vmware"),
        (Rx("virtualbox|innotek"), "virtualbox"),
        (Rx("microsoft corporation.*virtual machine|hyper-v"), "hyperv"),
        (Rx(@"\bxen\b|hvm domu"), "xen"),
        (Rx(@"amazon ec2|\bamazon\b.*\bhvm\b"), "aws"),
        (Rx(@"google compute engine|\bgoogle\b.*compute"), "gcp"),
        (Rx("openstack"), "openstack"),
        (Rx("parallels"), "parallels"),
        (Rx("nutanix"), "ahv"),
        (Rx(@"qemu|\bkvm\b|red hat.*kvm|bochs"), "kvm"),
    };

    private static Regex Rx(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    [GeneratedRegex(@"[\x00-\x1f\x7f]")] private static partial Regex Control();
    [GeneratedRegex(@"^[0\s-]+$")] private static partial Regex Zeros();
    [GeneratedRegex(@"[\s-]+")] private static partial Regex Separators();

    /// <summary>제어문자를 없애고 양끝 공백을 다듬는다(DMI·WMI 문자열은 신뢰할 수 없는 입력).</summary>
    public static string CleanText(string? value) => Control().Replace(value ?? "", "").Trim();

    public static string CleanSerial(string? value)
    {
        var text = CleanText(value);
        return text.Length == 0 || PlaceholderSerials.Contains(text.ToLowerInvariant()) || Zeros().IsMatch(text) ? "" : text;
    }

    public static string NormalizeSerial(string? value) => Separators().Replace(CleanSerial(value), "").ToUpperInvariant();

    /// <summary>FQDN 에서 첫 라벨을 뺀 도메인(소문자). 점이 없거나 호스트 라벨이 없으면 빈 값.</summary>
    public static string DomainOf(string? fqdn)
    {
        var text = (fqdn ?? "").Trim().TrimEnd('.');
        var dot = text.IndexOf('.');
        return dot > 0 ? text[(dot + 1)..].Trim('.').ToLowerInvariant() : "";
    }

    /// <summary>(kind, virt). 우선순위: 컨테이너 > 감지 도구 > 제조사·모델 문자열 > CPU hypervisor 플래그. 근거가 없으면 unknown.</summary>
    public static (string Kind, string Virt) Classify(string vendor = "", string model = "", string biosVendor = "", bool hypervisorFlag = false,
                                                      string? detected = null, string? container = null)
    {
        if (!string.IsNullOrEmpty(container) && container != "none") return ("container", container);
        if (!string.IsNullOrEmpty(detected) && detected != "none") return ("virtual", detected);
        var haystack = $"{vendor} {model} {biosVendor}".Trim();
        foreach (var (pattern, name) in VirtPatterns)
            if (pattern.IsMatch(haystack)) return ("virtual", name);
        if (hypervisorFlag) return ("virtual", "unknown");
        return haystack.Length > 0 ? ("physical", "") : ("unknown", "");
    }
}

public static class HardwareCommands
{
    private static IReadOnlyList<string> Ps(string script) => new[]
    {
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        $"[Console]::OutputEncoding=[Text.Encoding]::UTF8; {script} | ConvertTo-Json -Compress",
    };

    // HypervisorPresent 는 Hyper-V 역할이 있는 물리 서버에서도 참이라 쓰지 않는다 — 제조사·모델 문자열로만 판정한다.
    public static readonly IReadOnlyList<string> System = Ps("Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,Domain,PartOfDomain,DNSHostName");
    // Win32_BIOS.SerialNumber 는 관리자 권한 없이 조회된다(실제 Windows 에서 LOCAL SERVICE 로는 검증하지 못했다).
    public static readonly IReadOnlyList<string> Bios = Ps("Get-CimInstance Win32_BIOS | Select-Object SerialNumber");
}

public sealed class WinHardware(ICommandRunner runner) : CollectorBase<(string System, string Bios), HardwareInfo>
{
    public override string Name => "hardware";

    protected override (string System, string Bios) Run()
    {
        var sys = runner.Run(HardwareCommands.System, TimeSpan.FromSeconds(60));
        if (sys.ExitCode != 0) throw new InvalidOperationException($"powershell exited {sys.ExitCode}: {(sys.Stderr.Length > 0 ? sys.Stderr : sys.Stdout).Trim()}");
        string bios;
        try   // 시리얼만 못 얻어도 나머지 장비 정보는 남긴다
        {
            var res = runner.Run(HardwareCommands.Bios, TimeSpan.FromSeconds(60));
            bios = res.ExitCode == 0 ? res.Stdout : "";
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { bios = ""; }
        return (sys.Stdout, bios);
    }

    private static JsonElement? First(string text)
    {
        text = text.Trim();
        if (text.Length == 0) return null;
        using var doc = JsonDocument.Parse(text);
        var root = doc.RootElement;
        // PowerShell 은 1건이면 객체, 여러 건이면 배열을 낸다
        var item = root.ValueKind == JsonValueKind.Array ? (root.GetArrayLength() > 0 ? root[0] : (JsonElement?)null) : root;
        return item?.Clone();
    }

    private static string Str(JsonElement? e, string name) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? HardwareRules.CleanText(v.GetString()) : "";

    protected override HardwareInfo Parse((string System, string Bios) raw)
    {
        var sys = First(raw.System);
        var vendor = Str(sys, "Manufacturer");
        var model = Str(sys, "Model");
        var (kind, virt) = HardwareRules.Classify(vendor, model);
        var host = Str(sys, "DNSHostName");
        var joined = sys is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty("PartOfDomain", out var p) && p.ValueKind == JsonValueKind.True;
        var domain = joined ? Str(sys, "Domain").ToLowerInvariant() : "";            // 워크그룹명은 도메인이 아니다
        var fqdn = host.Length > 0 && domain.Length > 0 ? $"{host}.{domain}" : host;
        var serial = HardwareRules.CleanSerial(Str(First(raw.Bios), "SerialNumber"));
        var derived = HardwareRules.DomainOf(fqdn);
        return new HardwareInfo(kind, virt, vendor, model, serial, fqdn, derived.Length > 0 ? derived : domain);
    }

    protected override void Contribute(SnapshotBuilder b, HardwareInfo value) => b.Hardware = value;
}
