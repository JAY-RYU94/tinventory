using System.Globalization;
using Swinventory.Agent.Collectors;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;

namespace Swinventory.Agent;

/// <summary>플랫폼별 수집기 조합과 host_id 제공자(추상 팩토리).</summary>
public interface IPlatformProfile
{
    string HostId();
    IReadOnlyList<ICollector> Collectors();
}

public sealed class WindowsProfile(IRegistryReader registry, ICommandRunner runner, INetworkProbe probe) : IPlatformProfile
{
    public string HostId()
    {
        var guid = registry.Values(WindowsKeys.Cryptography, 64) is { } v && v.TryGetValue("MachineGuid", out var o) ? Convert.ToString(o, CultureInfo.InvariantCulture)?.Trim() : null;
        return string.IsNullOrEmpty(guid) ? throw new InvalidOperationException($"MachineGuid 를 읽지 못했다({WindowsKeys.Cryptography})") : guid;
    }

    public IReadOnlyList<ICollector> Collectors() => new ICollector[]
    {
        new WinOs(registry), new WinKernel(registry),
        new WinRegistrySoftware(registry), new WinHotfixSoftware(runner),
        new WinInterfaces(probe), new WinPorts(probe), new WinHardware(runner),
    };
}

/// <summary>프로필의 수집기를 모두 실행해 Snapshot 을 조립한다. 수집기 하나가 실패해도 나머지는 계속한다.</summary>
public sealed class SnapshotOrchestrator(IPlatformProfile profile, Func<DateTimeOffset> clock, Func<string> hostname, string agentVersion)
{
    public Snapshot Collect()
    {
        var snapshot = new Snapshot
        {
            HostId = profile.HostId(),
            Hostname = hostname(),
            // 서버는 (host_id, collected_at) 으로 중복을 판정한다. 소수 초는 0 이 아닐 때만 붙는다(.FFFFFFF)
            CollectedAt = clock().ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFFFzzz", CultureInfo.InvariantCulture),
            AgentVersion = agentVersion,
        };
        var builder = new SnapshotBuilder();
        foreach (var collector in profile.Collectors())
        {
            CollectorResult result;
            try { result = collector.Collect(builder); }
            catch (Exception ex) { result = new CollectorResult(collector.Name, false, $"{ex.GetType().Name}: {ex.Message}"); }   // 수집기 구현이 예외를 새어 보내도 격리한다
            if (result.Ok) snapshot.Collected.Add(result.Name);
            else snapshot.Errors[result.Name] = result.Error ?? "unknown error";
        }
        snapshot.Os = builder.Os;
        snapshot.Kernel = builder.Kernel;
        snapshot.Packages = builder.Packages;
        snapshot.Interfaces = builder.Interfaces;
        snapshot.Ports = builder.Ports;
        snapshot.Hardware = builder.Hardware;
        return snapshot;
    }
}
