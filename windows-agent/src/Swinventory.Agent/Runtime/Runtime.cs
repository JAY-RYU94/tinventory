using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using Microsoft.Win32;

namespace Swinventory.Agent.Runtime;

// 외부 접근(명령·레지스트리·네트워크)은 모두 인터페이스 뒤에 둔다 — 테스트는 Fake 로 대체한다.

public sealed record CommandResult(int ExitCode, string Stdout, string Stderr);

public interface ICommandRunner
{
    /// <summary>셸을 거치지 않고 실행한다. 실행 파일이 없으면 FileNotFoundException, 시간 초과는 TimeoutException.</summary>
    CommandResult Run(IReadOnlyList<string> args, TimeSpan timeout);
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    public CommandResult Run(IReadOnlyList<string> args, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo(args[0])
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args.Skip(1)) psi.ArgumentList.Add(a);   // 인자 리스트: 따옴표·공백이 그대로 전달된다(셸 해석 없음)
        Process process;
        try { process = Process.Start(psi) ?? throw new FileNotFoundException(args[0]); }
        catch (Win32Exception) { throw new FileNotFoundException(args[0]); }
        using (process)
        {
            var stdout = process.StandardOutput.ReadToEndAsync();   // 비동기로 읽어 파이프가 차서 멈추는 일을 막는다
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(timeout))
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { /* 이미 종료 */ }
                throw new TimeoutException($"{args[0]} 가 {timeout.TotalSeconds:0}초 안에 끝나지 않았다");
            }
            process.WaitForExit();
            return new CommandResult(process.ExitCode, stdout.Result, stderr.Result);
        }
    }
}

/// <summary>HKLM 읽기 전용. view: 64 또는 32(WOW6432Node). 없는 키는 Values→null, SubKeys→빈 목록.</summary>
public interface IRegistryReader
{
    IReadOnlyDictionary<string, object?>? Values(string path, int view = 64);
    IReadOnlyList<string> SubKeys(string path, int view = 64);
    bool KeyExists(string path, int view = 64);
}

public sealed class WindowsRegistryReader : IRegistryReader
{
    // 플랫폼 분석기(CA1416)가 가드를 인식하도록 레지스트리를 만지는 메서드마다 직접 검사한다.
    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("레지스트리는 Windows 에서만 읽을 수 있다");
    }

    private static RegistryKey? Open(string path, int view)
    {
        RequireWindows();
        if (!OperatingSystem.IsWindows()) return null;
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view == 32 ? RegistryView.Registry32 : RegistryView.Registry64);
        return hklm.OpenSubKey(path, writable: false);   // KEY_READ 만 — 관리자·SYSTEM 권한이 필요 없다
    }

    public IReadOnlyDictionary<string, object?>? Values(string path, int view = 64)
    {
        RequireWindows();
        if (!OperatingSystem.IsWindows()) return null;
        using var key = Open(path, view);
        if (key is null) return null;
        var values = new Dictionary<string, object?>();
        foreach (var name in key.GetValueNames()) values[name] = key.GetValue(name);   // 람다 안에서는 분석기가 가드를 인식하지 못해 루프로 쓴다
        return values;
    }

    public IReadOnlyList<string> SubKeys(string path, int view = 64)
    {
        RequireWindows();
        if (!OperatingSystem.IsWindows()) return Array.Empty<string>();
        using var key = Open(path, view);
        return key?.GetSubKeyNames() ?? Array.Empty<string>();
    }

    public bool KeyExists(string path, int view = 64)
    {
        using var key = Open(path, view);
        return key is not null;
    }
}

public sealed record ProbeAddress(string Ip, int PrefixLength);

/// <summary>InterfaceType/Status 는 System.Net.NetworkInformation 열거형의 이름("Loopback", "Up" …).</summary>
public sealed record ProbeInterface(string Name, string InterfaceType, string Status, byte[]? Mac, IReadOnlyList<ProbeAddress> Addresses);

public sealed record ProbeEndpoint(string Address, int Port);

public interface INetworkProbe
{
    IReadOnlyList<ProbeInterface> Interfaces();
    IReadOnlyList<ProbeEndpoint> TcpListeners();
    IReadOnlyList<ProbeEndpoint> UdpListeners();
}

/// <summary>관리형 API(관리자 권한·PowerShell 불필요, Linux 에서도 동작해 컨테이너에서 실제로 검증할 수 있다).</summary>
public sealed class SystemNetworkProbe : INetworkProbe
{
    public IReadOnlyList<ProbeInterface> Interfaces() =>
        NetworkInterface.GetAllNetworkInterfaces().Select(ni => new ProbeInterface(
            ni.Name, ni.NetworkInterfaceType.ToString(), ni.OperationalStatus.ToString(), ni.GetPhysicalAddress().GetAddressBytes(),
            ni.GetIPProperties().UnicastAddresses.Select(u => new ProbeAddress(Strip(u.Address), u.PrefixLength)).ToList())).ToList();

    public IReadOnlyList<ProbeEndpoint> TcpListeners() =>
        IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(e => new ProbeEndpoint(Strip(e.Address), e.Port)).ToList();

    public IReadOnlyList<ProbeEndpoint> UdpListeners() =>
        IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Select(e => new ProbeEndpoint(Strip(e.Address), e.Port)).ToList();

    private static string Strip(IPAddress address) => address.ToString().Split('%')[0];   // fe80::1%12 의 스코프 ID 제거
}
