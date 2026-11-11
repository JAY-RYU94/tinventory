using System.Globalization;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;
using Swinventory.Agent.Transport;

namespace Swinventory.Agent;

/// <summary>모든 외부 접근(레지스트리·명령·네트워크·HTTP·시계·출력)을 주입할 수 있다(테스트용).</summary>
public sealed record CliRuntime(
    IRegistryReader Registry, ICommandRunner Runner, INetworkProbe Probe, IHttpPoster? Poster, bool IsWindows,
    Action<TimeSpan> Sleep, IReadOnlyDictionary<string, string> Env, TextWriter Out, TextWriter Err,
    Func<DateTimeOffset> Clock, Func<string> Hostname)
{
    public static CliRuntime Default() => new(
        new WindowsRegistryReader(), new ProcessCommandRunner(), new SystemNetworkProbe(), null, OperatingSystem.IsWindows(),
        Thread.Sleep, Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .Where(e => e.Key is string s && s.StartsWith("SWINV_", StringComparison.Ordinal))
            .ToDictionary(e => (string)e.Key, e => e.Value?.ToString() ?? ""),
        Console.Out, Console.Error, () => DateTimeOffset.UtcNow, () => Environment.MachineName);
}

/// <summary>종료 코드: 0 성공(스풀 보관 포함) · 1 수집/실행 실패 · 2 설정·인자 오류 · 3 지원하지 않는 플랫폼 · 4 서버가 영구 거절 · 5 flush 미완료</summary>
public static class Cli
{
    public const int Ok = 0, Failed = 1, ConfigError = 2, Unsupported = 3, Rejected = 4, FlushIncomplete = 5;

    private const string Usage = """
        swinventory-agent (Windows) — 설치 소프트웨어·커널·IP·열린 포트 수집 에이전트

        사용법: swinventory-agent [collect|print|flush|run|doctor] [옵션]
          collect   한 번 수집해 전송(기본)
          print     수집 결과를 stdout 에 JSON 으로 출력(전송 안 함)
          flush     스풀에 쌓인 항목만 재전송
          run       주기적으로 수집·전송(--interval 초, 기본 3600)  운영은 작업 스케줄러 권장
          doctor    진단: 레지스트리·PowerShell·네트워크 API·설정·TLS 파일·서버 연결/토큰을 항목별로 점검(서버에는 아무것도 저장하지 않음)

        옵션: --config <파일>  --server-url <URL>  --json-dir <디렉터리>  --spool-path <디렉터리>
              --interval <초>  --max-runs <횟수>  -v  --help
        종료 코드: 0 성공 · 1 실패 · 2 설정 오류 · 3 미지원 플랫폼 · 4 서버 거절 · 5 flush 미완료
        """;

    private sealed record Options(string Command, string? Config, string? ServerUrl, string? JsonDir, string? SpoolPath, double Interval, int? MaxRuns, bool Help);

    private static Options? Parse(string[] args, CliRuntime rt)
    {
        string command = "collect", cmdSeen = "";
        string? config = null, server = null, json = null, spool = null;
        double interval = 3600;
        int? maxRuns = null;
        bool help = false;
        for (var i = 0; i < args.Length; i++)
        {
            string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{args[i]} 에 값이 필요하다");
            switch (args[i])
            {
                case "--config": config = Next(); break;
                case "--server-url": server = Next(); break;
                case "--json-dir": json = Next(); break;
                case "--spool-path": spool = Next(); break;
                case "--interval": interval = double.Parse(Next(), CultureInfo.InvariantCulture); break;
                case "--max-runs": maxRuns = int.Parse(Next(), CultureInfo.InvariantCulture); break;
                case "-v": case "--verbose": break;
                case "-h": case "--help": help = true; break;
                case "collect": case "print": case "flush": case "run": case "doctor":
                    if (cmdSeen.Length > 0) throw new ArgumentException("명령은 하나만 지정한다");
                    command = cmdSeen = args[i]; break;
                default: throw new ArgumentException($"알 수 없는 인자: {args[i]}");
            }
        }
        return new Options(command, config, server, json, spool, interval, maxRuns, help);
    }

    private static void Log(CliRuntime rt, string level, string message) =>
        rt.Err.WriteLine($"{rt.Clock().ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)} {level} {message}");

    public static int Run(string[] args, CliRuntime rt)
    {
        Options opt;
        try { opt = Parse(args, rt)!; }
        catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
        {
            rt.Err.WriteLine(ex.Message);
            rt.Err.WriteLine(Usage);
            return ConfigError;
        }
        if (opt.Help) { rt.Out.WriteLine(Usage); return Ok; }

        if (opt.Command == "doctor") return Doctor.Run(rt, opt.Config, new Dictionary<string, string?>
            { ["server_url"] = opt.ServerUrl, ["json_dir"] = opt.JsonDir, ["spool_path"] = opt.SpoolPath });

        ITransport? transport = null;
        try
        {
            var cfg = AgentConfig.Load(opt.Config, rt.Env, new Dictionary<string, string?>
                { ["server_url"] = opt.ServerUrl, ["json_dir"] = opt.JsonDir, ["spool_path"] = opt.SpoolPath });
            if (opt.Command != "print")
            {
                cfg.Validate(needServer: opt.Command == "flush");
                transport = BuildTransport(cfg, rt);
            }
        }
        catch (Exception ex) when (ex is ConfigException or IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            Log(rt, "ERROR", $"설정 오류: {ex.Message}");   // 메시지에 토큰·키 내용은 담지 않는다
            return ConfigError;
        }

        if (opt.Command == "flush")
            return ((SpoolingTransport)transport!).Flush() ? Ok : FlushIncomplete;
        if (opt.Command != "run") return CollectOnce(opt.Command == "print", transport, rt);

        var worst = Ok;
        for (var runs = 1; ; runs++)
        {
            worst = Math.Max(worst, CollectOnce(false, transport, rt));
            if (opt.MaxRuns is { } max && runs >= max) return worst;
            rt.Sleep(TimeSpan.FromSeconds(opt.Interval));
        }
    }

    private static ITransport BuildTransport(AgentConfig cfg, CliRuntime rt)
    {
        if (cfg.ServerUrl is null) return new JsonFileTransport(cfg.JsonDir!);   // Validate() 가 json_dir 존재를 보장
        var poster = rt.Poster ?? new HttpClientPoster(cfg.CaFile, cfg.ClientCert, cfg.ClientKey);
        var https = new HttpsTransport(cfg.ServerUrl, cfg.Token!, poster, TimeSpan.FromSeconds(cfg.Timeout));
        return new SpoolingTransport(https, new FileSpool(cfg.SpoolPath, cfg.SpoolMaxItems));
    }

    private static int CollectOnce(bool print, ITransport? transport, CliRuntime rt)
    {
        if (!rt.IsWindows)
        {
            Log(rt, "ERROR", "이 에이전트는 Windows 전용이다(Linux 서버는 Python 에이전트를 사용한다)");
            return Unsupported;
        }
        Snapshot snapshot;
        try { snapshot = new SnapshotOrchestrator(new WindowsProfile(rt.Registry, rt.Runner, rt.Probe), rt.Clock, rt.Hostname, typeof(Cli).Assembly.GetName().Version?.ToString(3) ?? "0").Collect(); }
        catch (Exception ex)   // host_id 조회 실패 등. run 루프를 죽이지 않는다
        {
            Log(rt, "ERROR", $"수집 실패: {ex.GetType().Name}: {ex.Message}");
            return Failed;
        }
        foreach (var (name, error) in snapshot.Errors) Log(rt, "WARNING", $"수집기 실패(계속 진행): {name}: {error}");
        if (print)
        {
            rt.Out.WriteLine(SnapshotJson.Serialize(snapshot));
            return Ok;
        }
        try
        {
            var outcome = transport!.Send(snapshot);
            Log(rt, "INFO", $"스냅샷 {(outcome == SendOutcome.Sent ? "전송 완료" : "스풀에 보관")} (host={snapshot.HostId}, packages={snapshot.Packages.Count}, errors={snapshot.Errors.Count})");
            return Ok;
        }
        catch (PermanentTransportException ex) { Log(rt, "ERROR", $"서버가 스냅샷을 거절했다: {ex.Message}"); return Rejected; }
        catch (TransportException ex) { Log(rt, "ERROR", $"전송 실패: {ex.Message}"); return Failed; }
    }
}
