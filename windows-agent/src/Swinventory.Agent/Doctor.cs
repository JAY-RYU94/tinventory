using System.Globalization;
using System.Text;
using Swinventory.Agent.Collectors;
using Swinventory.Agent.Models;
using Swinventory.Agent.Runtime;
using Swinventory.Agent.Transport;

namespace Swinventory.Agent;

/// <summary>배포 문제 진단. 항목별 PASS/FAIL/SKIP 을 출력하고 FAIL 이 하나라도 있으면 종료 코드 1.
/// 서버 점검은 빈 본문(`{}`)을 POST 한다 — 인증이 본문 검증보다 먼저라 422 면 연결·TLS·토큰이 모두 정상이고, 서버에는 아무것도 저장되지 않는다.</summary>
internal static class Doctor
{
    private sealed record Check(string Name, string Status, string Detail);

    public static int Run(CliRuntime rt, string? configPath, IReadOnlyDictionary<string, string?> overrides)
    {
        var checks = new List<Check>();
        void Add(string name, string status, string detail) => checks.Add(new Check(name, status, detail));
        void Collect(string name, ICollector collector, SnapshotBuilder builder, Func<SnapshotBuilder, string> detail)
        {
            var result = collector.Collect(builder);
            Add(name, result.Ok ? "PASS" : "FAIL", result.Ok ? detail(builder) : result.Error ?? "");
        }

        Add("플랫폼", rt.IsWindows ? "PASS" : "SKIP", rt.IsWindows ? "Windows" : "Windows 가 아니다 — 레지스트리·PowerShell 점검은 건너뜀");
        var builder = new SnapshotBuilder();
        if (rt.IsWindows)
        {
            Collect("레지스트리 읽기(OS·커널, 비특권)", new WinKernel(rt.Registry), builder, b => $"커널 {b.Kernel!.Running}, 재부팅 필요 {b.Kernel.RebootRequired}");
            Collect("레지스트리 읽기(설치 프로그램)", new WinRegistrySoftware(rt.Registry), builder, b => $"프로그램 {b.Packages.Count}개");
            Collect("PowerShell Get-HotFix", new WinHotfixSoftware(rt.Runner), builder, b => $"핫픽스 {b.Packages.Count(p => p.Source == "win_hotfix")}개");
        }
        else
        {
            Add("레지스트리 읽기", "SKIP", "Windows 가 아니다");
            Add("PowerShell Get-HotFix", "SKIP", "Windows 가 아니다");
        }
        var net = new SnapshotBuilder();
        var ifs = new WinInterfaces(rt.Probe).Collect(net);
        var ports = new WinPorts(rt.Probe).Collect(net);
        Add("네트워크 API(인터페이스·열린 포트)", ifs.Ok && ports.Ok ? "PASS" : "FAIL",
            ifs.Ok && ports.Ok ? $"인터페이스 {net.Interfaces.Count}개, 리슨 포트 {net.Ports.Count}개" : $"{ifs.Error} {ports.Error}".Trim());
        try
        {
            var probe = new Snapshot { HostId = "doctor", Hostname = "doctor", CollectedAt = rt.Clock().ToString("o", CultureInfo.InvariantCulture), AgentVersion = "0" };
            probe.Packages.Add(new PackageRecord("win_registry", "한글", "1"));
            var ok = SnapshotJson.Deserialize(SnapshotJson.Serialize(probe)).Packages[0].Name == "한글";
            Add("JSON 직렬화(트리밍 포함 빌드 점검)", ok ? "PASS" : "FAIL", ok ? "왕복 일치" : "왕복 불일치");
        }
        catch (Exception ex) { Add("JSON 직렬화(트리밍 포함 빌드 점검)", "FAIL", $"{ex.GetType().Name}: {ex.Message}"); }

        AgentConfig? cfg = null;
        try
        {
            cfg = AgentConfig.Load(configPath, rt.Env, overrides);
            if (cfg.ServerUrl is null && cfg.JsonDir is null && configPath is null) Add("설정", "SKIP", "설정 없음 — 서버 점검은 건너뜀(--config 또는 SWINV_* 지정)");
            else { cfg.Validate(false); Add("설정", "PASS", cfg.ServerUrl ?? $"json_dir={cfg.JsonDir}"); }
        }
        catch (ConfigException ex) { Add("설정", "FAIL", ex.Message); cfg = null; }   // 메시지에 토큰·키는 담기지 않는다

        if (cfg?.ServerUrl is null)
        {
            Add("TLS 파일(CA·클라이언트 인증서)", "SKIP", "서버 설정 없음");
            Add("서버 연결·토큰", "SKIP", "서버 설정 없음");
        }
        else CheckServer(rt, cfg, Add);

        var width = checks.Max(c => c.Name.Length);
        foreach (var c in checks) rt.Out.WriteLine($"{c.Status} {c.Name.PadRight(width)}  {c.Detail}");
        var failed = checks.Count(c => c.Status == "FAIL");
        rt.Out.WriteLine(failed == 0 ? "진단 통과" : $"진단 실패 {failed}건");
        return failed == 0 ? Cli.Ok : Cli.Failed;
    }

    private static void CheckServer(CliRuntime rt, AgentConfig cfg, Action<string, string, string> add)
    {
        IHttpPoster poster;
        try
        {
            poster = rt.Poster ?? new HttpClientPoster(cfg.CaFile, cfg.ClientCert, cfg.ClientKey);
            add("TLS 파일(CA·클라이언트 인증서)", "PASS", cfg.CaFile is null && cfg.ClientCert is null ? "사설 CA·mTLS 미사용(시스템 신뢰 저장소)" : "로드 성공");
        }
        catch (Exception ex) when (ex is IOException or System.Security.Cryptography.CryptographicException or ArgumentException or InvalidOperationException)
        {
            add("TLS 파일(CA·클라이언트 인증서)", "FAIL", $"{ex.GetType().Name}: 파일을 읽지 못했거나 형식이 올바르지 않다");
            add("서버 연결·토큰", "SKIP", "TLS 파일 오류");
            return;
        }
        var url = new Uri(cfg.ServerUrl!.TrimEnd('/') + "/v1/ingest");
        var headers = new Dictionary<string, string> { ["Authorization"] = $"Bearer {cfg.Token}", ["Content-Type"] = "application/json" };
        try
        {
            var status = poster.Post(url, Encoding.UTF8.GetBytes("{}"), headers, TimeSpan.FromSeconds(Math.Min(cfg.Timeout, 15))).Status;
            var (result, detail) = status switch
            {
                422 or (>= 200 and < 300) => ("PASS", $"서버 응답 {status}: 연결·토큰 정상"),
                401 => ("FAIL", "서버 응답 401: 토큰이 거부됐다(token_file 의 값과 서버의 수집 토큰을 확인)"),
                403 => ("FAIL", "서버 응답 403: 이 토큰은 수집(ingest) 권한이 없다(조회·관리자 토큰이 아닌 수집 전용 토큰을 쓴다)"),
                _ => ("FAIL", $"서버 응답 {status}: 서버·프록시 상태를 확인한다"),
            };
            add("서버 연결·토큰", result, detail);
        }
        catch (Exception ex)
        {
            var message = cfg.Token is { Length: > 0 } t ? ex.Message.Replace(t, "***", StringComparison.Ordinal) : ex.Message;
            add("서버 연결·토큰", "FAIL", $"서버에 연결하지 못했다({ex.GetType().Name}: {message}) — 주소·방화벽·프록시·인증서(CA)를 확인한다");
        }
    }
}
