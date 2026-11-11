using System.Globalization;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Swinventory.Agent.Models;

namespace Swinventory.Agent.Transport;

/// <summary>재시도하면 성공할 수 있는 실패(네트워크·5xx·인증 설정 오류 등).</summary>
public class TransportException(string message) : Exception(message);

/// <summary>같은 내용을 다시 보내도 소용없는 거절(스키마 위반·본문 초과). 스풀하지 않고 격리한다.</summary>
public sealed class PermanentTransportException(string message) : TransportException(message);

public enum SendOutcome { Sent, Spooled }

public interface ITransport
{
    SendOutcome Send(Snapshot snapshot);
}

public sealed record HttpResult(int Status, byte[] Body);

/// <summary>HTTP POST 추상화. 4xx/5xx 도 예외가 아니라 응답으로 돌려주고, 연결 실패·시간 초과만 예외다.</summary>
public interface IHttpPoster
{
    HttpResult Post(Uri url, byte[] body, IReadOnlyDictionary<string, string> headers, TimeSpan timeout);
}

public sealed class HttpClientPoster : IHttpPoster, IDisposable
{
    private readonly HttpClient _client;
    private readonly X509Certificate2Collection? _roots;
    private readonly X509Certificate2? _clientCertificate;

    /// <summary>사설 CA(caFile, PEM)와 mTLS(clientCert/clientKey, PEM)를 지원한다. 파일 문제는 생성 시점에 예외로 드러난다(CLI 가 설정 오류로 보고).</summary>
    public HttpClientPoster(string? caFile, string? clientCert, string? clientKey)
    {
        if (caFile is not null)
        {
            _roots = new X509Certificate2Collection();
            _roots.ImportFromPemFile(caFile);
            if (_roots.Count == 0) throw new InvalidOperationException($"CA 파일에 인증서가 없다: {caFile}");
        }
        if (clientCert is not null)
        {
            using var pem = X509Certificate2.CreateFromPemFile(clientCert, clientKey);
            _clientCertificate = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pfx), null);   // Windows(SChannel)는 PEM 에서 읽은 임시 키를 쓰지 못해 한 번 내보내 다시 읽는다
        }
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,   // Bearer 토큰을 들고 다른 곳으로 따라가면 유출된다
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = Validate,
                ClientCertificates = _clientCertificate is null ? null : new X509CertificateCollection { _clientCertificate },
            },
        };
        _client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };   // 시간 제한은 요청마다 CancellationToken 으로 건다
    }

    private bool Validate(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None) return true;                      // 시스템 신뢰 저장소로 통과
        if (_roots is null || cert is null) return false;
        // 사설 CA 를 지정해도 호스트명 검증은 그대로 유지한다 — 체인 오류만 우리 CA 로 다시 검증한다
        if ((errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
        using var custom = new X509Chain();
        custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        custom.ChainPolicy.CustomTrustStore.AddRange(_roots);
        custom.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;       // 사설 CA 는 보통 CRL/OCSP 가 없다
        return custom.Build(new X509Certificate2(cert));
    }

    public HttpResult Post(Uri url, byte[] body, IReadOnlyDictionary<string, string> headers, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new ByteArrayContent(body) };
        foreach (var (k, v) in headers)
            if (!k.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) request.Headers.TryAddWithoutValidation(k, v);
        request.Content.Headers.TryAddWithoutValidation("Content-Type", headers.GetValueOrDefault("Content-Type", "application/json"));
        using var response = _client.Send(request, HttpCompletionOption.ResponseContentRead, cts.Token);
        using var ms = new MemoryStream();
        using (var stream = response.Content.ReadAsStream(cts.Token)) stream.CopyTo(ms);
        return new HttpResult((int)response.StatusCode, ms.ToArray());
    }

    public void Dispose()
    {
        _client.Dispose();
        _clientCertificate?.Dispose();
    }
}

public sealed class HttpsTransport(string baseUrl, string token, IHttpPoster poster, TimeSpan timeout) : ITransport
{
    private static readonly HashSet<int> PermanentStatuses = new() { 400, 413, 422 };   // 401/403(토큰 교정 후 복구)·404(URL 교정)·429·5xx 는 재시도 대상
    private readonly Uri _url = new(baseUrl.TrimEnd('/') + "/v1/ingest");

    private string Redact(string text) => token.Length > 0 ? text.Replace(token, "***", StringComparison.Ordinal) : text;

    public SendOutcome Send(Snapshot snapshot)
    {
        var body = Encoding.UTF8.GetBytes(SnapshotJson.Serialize(snapshot));
        var headers = new Dictionary<string, string> { ["Authorization"] = $"Bearer {token}", ["Content-Type"] = "application/json" };
        HttpResult response;
        try { response = poster.Post(_url, body, headers, timeout); }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException or TimeoutException
                                       or System.Security.Authentication.AuthenticationException or System.Net.Sockets.SocketException)
        {
            throw new TransportException($"request failed: {ex.GetType().Name}: {Redact(ex.Message)}");   // 토큰이 메시지에 섞여도 지운다
        }
        if (response.Status is >= 200 and < 300) return SendOutcome.Sent;
        var detail = Redact(Encoding.UTF8.GetString(response.Body, 0, Math.Min(response.Body.Length, 200)));
        var message = $"server responded {response.Status.ToString(CultureInfo.InvariantCulture)}: {detail}";
        throw PermanentStatuses.Contains(response.Status) ? new PermanentTransportException(message) : new TransportException(message);
    }
}

public sealed record SpoolItem(string Path, Snapshot Snapshot);

/// <summary>전송 실패분 보관소(디렉터리 + JSON 파일, NuGet 의존성 없음). 파일명이 수집 시각 순이라 오래된 것부터 꺼낸다.
/// 영구 거절·손상 항목은 rejected 폴더로 격리해 큐를 막지 않는다. 쓰기는 임시 파일에 쓴 뒤 이름을 바꿔 반쪽 파일을 남기지 않는다.</summary>
public sealed class FileSpool
{
    private readonly string _dir;
    private readonly string _rejected;
    private readonly int _max;

    public FileSpool(string dir, int maxItems)
    {
        _dir = dir;
        _rejected = Path.Combine(dir, "rejected");
        _max = maxItems;
        Create(dir);
    }

    // Unix 에서는 소유자만(0700). Windows 는 설치 스크립트가 ACL 로 제한한다.
    private static void Create(string path)
    {
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
        else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    internal static string Stamp(string collectedAt) =>
        DateTimeOffset.TryParse(collectedAt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)
            ? t.ToUniversalTime().ToString("yyyyMMdd'T'HHmmssfffffff'Z'", CultureInfo.InvariantCulture)
            : "00000000T0000000000000Z";

    private IEnumerable<string> Files() => Directory.GetFiles(_dir, "*.json").OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal);

    public int Count => Files().Count();
    public int RejectedCount => Directory.Exists(_rejected) ? Directory.GetFiles(_rejected, "*.json").Length : 0;

    public void Put(Snapshot snapshot)
    {
        var final = Path.Combine(_dir, $"{Stamp(snapshot.CollectedAt)}-{Guid.NewGuid():N}.json");
        var tmp = final + ".tmp";
        File.WriteAllText(tmp, SnapshotJson.Serialize(snapshot), new UTF8Encoding(false));
        File.Move(tmp, final);
        foreach (var old in Files().Take(Math.Max(0, Files().Count() - _max))) File.Delete(old);   // 상한을 넘으면 가장 오래된 것부터 버린다
    }

    public List<SpoolItem> Oldest(int limit)
    {
        var items = new List<SpoolItem>();
        foreach (var file in Files().ToList())
        {
            Snapshot snapshot;
            try { snapshot = SnapshotJson.Deserialize(File.ReadAllText(file, Encoding.UTF8)); }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or ArgumentException)
            {
                MoveToRejected(file, "corrupt payload");
                continue;
            }
            items.Add(new SpoolItem(file, snapshot));
            if (items.Count >= limit) break;
        }
        return items;
    }

    public void Delete(SpoolItem item) => File.Delete(item.Path);

    public void Reject(SpoolItem item, string reason) => MoveToRejected(item.Path, reason);

    private void MoveToRejected(string file, string reason)
    {
        Create(_rejected);
        var target = Path.Combine(_rejected, Path.GetFileName(file));
        File.Move(file, target, overwrite: true);
        File.WriteAllText(target + ".reason.txt", reason.Length > 500 ? reason[..500] : reason);
    }
}

/// <summary>실패 시 스풀에 보관하고 다음 기회에 오래된 순으로 재전송하는 데코레이터. 스풀이 비워지지 않았으면 현재 스냅샷은 항상 맨 뒤에 들어간다.</summary>
public sealed class SpoolingTransport(ITransport inner, FileSpool spool) : ITransport
{
    /// <summary>모두 비우면 true, 재시도 가능한 실패로 멈추면 false.</summary>
    public bool Flush()
    {
        while (true)
        {
            var items = spool.Oldest(50);
            if (items.Count == 0) return true;
            foreach (var item in items)
            {
                try { inner.Send(item.Snapshot); }
                catch (PermanentTransportException ex) { spool.Reject(item, ex.Message); continue; }
                catch (TransportException) { return false; }
                spool.Delete(item);
            }
        }
    }

    public SendOutcome Send(Snapshot snapshot)
    {
        if (!Flush())
        {
            spool.Put(snapshot);
            return SendOutcome.Spooled;
        }
        try { return inner.Send(snapshot); }
        catch (PermanentTransportException) { throw; }   // 같은 내용을 다시 보내도 소용없으므로 스풀하지 않는다
        catch (TransportException)
        {
            spool.Put(snapshot);
            return SendOutcome.Spooled;
        }
    }
}

/// <summary>개발용: 서버 대신 디렉터리에 JSON 으로 쓴다.</summary>
public sealed class JsonFileTransport(string directory) : ITransport
{
    public SendOutcome Send(Snapshot snapshot)
    {
        Directory.CreateDirectory(directory);
        var final = Path.Combine(directory, $"snapshot-{FileSpool.Stamp(snapshot.CollectedAt)}-{Guid.NewGuid().ToString("N")[..8]}.json");
        var tmp = final + ".tmp";
        File.WriteAllText(tmp, SnapshotJson.Serialize(snapshot), new UTF8Encoding(false));
        File.Move(tmp, final);
        return SendOutcome.Sent;
    }
}
