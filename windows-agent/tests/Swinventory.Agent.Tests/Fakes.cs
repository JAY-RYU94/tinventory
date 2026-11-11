using System.Text;
using Swinventory.Agent;
using Swinventory.Agent.Runtime;
using Swinventory.Agent.Transport;

namespace Swinventory.Agent.Tests;

/// <summary>등록되지 않은 명령은 실제 환경처럼 FileNotFoundException.</summary>
internal sealed class FakeCommandRunner : ICommandRunner
{
    private readonly Dictionary<string, CommandResult> _responses = new();
    public List<string> Calls { get; } = new();

    public static string Key(IEnumerable<string> args) => string.Join('\u001f', args);

    public FakeCommandRunner Add(IReadOnlyList<string> args, int exit, string stdout = "", string stderr = "")
    {
        _responses[Key(args)] = new CommandResult(exit, stdout, stderr);
        return this;
    }

    public CommandResult Run(IReadOnlyList<string> args, TimeSpan timeout)
    {
        Calls.Add(Key(args));
        return _responses.TryGetValue(Key(args), out var r) ? r : throw new FileNotFoundException(args[0]);
    }
}

internal sealed class FakeRegistry : IRegistryReader
{
    private readonly Dictionary<(string, int), (string Path, Dictionary<string, object?> Values)> _keys = new();
    private static (string, int) Norm(string path, int view) => (path.Trim('\\').ToLowerInvariant(), view);

    public FakeRegistry Add(string path, int view, Dictionary<string, object?>? values = null)
    {
        _keys[Norm(path, view)] = (path.Trim('\\'), values ?? new());
        return this;
    }

    public IReadOnlyDictionary<string, object?>? Values(string path, int view = 64) =>
        _keys.TryGetValue(Norm(path, view), out var e) ? new Dictionary<string, object?>(e.Values) : null;

    public IReadOnlyList<string> SubKeys(string path, int view = 64)
    {
        var parent = path.Trim('\\');
        var prefix = parent.ToLowerInvariant() + "\\";
        return _keys.Where(kv => kv.Key.Item2 == view && kv.Key.Item1.StartsWith(prefix, StringComparison.Ordinal)
                                 && !kv.Key.Item1[prefix.Length..].Contains('\\'))
            .Select(kv => kv.Value.Path[(parent.Length + 1)..]).ToList();
    }

    public bool KeyExists(string path, int view = 64) => _keys.ContainsKey(Norm(path, view));
}

internal sealed class FakeProbe : INetworkProbe
{
    public List<ProbeInterface> InterfaceList { get; } = new();
    public List<ProbeEndpoint> Tcp { get; } = new();
    public List<ProbeEndpoint> Udp { get; } = new();
    public Exception? Fail { get; set; }

    public IReadOnlyList<ProbeInterface> Interfaces() => Fail is null ? InterfaceList : throw Fail;
    public IReadOnlyList<ProbeEndpoint> TcpListeners() => Fail is null ? Tcp : throw Fail;
    public IReadOnlyList<ProbeEndpoint> UdpListeners() => Fail is null ? Udp : throw Fail;
}

/// <summary>응답(HttpResult) 또는 예외를 순서대로 돌려준다. 마지막 항목은 반복된다.</summary>
internal sealed class FakePoster : IHttpPoster
{
    private readonly Queue<object> _script;
    private object _last;
    public List<(Uri Url, byte[] Body, IReadOnlyDictionary<string, string> Headers, TimeSpan Timeout)> Requests { get; } = new();

    public FakePoster(params object[] script)
    {
        _script = new Queue<object>(script);
        _last = script.Length > 0 ? script[^1] : new HttpResult(200, Array.Empty<byte>());
    }

    public static HttpResult Ok() => new(200, Encoding.UTF8.GetBytes("{}"));
    public static HttpResult Status(int code, string body = "") => new(code, Encoding.UTF8.GetBytes(body));

    public HttpResult Post(Uri url, byte[] body, IReadOnlyDictionary<string, string> headers, TimeSpan timeout)
    {
        Requests.Add((url, body, headers, timeout));
        var next = _script.Count > 0 ? _script.Dequeue() : _last;
        _last = next;
        return next is Exception e ? throw e : (HttpResult)next;
    }
}

internal static class Fx
{
    public static readonly DateTimeOffset Now = new(2026, 11, 5, 1, 2, 3, TimeSpan.Zero);

    public static Models.Snapshot Snap(int second, string host = "h") => new()
    {
        HostId = host, Hostname = "web01", CollectedAt = $"2026-11-05T00:00:{second:00}+00:00",
        AgentVersion = "0.2.0", Collected = new List<string> { "os" },
    };

    public static string TempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), "swinv-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }
}
