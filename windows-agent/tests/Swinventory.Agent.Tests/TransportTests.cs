using System.Text;
using System.Text.Json;
using Swinventory.Agent.Models;
using Swinventory.Agent.Transport;

namespace Swinventory.Agent.Tests;

public class HttpsTransportTests
{
    [Fact]
    public void Posts_json_with_bearer_token_to_the_ingest_endpoint()
    {
        var poster = new FakePoster(FakePoster.Ok());
        var t = new HttpsTransport("https://inv.example.com:8443/", "secret-token", poster, TimeSpan.FromSeconds(7));
        Assert.Equal(SendOutcome.Sent, t.Send(Fx.Snap(1)));
        var req = poster.Requests.Single();
        Assert.Equal("https://inv.example.com:8443/v1/ingest", req.Url.ToString());
        Assert.Equal("Bearer secret-token", req.Headers["Authorization"]);
        Assert.Equal("application/json", req.Headers["Content-Type"]);
        Assert.Equal(TimeSpan.FromSeconds(7), req.Timeout);
        Assert.Equal(SnapshotJson.Serialize(Fx.Snap(1)), Encoding.UTF8.GetString(req.Body));
    }

    [Theory]
    [InlineData(401)] [InlineData(403)] [InlineData(404)] [InlineData(408)] [InlineData(429)]
    [InlineData(500)] [InlineData(502)] [InlineData(503)] [InlineData(302)]
    public void Retryable_statuses(int status)
    {
        var t = new HttpsTransport("https://x", "tok", new FakePoster(FakePoster.Status(status, "nope")), TimeSpan.FromSeconds(5));
        var ex = Assert.Throws<TransportException>(() => t.Send(Fx.Snap(1)));
        Assert.IsNotType<PermanentTransportException>(ex);
    }

    [Theory]
    [InlineData(400)] [InlineData(413)] [InlineData(422)]
    public void Permanent_statuses(int status)
    {
        var t = new HttpsTransport("https://x", "tok", new FakePoster(FakePoster.Status(status, "bad")), TimeSpan.FromSeconds(5));
        Assert.Throws<PermanentTransportException>(() => t.Send(Fx.Snap(1)));
    }

    [Fact]
    public void Network_errors_are_retryable_and_never_leak_the_token()
    {
        var t = new HttpsTransport("https://x", "super-secret", new FakePoster(new HttpRequestException("refused super-secret?")), TimeSpan.FromSeconds(5));
        var ex = Assert.Throws<TransportException>(() => t.Send(Fx.Snap(1)));
        Assert.IsNotType<PermanentTransportException>(ex);
        Assert.DoesNotContain("super-secret", ex.Message);
    }

    [Fact]
    public void Timeouts_and_io_errors_are_retryable()
    {
        foreach (Exception e in new Exception[] { new TaskCanceledException("timeout"), new IOException("reset"), new System.Security.Authentication.AuthenticationException("tls") })
        {
            var t = new HttpsTransport("https://x", "tok", new FakePoster(e), TimeSpan.FromSeconds(5));
            Assert.IsNotType<PermanentTransportException>(Assert.Throws<TransportException>(() => t.Send(Fx.Snap(1))));
        }
    }

    [Fact]
    public void Error_message_truncates_the_response_body()
    {
        var t = new HttpsTransport("https://x", "tok", new FakePoster(FakePoster.Status(500, new string('x', 5000))), TimeSpan.FromSeconds(5));
        Assert.True(Assert.Throws<TransportException>(() => t.Send(Fx.Snap(1))).Message.Length < 400);
    }
}

public class FileSpoolTests : IDisposable
{
    private readonly string _dir = Fx.TempDir();
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private static string Second(Snapshot s) => s.CollectedAt.Substring(17, 2);

    [Fact]
    public void Oldest_first_by_collected_at_regardless_of_insertion_order_and_delete()
    {
        var sp = new FileSpool(Path.Combine(_dir, "s"), 10);
        foreach (var n in new[] { 3, 1, 2 }) sp.Put(Fx.Snap(n));
        Assert.Equal(new[] { "01", "02", "03" }, sp.Oldest(10).Select(i => Second(i.Snapshot)));
        sp.Delete(sp.Oldest(1)[0]);
        Assert.Equal(2, sp.Count);
    }

    [Fact]
    public void Cap_drops_the_oldest_items()
    {
        var sp = new FileSpool(Path.Combine(_dir, "s"), 3);
        for (var n = 1; n <= 5; n++) sp.Put(Fx.Snap(n));
        Assert.Equal(3, sp.Count);
        Assert.Equal("03", Second(sp.Oldest(10)[0].Snapshot));
    }

    [Fact]
    public void Reject_moves_to_dead_letter_and_corrupt_files_are_quarantined()
    {
        var path = Path.Combine(_dir, "s");
        var sp = new FileSpool(path, 10);
        sp.Put(Fx.Snap(1));
        sp.Put(Fx.Snap(2));
        sp.Reject(sp.Oldest(1)[0], "422");
        Assert.Equal((1, 1), (sp.Count, sp.RejectedCount));
        File.WriteAllText(Path.Combine(path, "00000000T000000000000Z-broken.json"), "{broken");
        Assert.Equal(new[] { "02" }, sp.Oldest(10).Select(i => Second(i.Snapshot)));
        Assert.Equal(2, sp.RejectedCount);
    }

    [Fact]
    public void Same_timestamp_snapshots_do_not_overwrite_each_other()
    {
        var sp = new FileSpool(Path.Combine(_dir, "s"), 10);
        sp.Put(Fx.Snap(1)); sp.Put(Fx.Snap(1));
        Assert.Equal(2, sp.Count);
    }

    [Fact]
    public void Spool_directory_is_private_on_unix()
    {
        if (OperatingSystem.IsWindows()) return;     // Windows 는 설치 스크립트가 ACL 로 제한한다
        var path = Path.Combine(_dir, "private");
        new FileSpool(path, 3).Put(Fx.Snap(1));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(path));
    }

    [Fact]
    public void Invalid_collected_at_still_spools_and_does_not_crash()
    {
        var sp = new FileSpool(Path.Combine(_dir, "s"), 3);
        var s = Fx.Snap(1);
        s.CollectedAt = "not-a-date";
        sp.Put(s);
        Assert.Equal(1, sp.Count);
    }
}

public class SpoolingTransportTests : IDisposable
{
    private readonly string _dir = Fx.TempDir();
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private sealed class Scripted(params Exception?[] steps) : ITransport
    {
        private readonly Queue<Exception?> _steps = new(steps);
        public List<string> Sent { get; } = new();
        public SendOutcome Send(Snapshot snapshot)
        {
            var step = _steps.Count > 0 ? _steps.Dequeue() : null;
            if (step is not null) throw step;
            Sent.Add(snapshot.CollectedAt.Substring(17, 2));
            return SendOutcome.Sent;
        }
    }

    private (SpoolingTransport T, Scripted Inner, FileSpool Spool) Make(params Exception?[] steps)
    {
        var inner = new Scripted(steps);
        var spool = new FileSpool(Path.Combine(_dir, "s"), 10);
        return (new SpoolingTransport(inner, spool), inner, spool);
    }

    private static TransportException Down(string m = "down") => new(m);

    [Fact]
    public void Failure_spools_and_the_next_send_flushes_oldest_first()
    {
        var (t, inner, sp) = Make(Down(), Down());
        Assert.Equal(SendOutcome.Spooled, t.Send(Fx.Snap(1)));
        Assert.Equal(SendOutcome.Spooled, t.Send(Fx.Snap(2)));
        Assert.Equal(2, sp.Count);
        Assert.Equal(SendOutcome.Sent, t.Send(Fx.Snap(3)));
        Assert.Equal(new[] { "01", "02", "03" }, inner.Sent);
        Assert.Equal(0, sp.Count);
    }

    [Fact]
    public void Flush_stops_at_the_first_retryable_failure_and_keeps_order()
    {
        var (t, inner, sp) = Make(Down(), Down(), null, Down());
        t.Send(Fx.Snap(1)); t.Send(Fx.Snap(2));
        Assert.Equal(SendOutcome.Spooled, t.Send(Fx.Snap(3)));      // 01 성공, 02 실패 → 03 은 02 뒤에 보관
        Assert.Equal(new[] { "01" }, inner.Sent);
        Assert.Equal(new[] { "02", "03" }, sp.Oldest(10).Select(i => i.Snapshot.CollectedAt.Substring(17, 2)));
    }

    [Fact]
    public void Permanent_error_during_flush_is_dead_lettered_and_flush_continues()
    {
        var (t, inner, sp) = Make(Down(), Down(), new PermanentTransportException("422"));
        t.Send(Fx.Snap(1)); t.Send(Fx.Snap(2));
        Assert.Equal(SendOutcome.Sent, t.Send(Fx.Snap(3)));
        Assert.Equal(new[] { "02", "03" }, inner.Sent);
        Assert.Equal((0, 1), (sp.Count, sp.RejectedCount));
    }

    [Fact]
    public void Permanent_error_on_the_current_snapshot_is_raised_not_spooled()
    {
        var (t, _, sp) = Make(new PermanentTransportException("422"));
        Assert.Throws<PermanentTransportException>(() => t.Send(Fx.Snap(1)));
        Assert.Equal(0, sp.Count);
    }

    [Fact]
    public void Explicit_flush_reports_whether_the_spool_drained()
    {
        var (t, _, sp) = Make(Down(), Down("still down"));
        t.Send(Fx.Snap(1));
        Assert.False(t.Flush());
        Assert.Equal(1, sp.Count);
        Assert.True(t.Flush());
        Assert.Equal(0, sp.Count);
    }

    [Fact]
    public void Json_file_transport_writes_atomically()
    {
        var dir = Path.Combine(_dir, "out");
        var t = new JsonFileTransport(dir);
        Assert.Equal(SendOutcome.Sent, t.Send(Fx.Snap(1)));
        t.Send(Fx.Snap(2));
        var files = Directory.GetFiles(dir);
        Assert.Equal(2, files.Length);
        Assert.All(files, f => Assert.EndsWith(".json", f));                  // .tmp 잔여물 없음
        Assert.Equal("web01", JsonDocument.Parse(File.ReadAllText(files[0])).RootElement.GetProperty("hostname").GetString());
    }
}
