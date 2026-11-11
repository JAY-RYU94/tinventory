using System.Globalization;
using System.Text.Json;

namespace Swinventory.Agent;

public sealed class ConfigException(string message) : Exception(message);

/// <summary>에이전트 설정. 우선순위: 설정 파일(JSON) &lt; 환경변수(SWINV_*) &lt; CLI 옵션. 키 이름은 Python 에이전트와 같다.</summary>
public sealed class AgentConfig
{
    private static readonly string[] Keys =
    {
        "server_url", "token", "token_file", "ca_file", "client_cert", "client_key", "json_dir", "spool_path",
        "spool_max_items", "timeout", "allow_insecure_http",
    };

    public string? ServerUrl { get; private set; }
    public string? Token { get; private set; }
    public string? TokenFile { get; private set; }
    public string? CaFile { get; private set; }
    public string? ClientCert { get; private set; }
    public string? ClientKey { get; private set; }
    public string? JsonDir { get; private set; }
    public string SpoolPath { get; private set; } = "";
    public int SpoolMaxItems { get; private set; } = 200;
    public double Timeout { get; private set; } = 30;
    public bool AllowInsecureHttp { get; private set; }

    public static string DefaultSpoolPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "swinventory", "spool");

    public static AgentConfig Load(string? path, IReadOnlyDictionary<string, string> env, IReadOnlyDictionary<string, string?> overrides)
    {
        var values = new Dictionary<string, string?>();
        if (path is not null) ReadFile(path, values);
        foreach (var key in Keys)
            if (env.TryGetValue("SWINV_" + key.ToUpperInvariant(), out var e)) values[key] = e;
        foreach (var (k, v) in overrides)
            if (v is not null) values[k] = v;

        var cfg = new AgentConfig();
        string? Get(string k) => values.TryGetValue(k, out var v) && !string.IsNullOrEmpty(v) ? v : null;
        cfg.ServerUrl = Get("server_url");
        cfg.Token = Get("token");
        cfg.TokenFile = Get("token_file");
        cfg.CaFile = Get("ca_file");
        cfg.ClientCert = Get("client_cert");
        cfg.ClientKey = Get("client_key");
        cfg.JsonDir = Get("json_dir");
        cfg.SpoolPath = Get("spool_path") ?? DefaultSpoolPath();
        cfg.SpoolMaxItems = Get("spool_max_items") is { } n ? ParseNumber(n, "spool_max_items", int.Parse) : 200;
        cfg.Timeout = Get("timeout") is { } t ? ParseNumber(t, "timeout", s => double.Parse(s, CultureInfo.InvariantCulture)) : 30;
        cfg.AllowInsecureHttp = Get("allow_insecure_http") is { } b && b.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";
        if (cfg.TokenFile is not null && cfg.Token is null)
        {
            try { cfg.Token = File.ReadAllText(cfg.TokenFile).Trim().TrimStart('﻿').Trim(); }   // 메모장이 붙인 BOM·CRLF 를 제거한다
            catch (IOException ex) { throw new ConfigException($"token_file 을 읽지 못했다: {ex.GetType().Name}"); }
            catch (UnauthorizedAccessException) { throw new ConfigException("token_file 에 읽기 권한이 없다"); }
        }
        return cfg;
    }

    private static T ParseNumber<T>(string text, string key, Func<string, T> parse)
    {
        try { return parse(text); }
        catch (Exception ex) when (ex is FormatException or OverflowException) { throw new ConfigException($"{key} 는 숫자여야 한다"); }
    }

    private static void ReadFile(string path, Dictionary<string, string?> values)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new ConfigException("설정 파일의 최상위는 객체여야 한다");
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (!Keys.Contains(prop.Name)) throw new ConfigException($"알 수 없는 설정 키: {prop.Name}");
                values[prop.Name] = prop.Value.ValueKind switch
                {
                    JsonValueKind.String => prop.Value.GetString(),
                    JsonValueKind.Null => null,
                    _ => prop.Value.GetRawText(),   // 숫자·bool
                };
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            throw new ConfigException($"설정 파일을 읽지 못했다({path}): {ex.GetType().Name}");
        }
    }

    public void Validate(bool needServer)
    {
        if (needServer && ServerUrl is null) throw new ConfigException("server_url 이 필요하다");
        if (ServerUrl is null && JsonDir is null) throw new ConfigException("전송 목적지가 없다: server_url 또는 json_dir 를 설정한다");
        if (ServerUrl is null) return;
        if (!Uri.TryCreate(ServerUrl, UriKind.Absolute, out var uri)) throw new ConfigException("server_url 이 올바른 URL 이 아니다");
        if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && AllowInsecureHttp))
            throw new ConfigException("server_url 은 https 여야 한다(개발용은 allow_insecure_http)");
        if (string.IsNullOrEmpty(Token)) throw new ConfigException("token 또는 token_file 이 필요하다");
        if (SpoolMaxItems < 1) throw new ConfigException("spool_max_items 는 1 이상이어야 한다");
        if (Timeout <= 0) throw new ConfigException("timeout 은 0 보다 커야 한다");
    }
}
