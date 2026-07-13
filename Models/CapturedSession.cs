namespace WirePeek.Models;

public sealed class HeaderItem
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
}

public sealed class CapturedSession
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public int Index { get; set; }

    // Request
    public DateTime StartedUtc { get; set; } = DateTime.UtcNow;
    public string Method { get; set; } = "";
    public string Scheme { get; set; } = "";
    public string Host { get; set; } = "";
    public string Url { get; set; } = "";
    public string Path { get; set; } = "";
    public List<HeaderItem> RequestHeaders { get; set; } = new();
    public string? RequestContentType { get; set; }
    public string? RequestBody { get; set; }
    public bool RequestBodyIsBinary { get; set; }
    public long RequestBodySize { get; set; }

    // Response
    public bool HasResponse { get; set; }
    public int StatusCode { get; set; }
    public string StatusText { get; set; } = "";
    public List<HeaderItem> ResponseHeaders { get; set; } = new();
    public string? ResponseContentType { get; set; }
    public string? ResponseBody { get; set; }
    public bool ResponseBodyIsBinary { get; set; }
    public long ResponseBodySize { get; set; }
    public double DurationMs { get; set; }

    // Error (e.g. connection failure)
    public string? Error { get; set; }
}

/// <summary>Lightweight row used for the live list to keep payloads small.</summary>
public sealed class SessionSummary
{
    public string Id { get; set; } = "";
    public int Index { get; set; }
    public DateTime StartedUtc { get; set; }
    public string Method { get; set; } = "";
    public string Host { get; set; } = "";
    public string Path { get; set; } = "";
    public string Url { get; set; } = "";
    public string Scheme { get; set; } = "";
    public bool HasResponse { get; set; }
    public int StatusCode { get; set; }
    public string? ResponseContentType { get; set; }
    public long ResponseBodySize { get; set; }
    public double DurationMs { get; set; }
    public string? Error { get; set; }

    public static SessionSummary From(CapturedSession s) => new()
    {
        Id = s.Id,
        Index = s.Index,
        StartedUtc = s.StartedUtc,
        Method = s.Method,
        Host = s.Host,
        Path = s.Path,
        Url = s.Url,
        Scheme = s.Scheme,
        HasResponse = s.HasResponse,
        StatusCode = s.StatusCode,
        ResponseContentType = s.ResponseContentType,
        ResponseBodySize = s.ResponseBodySize,
        DurationMs = s.DurationMs,
        Error = s.Error
    };
}
