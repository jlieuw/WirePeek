using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.FileProviders;
using WirePeek.Hubs;
using WirePeek.Services;

var (options, parseError) = CliOptions.Parse(args);
if (parseError is not null) return Fail(parseError);
if (options!.ShowHelp)
{
    Console.WriteLine(CliOptions.HelpText);
    return 0;
}
var (uiPort, proxyPort) = (options.UiPort, options.ProxyPort);

// Fail fast with a clear message instead of a mid-startup stack trace. (A race with
// another process grabbing the port after this check is possible but acceptable here.)
foreach (var (port, what, flag) in new[] { (uiPort, "web UI", "--ui-port"), (proxyPort, "capture proxy", "--proxy-port") })
{
    if (!IsPortFree(port))
        return Fail($"Port {port} (the {what} port) is already in use — is another WirePeek instance running? " +
                    $"Pick a different port with {flag} <port>.");
}

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls($"http://127.0.0.1:{uiPort}");

// Keep C# PascalCase property names in JSON so the front-end (which reads
// s.Method, s.Host, etc.) and SignalR payloads stay consistent.
builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(o =>
    o.SerializerOptions.PropertyNamingPolicy = null);

builder.Services.AddSignalR()
    .AddJsonProtocol(o => o.PayloadSerializerOptions.PropertyNamingPolicy = null);
builder.Services.AddSingleton<SessionStore>(_ => new SessionStore(capacity: 5000));
builder.Services.AddSingleton<ICaptureBroadcaster, CaptureBroadcaster>();
builder.Services.AddSingleton(new ProxyOptions(proxyPort));
builder.Services.AddSingleton<ProxyService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ProxyService>());

var app = builder.Build();

// --- Loopback hardening -------------------------------------------------------
// The API/Hub are unauthenticated and bound to loopback. Guard against malicious
// web pages reaching them via DNS-rebinding (Host header) or cross-site requests
// (Origin header). Native local processes are out of scope (inherent to loopback).
var allowedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    $"127.0.0.1:{uiPort}", $"localhost:{uiPort}"
};
var allowedOrigins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    $"http://127.0.0.1:{uiPort}", $"http://localhost:{uiPort}"
};
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path;
    if (path.StartsWithSegments("/api") || path.StartsWithSegments("/hub"))
    {
        if (!allowedHosts.Contains(ctx.Request.Host.Value ?? ""))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsync("Forbidden: unexpected Host header.");
            return;
        }

        var m = ctx.Request.Method;
        if (HttpMethods.IsPost(m) || HttpMethods.IsPut(m) || HttpMethods.IsDelete(m) || HttpMethods.IsPatch(m))
        {
            var origin = ctx.Request.Headers.Origin.ToString();
            if (!string.IsNullOrEmpty(origin) && !allowedOrigins.Contains(origin))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsync("Forbidden: cross-origin request rejected.");
                return;
            }
        }
    }
    await next();
});

// The UI is embedded in the assembly so the app works when installed as a dotnet
// tool (where there is no wwwroot on disk next to the working directory). During
// development, serve from the physical wwwroot so edits show up without a rebuild.
var devWwwroot = Path.Combine(app.Environment.ContentRootPath, "wwwroot");
IFileProvider uiFiles = app.Environment.IsDevelopment() && Directory.Exists(devWwwroot)
    ? new PhysicalFileProvider(devWwwroot)
    : new ManifestEmbeddedFileProvider(typeof(Program).Assembly, "wwwroot");
app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = uiFiles });
app.UseStaticFiles(new StaticFileOptions { FileProvider = uiFiles });

var proxy = app.Services.GetRequiredService<ProxyService>();
// Don't record the UI's own traffic if it ever routes through the proxy.
proxy.IgnoredHosts.Add("localhost");
proxy.IgnoredHosts.Add("127.0.0.1");

app.MapHub<CaptureHub>("/hub");

app.MapGet("/api/status", (ProxyService p, SessionStore store) => Results.Ok(new
{
    running = p.IsRunning,
    port = p.Port,
    certTrusted = p.IsCertTrusted,
    certName = p.RootCertificateName,
    systemProxyEnabled = p.SystemProxyEnabled,
    captureEnabled = p.CaptureEnabled,
    capacity = store.Capacity,
    count = store.ListSummaries().Count
}));

app.MapGet("/api/sessions", (SessionStore store) => Results.Ok(store.ListSummaries()));

app.MapGet("/api/sessions/{id}", (string id, SessionStore store) =>
{
    var s = store.Get(id);
    return s is null ? Results.NotFound() : Results.Ok(s);
});

app.MapPost("/api/clear", async (SessionStore store, ICaptureBroadcaster b) =>
{
    store.Clear();
    await b.ClearedAsync();
    return Results.NoContent();
});

app.MapPost("/api/capture", (CaptureToggle body, ProxyService p) =>
{
    p.CaptureEnabled = body.Enabled;
    return Results.Ok(new { captureEnabled = p.CaptureEnabled });
});

app.MapGet("/api/cert", (ProxyService p) =>
{
    try
    {
        var bytes = p.ExportRootCertificate();
        return Results.File(bytes, "application/x-x509-ca-cert", "WirePeekRoot.cer");
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
});

app.MapPost("/api/cert/install", (ProxyService p) =>
{
    try { p.TrustCertificate(); return Results.Ok(new { certTrusted = p.IsCertTrusted }); }
    catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapPost("/api/cert/uninstall", (ProxyService p) =>
{
    try { p.UntrustCertificate(); return Results.Ok(new { certTrusted = p.IsCertTrusted }); }
    catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.MapPost("/api/system-proxy", (SystemProxyToggle body, ProxyService p) =>
{
    try
    {
        if (body.Enabled) p.EnableSystemProxy();
        else p.DisableSystemProxy();
        return Results.Ok(new { systemProxyEnabled = p.SystemProxyEnabled });
    }
    catch (Exception ex) { return Results.Problem(ex.Message); }
});

app.Run();
return 0;

static int Fail(string message)
{
    Console.Error.WriteLine($"wirepeek: {message}");
    return 1;
}

static bool IsPortFree(int port)
{
    try
    {
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();
        listener.Stop();
        return true;
    }
    catch (SocketException)
    {
        return false;
    }
}

internal record CaptureToggle(bool Enabled);
internal record SystemProxyToggle(bool Enabled);

/// <summary>
/// WirePeek's own command-line options. Parsing is pure (no Console/Environment.Exit)
/// so it stays unit-testable; unrecognized -- options are left for the ASP.NET Core host.
/// </summary>
internal sealed record CliOptions(int UiPort, int ProxyPort, bool ShowHelp)
{
    public const int DefaultUiPort = 5266;
    public const int DefaultProxyPort = 8888;

    public static readonly string HelpText = $"""
        WirePeek — local HTTP(S) capture proxy

        Usage: wirepeek [options]

        Options:
          --ui-port <port>     Port for the web UI (default {DefaultUiPort})
          --proxy-port <port>  Port the capture proxy listens on (default {DefaultProxyPort})
          -h, --help           Show this help

        Unrecognized --options are passed through to the ASP.NET Core host
        (e.g. --environment Development).
        """;

    /// <summary>Returns the parsed options or an error message, never both.</summary>
    public static (CliOptions? Options, string? Error) Parse(string[] args)
    {
        var uiPort = DefaultUiPort;
        var proxyPort = DefaultProxyPort;

        for (var i = 0; i < args.Length; i++)
        {
            string? error = null;
            switch (args[i])
            {
                case "--help" or "-h" or "-?":
                    return (new CliOptions(uiPort, proxyPort, ShowHelp: true), null);
                case "--ui-port":
                    error = TakePortValue("--ui-port", args, ref i, out uiPort);
                    break;
                case "--proxy-port":
                    error = TakePortValue("--proxy-port", args, ref i, out proxyPort);
                    break;
                case var opt when opt.StartsWith("--ui-port=", StringComparison.Ordinal):
                    error = ParsePort("--ui-port", opt["--ui-port=".Length..], out uiPort);
                    break;
                case var opt when opt.StartsWith("--proxy-port=", StringComparison.Ordinal):
                    error = ParsePort("--proxy-port", opt["--proxy-port=".Length..], out proxyPort);
                    break;
                case var opt when opt.StartsWith('-'):
                    // Not one of ours — pass through to the ASP.NET Core host untouched
                    // (--environment, --contentRoot, --Logging:*, etc.). Skip its value
                    // token too so we don't misparse "--environment Development".
                    if (i + 1 < args.Length && !args[i + 1].StartsWith('-')) i++;
                    break;
                default:
                    error = $"Unexpected argument '{args[i]}'. Run 'wirepeek --help' for usage.";
                    break;
            }
            if (error is not null) return (null, error);
        }

        if (uiPort == proxyPort)
            return (null, $"--ui-port and --proxy-port must differ (both are {uiPort}).");

        return (new CliOptions(uiPort, proxyPort, ShowHelp: false), null);
    }

    private static string? TakePortValue(string name, string[] args, ref int i, out int port)
    {
        port = 0;
        if (i + 1 >= args.Length) return $"Missing value for {name}.";
        return ParsePort(name, args[++i], out port);
    }

    private static string? ParsePort(string name, string value, out int port)
    {
        if (int.TryParse(value, out port) && port is >= 1 and <= 65535) return null;
        return $"Invalid value '{value}' for {name} — expected a port number between 1 and 65535.";
    }
}
