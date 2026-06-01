using MiniFiddler.Hubs;
using MiniFiddler.Services;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://127.0.0.1:5266");

// Keep C# PascalCase property names in JSON so the front-end (which reads
// s.Method, s.Host, etc.) and SignalR payloads stay consistent.
builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(o =>
    o.SerializerOptions.PropertyNamingPolicy = null);

builder.Services.AddSignalR()
    .AddJsonProtocol(o => o.PayloadSerializerOptions.PropertyNamingPolicy = null);
builder.Services.AddSingleton<SessionStore>(_ => new SessionStore(capacity: 5000));
builder.Services.AddSingleton<ICaptureBroadcaster, CaptureBroadcaster>();
builder.Services.AddSingleton<ProxyService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ProxyService>());

var app = builder.Build();

// --- Loopback hardening -------------------------------------------------------
// The API/Hub are unauthenticated and bound to loopback. Guard against malicious
// web pages reaching them via DNS-rebinding (Host header) or cross-site requests
// (Origin header). Native local processes are out of scope (inherent to loopback).
var allowedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "127.0.0.1:5266", "localhost:5266"
};
var allowedOrigins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "http://127.0.0.1:5266", "http://localhost:5266"
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

app.UseDefaultFiles();
app.UseStaticFiles();

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
        return Results.File(bytes, "application/x-x509-ca-cert", "MiniFiddlerRoot.cer");
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

internal record CaptureToggle(bool Enabled);
internal record SystemProxyToggle(bool Enabled);
