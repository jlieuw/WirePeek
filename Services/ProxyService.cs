using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using MiniFiddler.Hubs;
using MiniFiddler.Models;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace MiniFiddler.Services;

public sealed class ProxyService : IHostedService, IDisposable
{
    private const int MaxCaptureBodyBytes = 2 * 1024 * 1024; // 2 MB cap per body

    private readonly SessionStore _store;
    private readonly ICaptureBroadcaster _broadcaster;
    private readonly ILogger<ProxyService> _logger;

    private readonly ProxyServer _proxy;
    private ExplicitProxyEndPoint? _endPoint;

    public int Port { get; } = 8888;
    public bool IsRunning { get; private set; }
    public bool SystemProxyEnabled { get; private set; }

    /// <summary>When false, captured requests are passed through but not recorded.</summary>
    public bool CaptureEnabled { get; set; } = true;

    /// <summary>Hosts to never record (e.g. the UI's own SignalR/API traffic).</summary>
    public HashSet<string> IgnoredHosts { get; } = new(StringComparer.OrdinalIgnoreCase);

    public ProxyService(SessionStore store, ICaptureBroadcaster broadcaster, ILogger<ProxyService> logger)
    {
        _store = store;
        _broadcaster = broadcaster;
        _logger = logger;
        _proxy = new ProxyServer();
    }

    // ---- Certificate helpers ----------------------------------------------
    public bool IsCertTrusted => _proxy.CertificateManager.IsRootCertificateUserTrusted();

    public byte[] ExportRootCertificate()
    {
        var cert = _proxy.CertificateManager.RootCertificate
                   ?? throw new InvalidOperationException("Root certificate not generated yet.");
        return cert.Export(X509ContentType.Cert);
    }

    public string RootCertificateName => _proxy.CertificateManager.RootCertificateName ?? "MiniFiddler Root";

    public void TrustCertificate() => _proxy.CertificateManager.TrustRootCertificate(machineTrusted: false);
    public void UntrustCertificate() => _proxy.CertificateManager.RemoveTrustedRootCertificate(machineTrusted: false);

    // ---- System proxy helpers ---------------------------------------------
    public void EnableSystemProxy()
    {
        if (_endPoint is null) return;
        _proxy.SetAsSystemProxy(_endPoint, ProxyProtocolType.AllHttp);
        SetLocalBypass();
        SystemProxyEnabled = true;
        _logger.LogInformation("System proxy enabled on 127.0.0.1:{Port} (loopback bypassed)", Port);
    }

    /// <summary>
    /// Ensure the machine's own loopback traffic (incl. this tool's web UI + SignalR
    /// socket) bypasses the proxy, so enabling capture never breaks the UI.
    /// </summary>
    private void SetLocalBypass()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: true);
            key?.SetValue("ProxyOverride", "localhost;127.0.0.1;<-loopback>", RegistryValueKind.String);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set loopback proxy bypass");
        }
    }

    private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
    private const int INTERNET_OPTION_REFRESH = 37;

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    public void DisableSystemProxy()
    {
        _proxy.DisableAllSystemProxies();
        SystemProxyEnabled = false;
        _logger.LogInformation("System proxy disabled");
    }

    // ---- Lifecycle ---------------------------------------------------------
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Store the CA private key in a per-user, ACL-restricted location with a
        // DPAPI-protected password instead of an unencrypted, world-readable pfx
        // in the working directory.
        var pfxPassword = CaKeyStore.EnsureSecureDirectoryAndPassword();
        _proxy.CertificateManager.PfxFilePath = CaKeyStore.PfxPath;
        _proxy.CertificateManager.PfxPassword = pfxPassword;

        _proxy.CertificateManager.RootCertificateName = "MiniFiddler Root CA";
        _proxy.CertificateManager.RootCertificateIssuerName = "MiniFiddler";
        _proxy.CertificateManager.EnsureRootCertificate();

        _endPoint = new ExplicitProxyEndPoint(IPAddress.Loopback, Port, decryptSsl: true);
        _proxy.AddEndPoint(_endPoint);

        _proxy.BeforeRequest += OnBeforeRequest;
        _proxy.BeforeResponse += OnBeforeResponse;
        _proxy.ServerCertificateValidationCallback += OnServerCertValidation;

        _proxy.Start(changeSystemProxySettings: false);
        IsRunning = true;
        _logger.LogInformation("MiniFiddler proxy listening on 127.0.0.1:{Port}", Port);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (SystemProxyEnabled) DisableSystemProxy();
            if (IsRunning)
            {
                _proxy.BeforeRequest -= OnBeforeRequest;
                _proxy.BeforeResponse -= OnBeforeResponse;
                _proxy.ServerCertificateValidationCallback -= OnServerCertValidation;
                _proxy.Stop();
                IsRunning = false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error stopping proxy");
        }
        return Task.CompletedTask;
    }

    private Task OnServerCertValidation(object sender, CertificateValidationEventArgs e)
    {
        // Validate upstream server certificates by default so the proxy->server leg
        // isn't silently MITM-able. Invalid certs cause that request to fail (safe default).
        e.IsValid = e.SslPolicyErrors == System.Net.Security.SslPolicyErrors.None;
        if (!e.IsValid)
            _logger.LogWarning("Rejected upstream certificate for {Host}: {Errors}",
                e.Session?.HttpClient?.Request?.RequestUri?.Host, e.SslPolicyErrors);
        return Task.CompletedTask;
    }

    // ---- Capture handlers --------------------------------------------------
    private async Task OnBeforeRequest(object sender, SessionEventArgs e)
    {
        if (!CaptureEnabled) return;

        var req = e.HttpClient.Request;
        var host = e.HttpClient.Request.RequestUri.Host;
        if (IgnoredHosts.Contains(host)) return;

        var session = new CapturedSession
        {
            StartedUtc = DateTime.UtcNow,
            Method = req.Method,
            Scheme = req.RequestUri.Scheme,
            Host = host,
            Url = req.Url,
            Path = req.RequestUri.PathAndQuery,
            RequestContentType = req.ContentType,
            RequestHeaders = req.Headers.Select(h => new HeaderItem { Name = h.Name, Value = h.Value }).ToList(),
            RequestBodySize = req.ContentLength
        };

        if (req.HasBody)
        {
            try
            {
                if (IsTextual(req.ContentType) && req.ContentLength is > 0 and <= MaxCaptureBodyBytes)
                    session.RequestBody = await e.GetRequestBodyAsString();
                else
                    session.RequestBodyIsBinary = true;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed reading request body for {Url}", req.Url);
                session.RequestBodyIsBinary = true;
            }
        }

        e.UserData = session;
        _store.Add(session);
        await _broadcaster.NewSessionAsync(SessionSummary.From(session));
    }

    private async Task OnBeforeResponse(object sender, SessionEventArgs e)
    {
        if (e.UserData is not CapturedSession session) return;

        var resp = e.HttpClient.Response;
        session.HasResponse = true;
        session.StatusCode = resp.StatusCode;
        session.StatusText = resp.StatusDescription;
        session.ResponseContentType = resp.ContentType;
        session.ResponseHeaders = resp.Headers.Select(h => new HeaderItem { Name = h.Name, Value = h.Value }).ToList();
        session.ResponseBodySize = resp.ContentLength;
        session.DurationMs = (DateTime.UtcNow - session.StartedUtc).TotalMilliseconds;

        if (resp.HasBody)
        {
            try
            {
                if (IsTextual(resp.ContentType))
                {
                    var body = await e.GetResponseBodyAsString();
                    if (body.Length <= MaxCaptureBodyBytes * 2)
                    {
                        session.ResponseBody = body;
                        session.ResponseBodySize = body.Length;
                    }
                    else
                    {
                        session.ResponseBodyIsBinary = true;
                    }
                }
                else
                {
                    session.ResponseBodyIsBinary = true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed reading response body for {Url}", session.Url);
                session.ResponseBodyIsBinary = true;
            }
        }

        await _broadcaster.UpdateSessionAsync(SessionSummary.From(session));
    }

    private static bool IsTextual(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return true; // assume text when unknown
        contentType = contentType.ToLowerInvariant();
        string[] textual =
        {
            "text/", "json", "xml", "javascript", "ecmascript", "html",
            "x-www-form-urlencoded", "graphql", "csv", "+json", "+xml", "svg"
        };
        return textual.Any(contentType.Contains);
    }

    public void Dispose() => _proxy.Dispose();
}
