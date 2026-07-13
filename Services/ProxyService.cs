using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using WirePeek.Hubs;
using WirePeek.Models;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace WirePeek.Services;

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

    public string RootCertificateName => _proxy.CertificateManager.RootCertificateName ?? "WirePeek Root";

    public void TrustCertificate() => _proxy.CertificateManager.TrustRootCertificate(machineTrusted: false);
    public void UntrustCertificate() => _proxy.CertificateManager.RemoveTrustedRootCertificate(machineTrusted: false);

    private void ExportCaPem()
    {
        try
        {
            var cert = _proxy.CertificateManager.RootCertificate;
            if (cert is null) return;
            File.WriteAllText(CaKeyStore.CaPemPath, cert.ExportCertificatePem());
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not export CA certificate as PEM for NODE_EXTRA_CA_CERTS");
        }
    }

    // ---- System proxy helpers ---------------------------------------------

    // Registry key where we back up the user's original env var values before overwriting them.
    // Presence of this key acts as a sentinel that WirePeek owns the current values.
    private const string EnvBackupRegKey = @"Software\WirePeek\EnvBackup";
    private const string HkcuEnvironmentKey = @"Environment";
    private static readonly string[] ManagedEnvVars = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS"];

    public void EnableSystemProxy()
    {
        if (_endPoint is null) return;
        _proxy.SetAsSystemProxy(_endPoint, ProxyProtocolType.AllHttp);
        SetLocalBypass();
        SetProxyEnvVars();
        SystemProxyEnabled = true;
        _logger.LogInformation("System proxy enabled on 127.0.0.1:{Port} (loopback bypassed)", Port);
    }

    /// <summary>
    /// Sets HTTP_PROXY, HTTPS_PROXY, NO_PROXY, and NODE_EXTRA_CA_CERTS in HKCU\Environment so
    /// non-WinInet clients (Node.js / VS Code extensions, curl, Python, etc.) also route through
    /// the proxy. The original values are backed up to a WirePeek-owned registry key so they
    /// can be restored on disable — including after a crash, via ReconcileEnvVarState.
    /// </summary>
    private void SetProxyEnvVars()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var proxyUrl = $"http://127.0.0.1:{Port}";

            // Save originals only on the first call; skip if the backup key already exists,
            // meaning we still hold the real originals from a previous enable.
            using (var existingBackup = Registry.CurrentUser.OpenSubKey(EnvBackupRegKey, writable: false))
            {
                if (existingBackup is null)
                {
                    using var envKey = Registry.CurrentUser.OpenSubKey(HkcuEnvironmentKey, writable: false);
                    using var backup = Registry.CurrentUser.CreateSubKey(EnvBackupRegKey, writable: true);
                    foreach (var name in ManagedEnvVars)
                    {
                        var existing = envKey?.GetValue(name) as string;
                        if (existing is not null)
                            backup.SetValue(name, existing, RegistryValueKind.String);
                    }
                    // Written last: ClearProxyEnvVars uses this to detect a partial write after crash.
                    backup.SetValue("_written", "1", RegistryValueKind.String);
                }
            }

            var pemSet = File.Exists(CaKeyStore.CaPemPath);
            using (var envKey = Registry.CurrentUser.CreateSubKey(HkcuEnvironmentKey, writable: true))
            {
                envKey.SetValue("HTTP_PROXY", proxyUrl, RegistryValueKind.String);
                envKey.SetValue("HTTPS_PROXY", proxyUrl, RegistryValueKind.String);
                envKey.SetValue("NO_PROXY", "localhost,127.0.0.1,::1", RegistryValueKind.String);
                if (pemSet)
                    envKey.SetValue("NODE_EXTRA_CA_CERTS", CaKeyStore.CaPemPath, RegistryValueKind.String);
            }

            BroadcastEnvironmentChange();
            _logger.LogInformation("Set proxy environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY{NodeCa})",
                pemSet ? ", NODE_EXTRA_CA_CERTS" : "");
            if (!pemSet)
                _logger.LogWarning("CA PEM not found at {Path}; NODE_EXTRA_CA_CERTS was not set — Node.js HTTPS interception will not work",
                    CaKeyStore.CaPemPath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set proxy environment variables");
        }
    }

    /// <summary>
    /// Restores the user's original env var values (or removes them if they were absent before)
    /// and deletes the WirePeek backup key.
    /// </summary>
    private void ClearProxyEnvVars()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            bool restored;
            using (var backup = Registry.CurrentUser.OpenSubKey(EnvBackupRegKey, writable: false))
            {
                if (backup is null) return; // We never set these env vars; nothing to restore.

                // Partial-write guard: if the completion marker is missing, a crash occurred between
                // CreateSubKey and the first SetValue. The env vars were never changed — don't delete
                // anything; just clean up the orphaned backup key below.
                if (backup.GetValue("_written") is null)
                {
                    restored = false;
                }
                else
                {
                    using var envKey = Registry.CurrentUser.CreateSubKey(HkcuEnvironmentKey, writable: true);
                    foreach (var name in ManagedEnvVars)
                    {
                        var saved = backup.GetValue(name) as string;
                        if (saved is not null)
                            envKey.SetValue(name, saved, RegistryValueKind.String);
                        else
                            envKey.DeleteValue(name, throwOnMissingValue: false);
                    }
                    restored = true;
                }
            } // backup handle must be closed before DeleteSubKey

            Registry.CurrentUser.DeleteSubKey(EnvBackupRegKey, throwOnMissingSubKey: false);

            if (restored)
            {
                BroadcastEnvironmentChange();
                _logger.LogInformation("Restored proxy environment variables");
            }
            else
            {
                _logger.LogWarning("Discarded incomplete proxy env var backup (partial write before crash); env vars were not changed");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not restore proxy environment variables");
        }
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = false)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, IntPtr wParam, string lParam,
        uint fuFlags, uint uTimeout, out IntPtr lpdwResult);

    private const int HWND_BROADCAST = 0xffff;
    private const uint WM_SETTINGCHANGE = 0x001A;
    private const uint SMTO_ABORTIFHUNG = 0x0002;

    private static void BroadcastEnvironmentChange()
    {
        SendMessageTimeout(new IntPtr(HWND_BROADCAST), WM_SETTINGCHANGE,
            IntPtr.Zero, "Environment", SMTO_ABORTIFHUNG, 1000, out _);
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
        ClearProxyEnvVars();
        SystemProxyEnabled = false;
        _logger.LogInformation("System proxy disabled");
    }

    /// <summary>
    /// Reconciles in-memory state with the actual Windows proxy registry at startup.
    /// If a previous session exited abnormally (crash/hard-kill) it may have left the
    /// system proxy pointing at us; reflect that so the UI shows the true state and the
    /// user can turn it off. Only claims the proxy if it points at our own endpoint.
    /// </summary>
    public bool ReconcileSystemProxyState()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: false);
            var enabled = (key?.GetValue("ProxyEnable") as int?) == 1;
            var server = key?.GetValue("ProxyServer") as string ?? "";

            // Only treat it as "ours" if the system proxy points at our loopback port.
            var pointsAtUs = server.Contains($":{Port}", StringComparison.Ordinal)
                             && (server.Contains("127.0.0.1", StringComparison.OrdinalIgnoreCase)
                                 || server.Contains("localhost", StringComparison.OrdinalIgnoreCase));

            SystemProxyEnabled = enabled && pointsAtUs;
            if (SystemProxyEnabled)
                _logger.LogWarning(
                    "Detected a leftover system proxy from a previous session (ProxyServer={Server}). " +
                    "Reflecting it as enabled; it will be disabled on clean shutdown or via the UI.", server);

            ReconcileEnvVarState();
            return SystemProxyEnabled;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not read system proxy state");
            return false;
        }
    }

    /// <summary>
    /// Checks whether our env var backup key is present (i.e. WirePeek owns the current env
    /// vars) and reconciles that with the proxy-enabled state. If the proxy is off but env vars
    /// were left behind by a crash, they are cleaned up now.
    /// </summary>
    private void ReconcileEnvVarState()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            using var backup = Registry.CurrentUser.OpenSubKey(EnvBackupRegKey, writable: false);
            if (backup is null) return; // No backup key — we don't own the env vars.

            if (SystemProxyEnabled)
            {
                // Proxy is still active; re-apply env vars in case they were manually removed between sessions.
                _logger.LogWarning(
                    "Leftover proxy environment variables detected from previous session — re-applying (proxy is still active).");
                SetProxyEnvVars();
            }
            else
            {
                // Proxy was turned off or belongs to another app; env vars are stale — clean up.
                _logger.LogWarning(
                    "Leftover proxy environment variables detected from previous session — clearing them.");
                ClearProxyEnvVars();
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not reconcile proxy environment variable state");
        }
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

        _proxy.CertificateManager.RootCertificateName = "WirePeek Root CA";
        _proxy.CertificateManager.RootCertificateIssuerName = "WirePeek";
        _proxy.CertificateManager.EnsureRootCertificate();
        ExportCaPem(); // Write PEM so NODE_EXTRA_CA_CERTS can point at it

        _endPoint = new ExplicitProxyEndPoint(IPAddress.Loopback, Port, decryptSsl: true);
        _proxy.AddEndPoint(_endPoint);

        _proxy.BeforeRequest += OnBeforeRequest;
        _proxy.BeforeResponse += OnBeforeResponse;
        _proxy.ServerCertificateValidationCallback += OnServerCertValidation;

        _proxy.Start(changeSystemProxySettings: false);
        IsRunning = true;
        _logger.LogInformation("WirePeek proxy listening on 127.0.0.1:{Port}", Port);

        // If a previous run left the system proxy enabled (e.g. abnormal exit), reflect
        // that in our state so the UI is accurate and the user can disable it.
        ReconcileSystemProxyState();

        // Backstop: ensure the system proxy is restored if the process exits via a path
        // the host's StopAsync doesn't cover (best-effort; a hard kill can't be caught).
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
        return Task.CompletedTask;
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        try { if (SystemProxyEnabled) _proxy.DisableAllSystemProxies(); }
        catch { /* best-effort cleanup */ }
        try { ClearProxyEnvVars(); }
        catch { /* best-effort cleanup */ }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
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
