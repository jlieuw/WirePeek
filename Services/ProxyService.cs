using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using WirePeek.Hubs;
using WirePeek.Models;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Exceptions;
using Titanium.Web.Proxy.Models;

namespace WirePeek.Services;

/// <summary>Startup configuration for <see cref="ProxyService"/>.</summary>
public sealed record ProxyOptions(int Port, int UiPort);

public sealed class ProxyService : IHostedService, IDisposable
{
    private const int MaxCaptureBodyBytes = 2 * 1024 * 1024; // 2 MB cap per body

    private readonly SessionStore _store;
    private readonly ICaptureBroadcaster _broadcaster;
    private readonly ILogger<ProxyService> _logger;

    private readonly ProxyServer _proxy;
    private readonly int _uiPort;

    // Titanium clears SessionEventArgs.UserData before reporting a failure to ExceptionFunc, so
    // keep our own (weak) link from the event args to the row they produced.
    private readonly ConditionalWeakTable<SessionEventArgsBase, CapturedSession> _rows = new();
    private readonly ConcurrentDictionary<string, SslPolicyErrors> _rejectedCerts = new(StringComparer.OrdinalIgnoreCase);
    private ExplicitProxyEndPoint? _endPoint;

    public int Port { get; }
    public bool IsRunning { get; private set; }
    public bool SystemProxyEnabled { get; private set; }

    /// <summary>
    /// When true, the system proxy settings (and NO_PROXY on Windows) stop bypassing loopback, so
    /// calls to local APIs (localhost, 127.0.0.1) are routed through and captured as well.
    /// </summary>
    public bool CaptureLocalhost { get; private set; }

    /// <summary>When false, captured requests are passed through but not recorded.</summary>
    public bool CaptureEnabled { get; set; } = true;

    public ProxyService(SessionStore store, ICaptureBroadcaster broadcaster, ILogger<ProxyService> logger, ProxyOptions options)
    {
        _store = store;
        _broadcaster = broadcaster;
        _logger = logger;
        Port = options.Port;
        _uiPort = options.UiPort;
        _proxy = new ProxyServer();
    }

    // ---- Certificate helpers ----------------------------------------------
    public bool IsCertTrusted => OperatingSystem.IsMacOS()
        ? _proxy.CertificateManager.RootCertificate is { } root && MacSystemIntegration.IsRootTrusted(root)
        : _proxy.CertificateManager.IsRootCertificateUserTrusted();

    public byte[] ExportRootCertificate()
    {
        var cert = _proxy.CertificateManager.RootCertificate
                   ?? throw new InvalidOperationException("Root certificate not generated yet.");
        return cert.Export(X509ContentType.Cert);
    }

    public string RootCertificateName => _proxy.CertificateManager.RootCertificateName ?? "WirePeek Root";

    public void TrustCertificate()
    {
        if (OperatingSystem.IsMacOS()) MacSystemIntegration.TrustRoot(CaKeyStore.CaPemPath);
        else _proxy.CertificateManager.TrustRootCertificate(machineTrusted: false);
    }

    public void UntrustCertificate()
    {
        if (OperatingSystem.IsMacOS()) MacSystemIntegration.UntrustRoot(CaKeyStore.CaPemPath);
        else _proxy.CertificateManager.RemoveTrustedRootCertificate(machineTrusted: false);
    }

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

    // Records which WirePeek process currently owns the system proxy (port + pid). Lets a
    // later startup distinguish "leftover from a crashed session" from "another live WirePeek
    // instance owns it" — the current port alone can't, now that ports are configurable.
    private const string OwnerRegKey = @"Software\WirePeek\SystemProxy";

    private void WriteOwnerRecord()
    {
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                MacSystemIntegration.WriteOwner(new(Port, Environment.ProcessId, Process.GetCurrentProcess().ProcessName));
                return;
            }
            if (!OperatingSystem.IsWindows()) return;
            using var key = Registry.CurrentUser.CreateSubKey(OwnerRegKey, writable: true);
            key.SetValue("Port", Port, RegistryValueKind.DWord);
            key.SetValue("Pid", Environment.ProcessId, RegistryValueKind.DWord);
            key.SetValue("ProcessName", Process.GetCurrentProcess().ProcessName, RegistryValueKind.String);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not record system proxy ownership");
        }
    }

    private void DeleteOwnerRecord()
    {
        try
        {
            if (OperatingSystem.IsMacOS()) MacSystemIntegration.DeleteOwner();
            else if (OperatingSystem.IsWindows()) Registry.CurrentUser.DeleteSubKey(OwnerRegKey, throwOnMissingSubKey: false);
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Could not clear system proxy ownership record"); }
    }

    private (int Port, int Pid, string Name)? ReadOwnerRecord()
    {
        if (OperatingSystem.IsMacOS())
            return MacSystemIntegration.ReadOwner() is { } o ? (o.Port, o.Pid, o.ProcessName) : null;
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(OwnerRegKey, writable: false);
            if (key?.GetValue("Port") is not int port || key.GetValue("Pid") is not int pid) return null;
            return (port, pid, key.GetValue("ProcessName") as string ?? "");
        }
        catch
        {
            return null;
        }
    }

    private static bool IsProcessAlive(int pid, string name)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited && p.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false; // no such process (or access denied — treat as not ours)
        }
    }

    /// <summary>The owner record of another, still-running WirePeek instance, if one holds the system proxy.</summary>
    private (int Port, int Pid, string Name)? LiveForeignOwner() =>
        ReadOwnerRecord() is { } o && o.Pid != Environment.ProcessId && IsProcessAlive(o.Pid, o.Name) ? o : null;

    private const string HkcuEnvironmentKey = @"Environment";
    private static readonly string[] ManagedEnvVars = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS"];

    public void EnableSystemProxy()
    {
        if (_endPoint is null) return;
        // Taking over would leave both instances believing they own the proxy, and whichever
        // shuts down first would restore the settings out from under the other.
        if (LiveForeignOwner() is { } other)
            throw new InvalidOperationException(
                $"The system proxy is in use by another WirePeek instance (pid {other.Pid}, port {other.Port}). Turn it off there first.");
        if (OperatingSystem.IsMacOS())
        {
            MacSystemIntegration.EnableSystemProxy(Port, CaptureLocalhost);
        }
        else
        {
            _proxy.SetAsSystemProxy(_endPoint, ProxyProtocolType.AllHttp);
            SetLocalBypass();
            SetProxyEnvVars();
        }
        WriteOwnerRecord();
        SystemProxyEnabled = true;
        _logger.LogInformation("System proxy enabled on 127.0.0.1:{Port} (loopback {Loopback})", Port,
            CaptureLocalhost ? "captured" : "bypassed");
    }

    /// <summary>Switches <see cref="CaptureLocalhost"/>, re-applying the bypass settings if the system proxy is ours.</summary>
    public void SetCaptureLocalhost(bool enabled)
    {
        var previous = CaptureLocalhost;
        CaptureLocalhost = enabled;
        if (!SystemProxyEnabled || LiveForeignOwner() is not null) return;
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                MacSystemIntegration.EnableSystemProxy(Port, CaptureLocalhost);
            }
            else
            {
                SetLocalBypass();
                SetProxyEnvVars();
            }
        }
        catch
        {
            CaptureLocalhost = previous;
            throw;
        }
        _logger.LogInformation("Localhost capture {State}", enabled ? "enabled" : "disabled");
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
                if (CaptureLocalhost)
                    envKey.DeleteValue("NO_PROXY", throwOnMissingValue: false);
                else
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
    /// Keeps loopback traffic off the proxy unless <see cref="CaptureLocalhost"/> is on. "&lt;-loopback&gt;"
    /// removes WinINet's implicit loopback bypass, so with capture on, local calls (including this UI,
    /// which the proxy forwards but doesn't record) are routed through the proxy.
    /// </summary>
    private void SetLocalBypass()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: true);
            key?.SetValue("ProxyOverride", CaptureLocalhost ? "<-loopback>" : "localhost;127.0.0.1;<-loopback>", RegistryValueKind.String);
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
        if (LiveForeignOwner() is { } other)
        {
            // Not ours (anymore): another live instance holds it, so leave its settings alone.
            _logger.LogWarning("System proxy is owned by another WirePeek instance (pid {Pid}); not touching it.", other.Pid);
            SystemProxyEnabled = false;
            return;
        }
        TurnOffSystemProxy();
        ClearProxyEnvVars();
        DeleteOwnerRecord();
        SystemProxyEnabled = false;
        _logger.LogInformation("System proxy disabled");
    }

    /// <summary>Points the OS proxy setting away from us: restores the originals on macOS, clears it on Windows.</summary>
    private void TurnOffSystemProxy()
    {
        if (OperatingSystem.IsMacOS()) MacSystemIntegration.RestoreSystemProxy();
        else _proxy.DisableAllSystemProxies();
    }

    /// <summary>The OS proxy setting as (enabled, "host:port"-ish server string).</summary>
    private static (bool Enabled, string Server) ReadSystemProxySetting()
    {
        if (OperatingSystem.IsMacOS()) return MacSystemIntegration.ReadSystemProxy();
        if (!OperatingSystem.IsWindows()) return (false, "");

        using var key = Registry.CurrentUser.OpenSubKey(
            @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: false);
        return ((key?.GetValue("ProxyEnable") as int?) == 1, key?.GetValue("ProxyServer") as string ?? "");
    }

    /// <summary>
    /// Reconciles in-memory state with the actual OS proxy setting at startup.
    /// If a previous session exited abnormally (crash/hard-kill) it may have left the
    /// system proxy pointing at us; reflect that so the UI shows the true state and the
    /// user can turn it off. Only claims the proxy if it points at our own endpoint.
    /// </summary>
    public bool ReconcileSystemProxyState()
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS()) return false;
        try
        {
            var (enabled, server) = ReadSystemProxySetting();

            static bool PointsAtLoopbackPort(string server, int port) =>
                server.Contains($":{port}", StringComparison.Ordinal)
                && (server.Contains("127.0.0.1", StringComparison.OrdinalIgnoreCase)
                    || server.Contains("localhost", StringComparison.OrdinalIgnoreCase));

            // Another live WirePeek instance owns the system proxy and env vars —
            // leave everything alone or we'd clobber its state.
            if (LiveForeignOwner() is { } live)
            {
                _logger.LogInformation(
                    "System proxy is owned by another running WirePeek instance (pid {Pid}, port {OwnerPort}); leaving it untouched.",
                    live.Pid, live.Port);
                SystemProxyEnabled = false;
                return false;
            }

            if (ReadOwnerRecord() is { } dead)
            {
                // Owner crashed. If the proxy still points at its (different) port, nobody
                // serves that endpoint anymore — machine-wide routing is broken. Adopting
                // wouldn't help (we listen elsewhere), so clean it up now.
                if (enabled && PointsAtLoopbackPort(server, dead.Port) && dead.Port != Port)
                {
                    _logger.LogWarning(
                        "Cleaning up system proxy left on port {OldPort} by a crashed session (this instance listens on {Port}).",
                        dead.Port, Port);
                    TurnOffSystemProxy();
                    ClearProxyEnvVars();
                    DeleteOwnerRecord();
                    SystemProxyEnabled = false;
                    return false;
                }
                // Proxy no longer points at the dead owner's port (user or another app
                // changed it): the OS setting isn't ours to touch, but our env-var
                // leftovers, saved originals and stale ownership record are — drop them.
                if (!(enabled && PointsAtLoopbackPort(server, Port)))
                {
                    ClearProxyEnvVars();
                    if (OperatingSystem.IsMacOS()) MacSystemIntegration.ForgetSystemProxyBackup();
                    DeleteOwnerRecord();
                    SystemProxyEnabled = false;
                    return false;
                }
                // Same port as ours: fall through and adopt it — we serve that endpoint again.
            }

            SystemProxyEnabled = enabled && PointsAtLoopbackPort(server, Port);
            if (SystemProxyEnabled)
            {
                _logger.LogWarning(
                    "Detected a leftover system proxy from a previous session (ProxyServer={Server}). " +
                    "Reflecting it as enabled; it will be disabled on clean shutdown or via the UI.", server);
                WriteOwnerRecord(); // we own it from here on
            }

            ReconcileEnvVarState();
            // Saved originals with no proxy pointing at us are stale (the user changed the setting).
            if (OperatingSystem.IsMacOS() && !SystemProxyEnabled) MacSystemIntegration.ForgetSystemProxyBackup();
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
        // Only create/load the CA here. The parameterless overload also trusts it (ProxyServer
        // defaults to user trust), which on Windows pops a certificate-install dialog at startup
        // and blocks until answered; trusting is the user's explicit Trust Cert action.
        _proxy.CertificateManager.EnsureRootCertificate(
            userTrustRootCertificate: false, machineTrustRootCertificate: false);
        CaKeyStore.RestrictFileToCurrentUser(CaKeyStore.PfxPath);
        ExportCaPem(); // Write PEM so NODE_EXTRA_CA_CERTS (Windows) / `security` (macOS) can use it

        _endPoint = new ExplicitProxyEndPoint(IPAddress.Loopback, Port, decryptSsl: true);
        _proxy.AddEndPoint(_endPoint);

        _proxy.BeforeRequest += OnBeforeRequest;
        _proxy.BeforeResponse += OnBeforeResponse;
        _proxy.ServerCertificateValidationCallback += OnServerCertValidation;
        _proxy.ExceptionFunc = OnProxyException;

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
        // Only touch shared machine state if this instance owns the system proxy —
        // another instance's env vars and ownership record are not ours to clear.
        if (!SystemProxyEnabled || LiveForeignOwner() is not null) return;
        try { TurnOffSystemProxy(); }
        catch { /* best-effort cleanup */ }
        try { ClearProxyEnvVars(); }
        catch { /* best-effort cleanup */ }
        try { DeleteOwnerRecord(); }
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
        e.IsValid = e.SslPolicyErrors == SslPolicyErrors.None;
        if (!e.IsValid)
        {
            var host = e.Session?.HttpClient?.Request?.RequestUri?.Host;
            _logger.LogWarning("Rejected upstream certificate for {Host}: {Errors}", host, e.SslPolicyErrors);
            // The failure reported afterwards only says "rejected by the callback", and the
            // session isn't reachable from here, so remember the reason for that host.
            if (host is not null) _rejectedCerts[host] = e.SslPolicyErrors;
        }
        return Task.CompletedTask;
    }

    // ---- Capture handlers --------------------------------------------------
    /// <summary>
    /// Titanium reports failures here instead of through the session events, so without this a
    /// request whose upstream leg fails stays "pending" forever, and a client that rejects our
    /// certificate during the TLS handshake never shows up at all.
    /// </summary>
    private void OnProxyException(Exception ex)
    {
        try
        {
            switch (ex)
            {
                case ProxyConnectException { Session: TunnelConnectSessionEventArgs tunnel }:
                    RecordFailure(tunnel, DescribeTunnelFailure(ex));
                    break;
                case ProxyHttpException { Session: { } session }:
                    RecordFailure(session, DescribeRequestFailure(ex, session));
                    break;
                default:
                    _logger.LogDebug(ex, "Proxy error");
                    break;
            }
        }
        catch (Exception inner)
        {
            _logger.LogDebug(inner, "Could not record proxy failure");
        }
    }

    private void RecordFailure(SessionEventArgsBase args, string error)
    {
        if (RowFor(args) is { } session)
        {
            // Errors after the response arrived (e.g. the client hanging up mid-body) aren't
            // failures of the request itself; don't turn a completed row into an error row.
            if (session.HasResponse) return;
            session.Error ??= error;
            session.DurationMs = (DateTime.UtcNow - session.StartedUtc).TotalMilliseconds;
            Broadcast(_broadcaster.UpdateSessionAsync(SessionSummary.From(session)));
            return;
        }

        // The failure happened before OnBeforeRequest ran (e.g. the client rejected our
        // certificate inside a CONNECT tunnel), so there is no row yet: add one.
        var req = args.HttpClient.Request;
        var uri = req.RequestUri;
        if (!CaptureEnabled || IsOwnTraffic(uri)) return;
        var isTunnel = args is TunnelConnectSessionEventArgs;
        var failed = new CapturedSession
        {
            StartedUtc = DateTime.UtcNow,
            Method = req.Method ?? (isTunnel ? "CONNECT" : ""),
            Scheme = isTunnel ? "https" : uri.Scheme,
            Host = uri.Host,
            Url = isTunnel ? $"{uri.Host}:{uri.Port}" : req.Url,
            Path = isTunnel ? $"{uri.Host}:{uri.Port}" : uri.PathAndQuery,
            RequestHeaders = req.Headers.Select(h => new HeaderItem { Name = h.Name, Value = h.Value }).ToList(),
            Error = error
        };
        _rows.AddOrUpdate(args, failed);
        _store.Add(failed);
        Broadcast(_broadcaster.NewSessionAsync(SessionSummary.From(failed)));
    }

    private CapturedSession? RowFor(SessionEventArgsBase? args) =>
        args is null ? null : args.UserData as CapturedSession ?? (_rows.TryGetValue(args, out var row) ? row : null);

    private void Broadcast(Task send) =>
        send.ContinueWith(t => _logger.LogDebug(t.Exception, "Broadcast failed"), TaskContinuationOptions.OnlyOnFaulted);

    private static string DescribeTunnelFailure(Exception ex)
    {
        if (Find<AuthenticationException>(ex) is not null || Find<IOException>(ex) is not null)
            return "TLS handshake with the client failed: the client doesn't trust the WirePeek root CA " +
                   "(or pins its certificates). Trust the CA in that app, or point it at the CA file. " +
                   $"Details: {Innermost(ex).Message}";
        return $"Tunnel failed: {Innermost(ex).Message}";
    }

    private string DescribeRequestFailure(Exception ex, SessionEventArgsBase session)
    {
        var host = session.HttpClient.Request.RequestUri.Host;
        if (Find<AuthenticationException>(ex) is not null)
            return _rejectedCerts.TryRemove(host, out var errors)
                ? $"The certificate of {host} is not valid ({errors}), so WirePeek refused to connect."
                : $"TLS handshake with {host} failed: {Innermost(ex).Message}";
        if (Find<SocketException>(ex) is { } socket)
            return $"Could not connect to {host}: {socket.Message}";
        return Innermost(ex).Message;
    }

    private static T? Find<T>(Exception? ex) where T : Exception
    {
        for (; ex is not null; ex = ex.InnerException)
            if (ex is T match) return match;
        return null;
    }

    private static Exception Innermost(Exception ex)
    {
        while (ex.InnerException is not null) ex = ex.InnerException;
        return ex;
    }

    /// <summary>
    /// True for requests to WirePeek's own UI or proxy port. Other loopback traffic (a local API
    /// called from Postman or a test) is captured like anything else.
    /// </summary>
    private bool IsOwnTraffic(Uri uri) =>
        (uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        && (uri.Port == _uiPort || uri.Port == Port);

    private async Task OnBeforeRequest(object sender, SessionEventArgs e)
    {
        if (!CaptureEnabled) return;

        var req = e.HttpClient.Request;
        var host = req.RequestUri.Host;
        if (IsOwnTraffic(req.RequestUri)) return;

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
        _rows.AddOrUpdate(e, session);
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
