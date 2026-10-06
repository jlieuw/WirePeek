using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace WirePeek.Services;

/// <summary>
/// macOS counterparts of the Windows-only integration in <see cref="ProxyService"/>:
/// trusting the root CA in the user's login keychain, pointing the system proxy at us via
/// <c>networksetup</c>, and the on-disk state that lets a later run undo a crashed session.
/// </summary>
[SupportedOSPlatform("macos")]
public static class MacSystemIntegration
{
    private const string Security = "/usr/bin/security";
    private const string NetworkSetup = "/usr/sbin/networksetup";
    private const string Scutil = "/usr/sbin/scutil";

    // Hosts that must never go through the proxy, so enabling capture never breaks the UI.
    private static readonly string[] LoopbackBypass = ["localhost", "127.0.0.1", "::1"];

    // Original per-service proxy settings, saved before we overwrite them. Its presence acts as
    // a sentinel that WirePeek owns the current settings (like EnvBackup on Windows).
    private static string BackupPath => Path.Combine(CaKeyStore.Directory, "system-proxy-backup.json");

    // Which WirePeek process owns the system proxy (like the SystemProxy registry key on Windows).
    private static string OwnerPath => Path.Combine(CaKeyStore.Directory, "system-proxy-owner.json");

    private static string LoginKeychain => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "Keychains", "login.keychain-db");

    // ---- Root certificate -------------------------------------------------

    /// <summary>True if macOS trusts the root CA (i.e. a chain to it builds without errors).</summary>
    public static bool IsRootTrusted(X509Certificate2 root)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(root);
    }

    /// <summary>
    /// Adds the CA to the login keychain with user-level "always trust" settings. macOS shows
    /// its own authentication dialog for this; cancelling it surfaces as an error.
    /// </summary>
    public static void TrustRoot(string pemPath) =>
        RunOrThrow(Security, "add-trusted-cert", "-r", "trustRoot", "-k", LoginKeychain, pemPath);

    /// <summary>Removes the user-level trust settings for the CA (the cert itself stays in the keychain).</summary>
    public static void UntrustRoot(string pemPath) =>
        RunOrThrow(Security, "remove-trusted-cert", pemPath);

    // ---- System proxy -----------------------------------------------------

    private sealed record ProxySetting(bool Enabled, string Server, int Port);
    private sealed record ServiceBackup(string Service, ProxySetting Web, ProxySetting Secure, string[] Bypass);
    public sealed record OwnerRecord(int Port, int Pid, string ProcessName);

    /// <summary>
    /// Points the HTTP and HTTPS proxy of every enabled network service at 127.0.0.1:<paramref name="port"/>,
    /// adding loopback to each service's bypass list. Originals are backed up first — only if no
    /// backup exists yet, so a re-enable never overwrites the real originals with our own values.
    /// </summary>
    public static void EnableSystemProxy(int port)
    {
        var services = EnabledNetworkServices();
        if (services.Count == 0) throw new InvalidOperationException("No enabled network services found.");

        List<ServiceBackup> backups;
        if (File.Exists(BackupPath))
        {
            backups = ReadBackup() ?? [];
        }
        else
        {
            backups = services.Select(s => new ServiceBackup(
                s,
                GetProxy("getwebproxy", s),
                GetProxy("getsecurewebproxy", s),
                GetBypassDomains(s))).ToList();
            WriteJson(BackupPath, backups);
        }

        foreach (var service in services)
        {
            RunNetworkSetup("-setwebproxy", service, "127.0.0.1", port.ToString());
            RunNetworkSetup("-setsecurewebproxy", service, "127.0.0.1", port.ToString());

            var original = backups.FirstOrDefault(b => b.Service == service)?.Bypass ?? [];
            var bypass = original.Concat(LoopbackBypass).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            RunNetworkSetup(["-setproxybypassdomains", service, .. bypass]);
        }
    }

    /// <summary>Restores the backed-up settings (if any) and deletes the backup. Returns false if there was none.</summary>
    public static bool RestoreSystemProxy()
    {
        if (!File.Exists(BackupPath)) return false; // We never changed the settings; nothing to restore.

        var current = EnabledNetworkServices().ToHashSet();
        var backups = ReadBackup();
        if (backups is null)
        {
            // Unreadable backup: the originals are lost, but at least stop routing through us.
            foreach (var service in current)
            {
                RunNetworkSetup("-setwebproxystate", service, "off");
                RunNetworkSetup("-setsecurewebproxystate", service, "off");
            }
            ForgetSystemProxyBackup();
            return true;
        }

        foreach (var b in backups.Where(b => current.Contains(b.Service)))
        {
            SetProxy("web", b.Service, b.Web);
            SetProxy("secureweb", b.Service, b.Secure);
            RunNetworkSetup(b.Bypass.Length == 0
                ? ["-setproxybypassdomains", b.Service, "Empty"]
                : ["-setproxybypassdomains", b.Service, .. b.Bypass]);
        }
        ForgetSystemProxyBackup();
        return true;
    }

    /// <summary>Drops the backup without applying it (the settings are no longer ours to restore).</summary>
    public static void ForgetSystemProxyBackup() => File.Delete(BackupPath);

    public static bool HasSystemProxyBackup => File.Exists(BackupPath);

    /// <summary>The effective system HTTP(S) proxy as macOS reports it (primary service), as "host:port".</summary>
    public static (bool Enabled, string Server) ReadSystemProxy()
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in RunOrThrow(Scutil, "--proxy").Split('\n'))
        {
            var parts = line.Split(" : ", 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 2) values[parts[0]] = parts[1];
        }

        foreach (var prefix in new[] { "HTTPS", "HTTP" })
        {
            if (values.GetValueOrDefault($"{prefix}Enable") == "1")
                return (true, $"{values.GetValueOrDefault($"{prefix}Proxy")}:{values.GetValueOrDefault($"{prefix}Port")}");
        }
        return (false, "");
    }

    // ---- Ownership record -------------------------------------------------

    public static void WriteOwner(OwnerRecord owner) => WriteJson(OwnerPath, owner);

    public static OwnerRecord? ReadOwner()
    {
        try { return File.Exists(OwnerPath) ? JsonSerializer.Deserialize<OwnerRecord>(File.ReadAllText(OwnerPath)) : null; }
        catch { return null; }
    }

    public static void DeleteOwner() => File.Delete(OwnerPath);

    // ---- networksetup helpers ---------------------------------------------

    private static List<string> EnabledNetworkServices() =>
        RunOrThrow(NetworkSetup, "-listallnetworkservices")
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Skip(1) // "An asterisk (*) denotes that a network service is disabled."
            .Where(s => !s.StartsWith('*'))
            .ToList();

    private static ProxySetting GetProxy(string command, string service)
    {
        var values = RunOrThrow(NetworkSetup, $"-{command}", service)
            .Split('\n')
            .Select(l => l.Split(':', 2, StringSplitOptions.TrimEntries))
            .Where(p => p.Length == 2)
            .ToDictionary(p => p[0], p => p[1]);
        return new ProxySetting(
            values.GetValueOrDefault("Enabled") == "Yes",
            values.GetValueOrDefault("Server") ?? "",
            int.TryParse(values.GetValueOrDefault("Port"), out var port) ? port : 0);
    }

    private static void SetProxy(string kind, string service, ProxySetting s)
    {
        RunNetworkSetup($"-set{kind}proxy", service, s.Server, s.Port.ToString());
        RunNetworkSetup($"-set{kind}proxystate", service, s.Enabled ? "on" : "off");
    }

    private static string[] GetBypassDomains(string service)
    {
        var output = RunOrThrow(NetworkSetup, "-getproxybypassdomains", service);
        if (output.StartsWith("There aren't any", StringComparison.Ordinal)) return [];
        return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    // networksetup reports some failures on stdout with exit code 0.
    private static void RunNetworkSetup(params string[] args)
    {
        var output = RunOrThrow(NetworkSetup, args);
        if (output.Contains("** Error", StringComparison.Ordinal))
            throw new InvalidOperationException($"networksetup {string.Join(' ', args)}: {output.Trim()}");
    }

    private static string RunOrThrow(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {file}.");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0)
            throw new InvalidOperationException(
                $"{Path.GetFileName(file)} {args.FirstOrDefault()} failed (exit {p.ExitCode}): {stderr.Trim()}");
        return stdout.Result;
    }

    // ---- State files ------------------------------------------------------

    private static List<ServiceBackup>? ReadBackup()
    {
        try { return JsonSerializer.Deserialize<List<ServiceBackup>>(File.ReadAllText(BackupPath)); }
        catch { return null; }
    }

    // Write-then-rename so a crash never leaves a half-written state file behind.
    private static void WriteJson<T>(string path, T value)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value));
        CaKeyStore.RestrictFileToCurrentUser(tmp);
        File.Move(tmp, path, overwrite: true);
    }
}
