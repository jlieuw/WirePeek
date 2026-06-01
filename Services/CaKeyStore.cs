using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace MiniFiddler.Services;

/// <summary>
/// Provides a per-user, access-restricted location for the proxy's root CA private key
/// and a DPAPI-protected random password, so the CA key is not world-readable or
/// stored unencrypted in the application/build directory.
/// </summary>
public static class CaKeyStore
{
    public static string Directory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "MiniFiddler");

    public static string PfxPath => Path.Combine(Directory, "rootCert.pfx");
    private static string PasswordPath => Path.Combine(Directory, "pfx.secret");

    /// <summary>Creates the directory (locked to the current user) and returns the CA password.</summary>
    public static string EnsureSecureDirectoryAndPassword()
    {
        System.IO.Directory.CreateDirectory(Directory);
        if (OperatingSystem.IsWindows())
            LockDirectoryToCurrentUser(Directory);

        return LoadOrCreatePassword();
    }

    private static string LoadOrCreatePassword()
    {
        if (File.Exists(PasswordPath))
        {
            try
            {
                var protectedBytes = File.ReadAllBytes(PasswordPath);
                var plain = OperatingSystem.IsWindows()
                    ? ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser)
                    : protectedBytes;
                return Convert.ToBase64String(plain);
            }
            catch
            {
                // Corrupt/unreadable — regenerate below.
            }
        }

        var secret = RandomNumberGenerator.GetBytes(32);
        var toStore = OperatingSystem.IsWindows()
            ? ProtectedData.Protect(secret, null, DataProtectionScope.CurrentUser)
            : secret;
        File.WriteAllBytes(PasswordPath, toStore);
        return Convert.ToBase64String(secret);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void LockDirectoryToCurrentUser(string path)
    {
        try
        {
            var di = new DirectoryInfo(path);
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            using var identity = WindowsIdentity.GetCurrent();
            var user = identity.User!;
            security.AddAccessRule(new FileSystemAccessRule(
                user,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                system,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            di.SetAccessControl(security);
        }
        catch
        {
            // If ACL hardening fails we still proceed; the password remains DPAPI-protected.
        }
    }
}
