using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Loopia.Console.Infrastructure.Accounts;

/// <summary>
/// Encrypts account passwords at rest so the store never holds plain text.
/// On Windows this is DPAPI bound to the current user by default; elsewhere, and on Windows when
/// <c>LOOPIA_SECRET_STORE=keyfile</c>, it is AES-GCM with a key kept in a key file next to the store.
/// </summary>
/// <remarks>
/// DPAPI needs the user's logon credentials, so it fails in sessions that have none, such as an
/// OpenSSH login with a key. The key file works in every session. Values written with the key file
/// on Windows carry <see cref="KeyFilePrefix"/>, so either kind can be read back whatever the
/// current setting is.
/// </remarks>
public static class SecretProtector
{
    private static readonly byte[] Entropy = "Loopia.Console/accounts/v1"u8.ToArray();

    private const string KeyFilePrefix = "aesgcm:";

    public const string StoreVariable = "LOOPIA_SECRET_STORE";

    private static bool UseKeyFile
    {
        get
        {
            var forced = Environment.GetEnvironmentVariable(StoreVariable)?.Trim().ToLowerInvariant();
            return forced switch
            {
                null or "" => !OperatingSystem.IsWindows(),
                "keyfile" => true,
                "dpapi" when OperatingSystem.IsWindows() => false,
                _ => throw new InvalidOperationException(
                    $"{StoreVariable}='{forced}' is not available on this platform. " +
                    (OperatingSystem.IsWindows() ? "Use 'dpapi' or 'keyfile', or unset it." : "Use 'keyfile', or unset it.")),
            };
        }
    }

    public static string Describe() => UseKeyFile
        ? $"AES-GCM (key file {AccountStore.KeyFilePath})"
        : "DPAPI (current Windows user)";

    public static string Protect(string plainText)
    {
        var bytes = Encoding.UTF8.GetBytes(plainText);
        if (!UseKeyFile)
            return Convert.ToBase64String(DpapiProtect(bytes));

        var cipher = Convert.ToBase64String(AesProtect(bytes));
        // Linux and macOS keep the unprefixed format they have always written.
        return OperatingSystem.IsWindows() ? KeyFilePrefix + cipher : cipher;
    }

    public static string Unprotect(string cipherText)
    {
        var keyFile = cipherText.StartsWith(KeyFilePrefix, StringComparison.Ordinal);
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(keyFile ? cipherText[KeyFilePrefix.Length..] : cipherText);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("The stored password is corrupt. Recreate the account with 'loopia account create'.");
        }

        if (!keyFile && OperatingSystem.IsWindows())
            return Encoding.UTF8.GetString(DpapiUnprotect(bytes));

        try
        {
            return Encoding.UTF8.GetString(AesUnprotect(bytes));
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException(
                $"The stored password could not be decrypted with the key file {AccountStore.KeyFilePath}. " +
                "It was encrypted with another key file, user or machine; recreate the account with 'loopia account create'.");
        }
    }

    private static byte[] DpapiProtect(byte[] plain)
    {
        try
        {
            return ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException ex)
        {
            throw DpapiUnavailable(ex);
        }
    }

    private static byte[] DpapiUnprotect(byte[] cipher)
    {
        try
        {
            return ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException ex) when (IsAccessDenied(ex))
        {
            throw DpapiUnavailable(ex);
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException(
                "The stored password could not be decrypted. It was encrypted for a different user or machine; " +
                "recreate the account with 'loopia account create'.");
        }
    }

    private static bool IsAccessDenied(CryptographicException ex) => ex.HResult == unchecked((int)0x80070005);

    private static InvalidOperationException DpapiUnavailable(CryptographicException ex) => new(
        $"Windows DPAPI is not available in this session ({ex.Message.TrimEnd('.')}). " +
        "This happens when you are signed in without a password, for example over SSH with a key. " +
        $"Set {StoreVariable}=keyfile to keep passwords encrypted with a key file in {AccountStore.DirectoryPath} instead, " +
        "then run 'loopia account create' (again) for each account.");

    private const int NonceSize = 12;
    private const int TagSize = 16;

    private static byte[] AesProtect(byte[] plain)
    {
        var result = new byte[NonceSize + plain.Length + TagSize];
        var nonce = result.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(LoadOrCreateKey(), TagSize);
        aes.Encrypt(nonce, plain, result.AsSpan(NonceSize, plain.Length), result.AsSpan(NonceSize + plain.Length, TagSize));
        return result;
    }

    private static byte[] AesUnprotect(byte[] cipher)
    {
        if (cipher.Length < NonceSize + TagSize)
            throw new CryptographicException("Cipher text is too short.");

        var plain = new byte[cipher.Length - NonceSize - TagSize];
        using var aes = new AesGcm(LoadOrCreateKey(), TagSize);
        aes.Decrypt(
            cipher.AsSpan(0, NonceSize),
            cipher.AsSpan(NonceSize, plain.Length),
            cipher.AsSpan(NonceSize + plain.Length, TagSize),
            plain);
        return plain;
    }

    private static byte[] LoadOrCreateKey()
    {
        var path = AccountStore.KeyFilePath;
        if (File.Exists(path))
            return Convert.FromBase64String(File.ReadAllText(path).Trim());

        var key = RandomNumberGenerator.GetBytes(32);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, Convert.ToBase64String(key));
        RestrictToOwner(path);
        return key;
    }

    /// <summary>
    /// Makes a file readable and writable by its owner only. On Windows the file keeps the ACL it
    /// inherits from the user profile (the user, SYSTEM and Administrators).
    /// </summary>
    public static void RestrictToOwner(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
