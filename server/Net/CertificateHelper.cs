using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SeroServer.Net;

public static class CertificateHelper
{
    private static readonly string CertDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer");
    private static readonly string CertPath = Path.Combine(CertDir, "server.pfx");
    private static readonly string PasswordPath = Path.Combine(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer"), "cert.key");

    private static string CertPassword
    {
        get
        {
            if (File.Exists(PasswordPath))
                return File.ReadAllText(PasswordPath).Trim();
            // Generate and persist a new random password
            var pwd = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
            Directory.CreateDirectory(CertDir);
            File.WriteAllText(PasswordPath, pwd);
            return pwd;
        }
    }

    /// <summary>
    /// Load or generate a self-signed TLS certificate.
    /// </summary>
    public static X509Certificate2 GetOrCreateCertificate()
    {
        Directory.CreateDirectory(CertDir);

        if (File.Exists(CertPath))
        {
            try
            {
                var cert = X509CertificateLoader.LoadPkcs12FromFile(CertPath, CertPassword);
                if (cert.NotAfter > DateTime.Now)
                    return cert;
            }
            catch { }
        }

        return GenerateAndSave();
    }

    public static X509Certificate2 GenerateAndSave()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=SeroServer, O=Sero, OU=Loader",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false)); // Server Auth

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
        sanBuilder.AddIpAddress(System.Net.IPAddress.Any);
        req.CertificateExtensions.Add(sanBuilder.Build());

        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

        var exported = cert.Export(X509ContentType.Pfx, CertPassword);
        File.WriteAllBytes(CertPath, exported);

        return X509CertificateLoader.LoadPkcs12(exported, CertPassword);
    }

    /// <summary>
    /// Import a .pfx certificate file, replacing the current one.
    /// </summary>
    public static void ImportCertificate(string pfxPath, string? password = null)
    {
        X509Certificate2? cert = null;

        const X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet;

        if (password != null)
        {
            cert = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password, flags);
        }
        else
        {
            foreach (var pwd in new string?[] { "", CertPassword, null })
            {
                try
                {
                    cert = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, pwd ?? "", flags);
                    break;
                }
                catch { }
            }
            if (cert == null)
                throw new InvalidOperationException("Could not read the certificate. It may require a password.");
        }

        if (!cert.HasPrivateKey)
            throw new InvalidOperationException("The certificate must contain a private key.");

        Directory.CreateDirectory(CertDir);
        var exported = cert.Export(X509ContentType.Pfx, CertPassword);
        File.WriteAllBytes(CertPath, exported);
    }

    /// <summary>
    /// Export the full .pfx certificate (with private key) to a chosen path, with no password.
    /// The user can import it without needing to type anything.
    /// </summary>
    public static void ExportPfx(string destinationPath)
    {
        if (!File.Exists(CertPath))
            GenerateAndSave();
        var cert = X509CertificateLoader.LoadPkcs12FromFile(CertPath, CertPassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        // Export with empty password so no password is needed on import
        File.WriteAllBytes(destinationPath, cert.Export(X509ContentType.Pfx, ""));
    }

    /// <summary>
    /// Generate a new certificate, save internally, and export a no-password copy to destinationPath.
    /// </summary>
    public static void GenerateAndExportTo(string destinationPath)
    {
        var cert = GenerateAndSave();
        File.WriteAllBytes(destinationPath, cert.Export(X509ContentType.Pfx, ""));
    }

    /// <summary>
    /// Export the public key for embedding in the client.
    /// </summary>
    public static byte[] ExportPublicKey()
    {
        var cert = GetOrCreateCertificate();
        return cert.Export(X509ContentType.Cert);
    }

    /// <summary>
    /// Get SHA256 hash of the certificate for cert pinning.
    /// </summary>
    public static string GetCertSha256Hash()
    {
        var cert = GetOrCreateCertificate();
        var hash = SHA256.HashData(cert.RawData);
        return Convert.ToHexString(hash);
    }
}
