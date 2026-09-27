using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SpcSign;

/// <summary>Loads the signing certificate (from the user store or a PFX) and chain material.</summary>
public static class CertLoader
{
    public static (X509Certificate2 cert, RSA key) FromStore(string thumbprintOrSubject)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        X509Certificate2? found = null;
        foreach (X509Certificate2 c in store.Certificates)
        {
            if (c.Thumbprint.Equals(thumbprintOrSubject, StringComparison.OrdinalIgnoreCase) ||
                c.Subject.Contains(thumbprintOrSubject, StringComparison.OrdinalIgnoreCase))
            {
                found = c;
                break;
            }
        }
        if (found is null) throw new FileNotFoundException($"certificate '{thumbprintOrSubject}' not found in CurrentUser\\My");
        if (!found.HasPrivateKey) throw new InvalidOperationException("certificate has no private key");
        RSA key = found.GetRSAPrivateKey() ?? throw new InvalidOperationException("private key is not RSA");
        return (found, key);
    }

    public static (X509Certificate2 cert, RSA key) FromPfx(string path, string password)
    {
        using X509Certificate2 col = X509CertificateLoader.LoadPkcs12FromFile(path, password,
            X509KeyStorageFlags.EphemeralKeySet);
        RSA key = col.GetRSAPrivateKey() ?? throw new InvalidOperationException("PFX private key is not RSA");
        return (col, key);
    }

    /// <summary>Reads every certificate from a PFX (leaf + any embedded intermediates).</summary>
    public static List<byte[]> AllCertsFromPfx(string path, string password)
    {
        X509Certificate2Collection col = X509CertificateLoader.LoadPkcs12CollectionFromFile(path, password,
            X509KeyStorageFlags.EphemeralKeySet);
        return col.Cast<X509Certificate2>().Select(c => c.Export(X509ContentType.Cert)).ToList();
    }

    public static byte[] LoadCer(string path) => X509CertificateLoader.LoadCertificateFromFile(path).Export(X509ContentType.Cert);
}
