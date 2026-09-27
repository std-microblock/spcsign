using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SpcSign;

public static class Timestamp
{
    /// <summary>
    /// Legacy Authenticode countersignature (PKCS#9), matching what signtool timestamp /t
    /// and the old pipeline produce: a SignerInfo carrying contentType=messageDigest-signingTime,
    /// embedded as the 1.2.840.113549.1.9.6 unsigned attribute of the main SignerInfo.
    /// wintrust takes signingTime as the authoritative signing time.
    /// </summary>
    public static byte[] BuildCountersign(
        byte[] mainSignature,
        RSA tsaKey,
        byte[] tsaCertDer,
        DateTimeOffset genTime)
    {
        byte[] imprint = System.Security.Cryptography.SHA1.HashData(mainSignature);

        // signedAttrs: contentType, signingTime, messageDigest in the legacy signer
        // order (not DER-sorted); crypt32 accepts and reproduces it, so match it byte for byte.
        byte[][] attrDers =
        [
            DerUtil.Encode(a =>
            {
                a.PushSequence(); // contentType = id-data
                a.WriteObjectIdentifier("1.2.840.113549.1.9.3");
                a.PushSetOf();
                a.WriteObjectIdentifier("1.2.840.113549.1.7.1");
                a.PopSetOf();
                a.PopSequence();
            }),
            DerUtil.Encode(a =>
            {
                a.PushSequence(); // signingTime
                a.WriteObjectIdentifier("1.2.840.113549.1.9.5");
                a.PushSetOf();
                a.WriteUtcTime(genTime.UtcDateTime);
                a.PopSetOf();
                a.PopSequence();
            }),
            DerUtil.Encode(a =>
            {
                a.PushSequence(); // messageDigest = SHA-1(main signature)
                a.WriteObjectIdentifier("1.2.840.113549.1.9.4");
                a.PushSetOf();
                a.WriteOctetString(imprint);
                a.PopSetOf();
                a.PopSequence();
            }),
        ];

        // the TSA signature covers the universal SET OF encoding of the attributes,
        // hand-assembled because AsnWriter would force DER sorting of the SET.
        byte[] attrsContent = new byte[attrDers.Sum(a => a.Length)];
        int off = 0;
        foreach (byte[] attr in attrDers)
        {
            attr.CopyTo(attrsContent, off);
            off += attr.Length;
        }
        byte[] attrsDer = DerUtil.MakeTlv(0x31, attrsContent);
        byte[] signature = tsaKey.SignData(attrsDer, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        (byte[] issuerDer, BigInteger serial) = DerUtil.ReadIssuerAndSerial(tsaCertDer);
        var ctx0 = new Asn1Tag(TagClass.ContextSpecific, 0);
        return DerUtil.Encode(w =>
        {
            w.PushSequence(); // SignerInfo
            w.WriteInteger(1); // version
            w.PushSequence(); // issuerAndSerialNumber
            w.WriteEncodedValue(issuerDer);
            w.WriteInteger(serial);
            w.PopSequence();

            w.PushSequence(); // digestAlgorithm = SHA-1
            w.WriteObjectIdentifier("1.3.14.3.2.26");
            w.WriteNull();
            w.PopSequence();

            w.PushSequence(ctx0); // [0] IMPLICIT signedAttrs — attribute TLVs directly, no SET wrapper
            foreach (byte[] attr in attrDers) w.WriteEncodedValue(attr);
            w.PopSequence(ctx0);

            w.PushSequence(); // digestEncryptionAlgorithm = sha1WithRSAEncryption, no NULL (matches legacy tooling)
            w.WriteObjectIdentifier("1.2.840.113549.1.1.5");
            w.PopSequence();
            w.WriteOctetString(signature);
            w.PopSequence();
        });
    }
}

/// <summary>Generates the local TSA (root + leaf with id-kp-timeStamping EKU, valid 2000..2099).
/// All private-key work happens inside; callers get PFX/CER bytes.</summary>
public static class TsaGen
{
    public sealed record TsaMaterial(byte[] RootPfx, byte[] RootCer, byte[] LeafPfx, byte[] LeafCer);

    public static TsaMaterial Generate(string commonName, string pfxPassword)
    {
        DateTimeOffset nb = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);
        DateTimeOffset na = new(2099, 12, 31, 23, 59, 59, TimeSpan.Zero);

        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest($"CN={commonName} Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 2, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using X509Certificate2 root = rootReq.CreateSelfSigned(nb, na);

        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest($"CN={commonName}", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var eku = new OidCollection { new("1.3.6.1.5.5.7.3.8", "Time Stamping") }; // id-kp-timeStamping
        leafReq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using X509Certificate2 publicLeaf = leafReq.Create(root, nb, na, serial);
        using X509Certificate2 leaf = publicLeaf.CopyWithPrivateKey(leafKey);

        byte[] rootPfx = root.Export(X509ContentType.Pfx, pfxPassword);
        byte[] rootCer = root.Export(X509ContentType.Cert);
        byte[] leafPfx = leaf.Export(X509ContentType.Pfx, pfxPassword);
        byte[] leafCer = leaf.Export(X509ContentType.Cert);
        return new TsaMaterial(rootPfx, rootCer, leafPfx, leafCer);
    }
}
