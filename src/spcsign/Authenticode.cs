using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;

namespace SpcSign;

public static class Oids
{
    public const string SignedData = "1.2.840.113549.1.7.2";
    public const string SpcIndirectData = "1.3.6.1.4.1.311.2.1.4";
    public const string SpcPeImageData = "1.3.6.1.4.1.311.2.1.15";
    public const string SpcStatementType = "1.3.6.1.4.1.311.2.1.11";
    public const string SpcSpOpusInfo = "1.3.6.1.4.1.311.2.1.12";
    public const string ContentTypeAttr = "1.2.840.113549.1.9.3";
    public const string MessageDigestAttr = "1.2.840.113549.1.9.4";
    public const string SigningTimeAttr = "1.2.840.113549.1.9.5";
    public const string CountersignatureAttr = "1.2.840.113549.1.9.6";
    public const string StatementTypeAttr = SpcStatementType;
    public const string OpusInfoAttr = SpcSpOpusInfo;
    public const string SignatureTimeStampToken = "1.2.840.113549.1.9.16.2.14";
    public const string IdCtTstInfo = "1.2.840.113549.1.9.16.1.4";
    public const string MsTimestampPolicy = "1.3.6.1.4.1.311.3.2.1";
}

/// <summary>Templates extracted from a known-good signature via `probe`.</summary>
public sealed class SpcTemplates
{
    /// <summary>Raw DER of SpcAttributeTypeAndOptionalValue (the `data` field of SpcIndirectDataContent).</summary>
    public required byte[] DataDer { get; init; }

    /// <summary>Raw DER of additional signed SPC attributes (statementType / opusInfo), concatenated.</summary>
    public required byte[] AttrsDer { get; init; }

    public static SpcTemplates Load(string dir)
    {
        string dataPath = Path.Combine(dir, "spc_data.bin");
        string attrsPath = Path.Combine(dir, "spc_attrs.bin");
        if (!File.Exists(dataPath)) throw new FileNotFoundException($"missing SPC template {dataPath}; run `probe` first");
        return new SpcTemplates
        {
            DataDer = File.ReadAllBytes(dataPath),
            AttrsDer = File.Exists(attrsPath) ? File.ReadAllBytes(attrsPath) : [],
        };
    }

    /// <summary>Splits the concatenated attribute DERs into whole TLV blobs.</summary>
    public IEnumerable<byte[]> SplitAttrs()
    {
        int p = 0;
        while (p < AttrsDer.Length)
        {
            (int hdr, int len) = ReadTlvHeader(AttrsDer, p);
            int total = hdr + len;
            if (p + total > AttrsDer.Length) throw new InvalidDataException("corrupt spc_attrs.bin");
            yield return AttrsDer[p..(p + total)];
            p += total;
        }
    }

    private static (int headerLen, int contentLen) ReadTlvHeader(byte[] b, int p)
    {
        int len = b[p + 1];
        int hdr = 2;
        if ((len & 0x80) != 0)
        {
            int count = len & 0x7F;
            len = 0;
            for (int i = 0; i < count; i++) len = (len << 8) | b[p + 2 + i];
            hdr = 2 + count;
        }
        return (hdr, len);
    }
}

public static class Authenticode
{
    /// <summary>Builds the SpcIndirectDataContent DER (data template + DigestInfo).</summary>
    public static byte[] BuildSpcIndirectData(byte[] dataTemplateDer, byte[] imageHash, bool sha1)
    {
        return DerUtil.Encode(w =>
        {
            w.PushSequence();
            w.WriteEncodedValue(dataTemplateDer);
            w.PushSequence();          // DigestInfo
            DerUtil.WriteDigestAlgorithm(w, sha1);
            w.WriteOctetString(imageHash);
            w.PopSequence();
            w.PopSequence();
        });
    }

    /// <summary>
    /// Builds the four Authenticode attributes in the legacy tool order:
    /// opusInfo, contentType, statementType, messageDigest (what mssign32-based
    /// signers emit; the verifier's countersign path pairs with this layout).
    /// messageDigest follows the flat-eContent convention: digest of the value part
    /// of the SpcIndirectDataContent SEQUENCE (no outer TLV header).
    /// </summary>
    private static List<byte[]> BuildAttrs(byte[] contentDigest, SpcTemplates tpl)
    {
        byte[] Attr(string oid, Action<AsnWriter> writeValue) => DerUtil.Encode(a =>
        {
            a.PushSequence();
            a.WriteObjectIdentifier(oid);
            a.PushSetOf();
            writeValue(a);
            a.PopSetOf();
            a.PopSequence();
        });

        var template = tpl.SplitAttrs();
        byte[] FindTemplateAttr(string oid)
        {
            foreach (byte[] t in template)
            {
                var r = new AsnReader(t, AsnEncodingRules.DER).ReadSequence();
                if (r.ReadObjectIdentifier() == oid) return t;
            }
            throw new InvalidOperationException($"template attr {oid} missing");
        }

        // opusInfo: empty SpcSpOpusInfo (SET { SEQUENCE {} }) — the legacy signer layout.
        // The rich 3ware.sys-style opus (program name + URL) is rejected by the driver
        // verification path, so legacy signers emit the empty form.
        byte[] emptyOpus = DerUtil.Encode(a =>
        {
            a.PushSequence();
            a.WriteObjectIdentifier(Oids.OpusInfoAttr);
            a.PushSetOf();
            a.WriteEncodedValue([0x30, 0x00]);
            a.PopSetOf();
            a.PopSequence();
        });

        return
        [
            emptyOpus,
            Attr(Oids.ContentTypeAttr, a => a.WriteObjectIdentifier(Oids.SpcIndirectData)),
            FindTemplateAttr(Oids.StatementTypeAttr),
            Attr(Oids.MessageDigestAttr, a => a.WriteOctetString(contentDigest)),
        ];
    }

    private static void WriteSignedAttrs(AsnWriter w, List<byte[]> attrs, bool implicitContextZero)
    {
        Asn1Tag? shell = implicitContextZero ? new Asn1Tag(TagClass.ContextSpecific, 0) : null;
        if (shell is not null) w.PushSequence(shell); else w.PushSetOf();
        foreach (byte[] attr in attrs)
            w.WriteEncodedValue(attr);
        if (shell is not null) w.PopSequence(shell); else w.PopSetOf();
    }

    /// <summary>Produces the DER of the SET OF (universal tag 0x31) that gets signed.</summary>
    private static byte[] EncodeSignedAttrsForSigning(List<byte[]> attrs)
    {
        return DerUtil.Encode(w => WriteSignedAttrs(w, attrs, implicitContextZero: false));
    }

    /// <summary>
    /// Builds the full Authenticode PKCS#7 ContentInfo DER.
    /// </summary>
    public static byte[] BuildSignedPkcs7(
        byte[] signerCertDer,
        RSA signerKey,
        byte[] spcIndirectDer,
        byte[] imageHash,
        IReadOnlyList<byte[]> extraCerts,
        SpcTemplates tpl,
        byte[]? tstContentInfoDer,
        bool sha1)
    {
        var hashAlg = sha1 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
        // 1. Sign the DER of the SET OF signedAttrs (universal SET tag, not [0]).
        // messageDigest follows the flat-eContent convention: the value part of the
        // SpcIndirectDataContent SEQUENCE (without its TLV header) is the digested content.
        byte[] spcContent = DerUtil.ContentOf(spcIndirectDer);
        byte[] contentDigest = sha1
            ? System.Security.Cryptography.SHA1.HashData(spcContent)
            : System.Security.Cryptography.SHA256.HashData(spcContent);
        var attrs = BuildAttrs(contentDigest, tpl);
        byte[] attrsForSigning = EncodeSignedAttrsForSigning(attrs);
        byte[] signature = signerKey.SignData(attrsForSigning, hashAlg, RSASignaturePadding.Pkcs1);

        // 2. Wrap as ContentInfo(signedData).
        var ctx0 = new Asn1Tag(TagClass.ContextSpecific, 0);
        var ctx1 = new Asn1Tag(TagClass.ContextSpecific, 1);
        return DerUtil.Encode(w =>
        {
            w.PushSequence();
            w.WriteObjectIdentifier(Oids.SignedData);
            w.PushSequence(ctx0); // [0] EXPLICIT SignedData

            w.PushSequence(); // SignedData
            w.WriteInteger(1); // version
            w.PushSetOf();     // digestAlgorithms
            DerUtil.WriteDigestAlgorithm(w, sha1);
            w.PopSetOf();

            w.PushSequence(); // encapContentInfo
            w.WriteObjectIdentifier(Oids.SpcIndirectData);
            DerUtil.WriteExplicitContext(w, 0, spcIndirectDer);
            w.PopSequence();

            w.PushSetOf(ctx0); // [0] IMPLICIT CertificateSet
            w.WriteEncodedValue(signerCertDer);
            foreach (byte[] c in extraCerts) w.WriteEncodedValue(c);
            w.PopSetOf(ctx0);

            w.PushSetOf(); // signerInfos
            w.PushSequence(); // SignerInfo
            w.WriteInteger(1); // version
            (byte[] issuerDer, BigInteger serial) = DerUtil.ReadIssuerAndSerial(signerCertDer);
            w.PushSequence(); // issuerAndSerialNumber
            w.WriteEncodedValue(issuerDer);
            w.WriteInteger(serial);
            w.PopSequence();
            DerUtil.WriteDigestAlgorithm(w, sha1); // SignerInfo digestAlgorithm
            WriteSignedAttrs(w, attrs, implicitContextZero: true); // identical content bytes to the signed encoding
            DerUtil.WriteRsaEncryption(w);
            w.WriteOctetString(signature);
            if (tstContentInfoDer is not null)
            {
                w.PushSetOf(ctx1); // [1] IMPLICIT unsignedAttrs
                w.PushSequence(); // Attribute(countersignature) — legacy Authenticode timestamp
                w.WriteObjectIdentifier(Oids.CountersignatureAttr);
                w.PushSetOf();
                w.WriteEncodedValue(tstContentInfoDer); // the countersigner SignerInfo DER
                w.PopSetOf();
                w.PopSequence();
                w.PopSetOf(ctx1);
            }
            w.PopSequence(); // SignerInfo
            w.PopSetOf();    // signerInfos
            w.PopSequence(); // SignedData

            w.PopSequence(ctx0); // [0] EXPLICIT
            w.PopSequence(); // ContentInfo
        });
    }
}
