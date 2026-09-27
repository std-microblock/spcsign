using System.Formats.Asn1;
using System.Numerics;

namespace SpcSign;

/// <summary>Minimal DER primitives the CMS builder needs on top of System.Formats.Asn1.</summary>
public static class DerUtil
{
    public static byte[] Sha256(ReadOnlySpan<byte> data) => System.Security.Cryptography.SHA256.HashData(data);

    public static void WriteDigestAlgorithm(AsnWriter w, bool sha1)
    {
        w.PushSequence();
        w.WriteObjectIdentifier(sha1 ? "1.3.14.3.2.26" : "2.16.840.1.101.3.4.2.1"); // SHA-1 / SHA-256
        w.WriteNull();
        w.PopSequence();
    }

    public static void WriteSha256Algorithm(AsnWriter w) => WriteDigestAlgorithm(w, sha1: false);

    public static void WriteRsaEncryption(AsnWriter w)
    {
        w.PushSequence();
        w.WriteObjectIdentifier("1.2.840.113549.1.1.1"); // rsaEncryption
        w.WriteNull();
        w.PopSequence();
    }

    /// <summary>Writes [n] EXPLICIT wrapping the given inner DER (constructed context tag).</summary>
    public static void WriteExplicitContext(AsnWriter w, int n, ReadOnlySpan<byte> innerDer)
    {
        var tag = new Asn1Tag(TagClass.ContextSpecific, n);
        w.PushSequence(tag);
        w.WriteEncodedValue(innerDer.ToArray());
        w.PopSequence(tag);
    }

    public static byte[] Encode(Action<AsnWriter> body)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        body(w);
        return w.Encode();
    }

    /// <summary>Returns the value bytes of a single TLV (everything after the header).</summary>
    public static byte[] ContentOf(ReadOnlySpan<byte> tlv)
    {
        // header: tag byte + short/long-form length
        int p = 1;
        int len = tlv[p++];
        if ((len & 0x80) != 0)
        {
            int count = len & 0x7F;
            len = 0;
            for (int i = 0; i < count; i++) len = (len << 8) | tlv[p++];
        }
        return tlv.Slice(p, len).ToArray();
    }

    /// <summary>Builds a TLV with the given tag byte and content, DER long-form lengths when needed.</summary>
    public static byte[] MakeTlv(byte tag, ReadOnlySpan<byte> content)
    {
        var ms = new MemoryStream(2 + content.Length);
        ms.WriteByte(tag);
        if (content.Length < 0x80)
        {
            ms.WriteByte((byte)content.Length);
        }
        else
        {
            int len = content.Length;
            byte[] tmp = new byte[5];
            int n = 0;
            while (len > 0) { tmp[n++] = (byte)(len & 0xFF); len >>= 8; }
            ms.WriteByte((byte)(0x80 | n));
            for (int i = n - 1; i >= 0; i--) ms.WriteByte(tmp[i]);
        }
        ms.Write(content);
        return ms.ToArray();
    }

    /// <summary>Extracts the raw issuer Name DER and the serial number from a certificate.</summary>
    public static (byte[] issuerDer, BigInteger serial) ReadIssuerAndSerial(byte[] certDer)
    {
        var r = new AsnReader(certDer, AsnEncodingRules.DER);
        var outer = r.ReadSequence();
        var tbs = outer.ReadSequence();
        // TBSCertificate: [0] version?, serialNumber, signature (AlgorithmIdentifier), issuer, ...
        var first = tbs.PeekTag();
        if (first.TagClass == TagClass.ContextSpecific && first.TagValue == 0)
            tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        BigInteger serial = tbs.ReadInteger();
        tbs.ReadSequence(); // signature AlgorithmIdentifier — skipped
        byte[] issuerDer = tbs.ReadEncodedValue().ToArray();
        return (issuerDer, serial);
    }

    /// <summary>Prints a compact structural dump of a DER blob (for `dump` and debugging).</summary>
    public static void Dump(AsnReader reader, string indent, TextWriter tw, int depth = 0)
    {
        if (depth > 12) { tw.WriteLine(indent + "..."); return; }
        while (reader.HasData)
        {
            var tag = reader.PeekTag();
            string label = tag.TagClass switch
            {
                TagClass.Universal => tag.TagValue switch
                {
                    0x02 => "INTEGER",
                    0x03 => "BIT STRING",
                    0x04 => "OCTET STRING",
                    0x05 => "NULL",
                    0x06 => "OID",
                    0x0C => "UTF8String",
                    0x10 => "SEQUENCE",
                    0x11 => "SET",
                    0x13 => "PrintableString",
                    0x16 => "IA5String",
                    0x17 => "UTCTime",
                    0x18 => "GeneralizedTime",
                    0x1E => "BMPString",
                    _ => $"universal({tag.TagValue:X2})",
                },
                TagClass.ContextSpecific => $"[{tag.TagValue}]",
                _ => tag.TagClass.ToString(),
            };

            if (tag.TagClass == TagClass.Universal && tag.TagValue == 0x06)
            {
                string oid = reader.ReadObjectIdentifier();
                tw.WriteLine($"{indent}{label}  {oid}");
            }
            else if (tag.IsConstructed)
            {
                int len = reader.PeekEncodedValue().ToArray().Length;
                tw.WriteLine($"{indent}{label}  ({len} bytes)");
                AsnReader sub = tag.TagClass == TagClass.ContextSpecific
                    ? reader.ReadSequence(tag)
                    : tag.TagValue == 0x11 ? reader.ReadSetOf(true, expectedTag: null)
                    : reader.ReadSequence();
                try { Dump(sub, indent + "  ", tw, depth + 1); } catch { /* tolerate weird contents */ }
            }
            else
            {
                byte[] raw = reader.ReadEncodedValue().ToArray();
                tw.WriteLine($"{indent}{label}  ({raw.Length} bytes)");
            }
        }
    }
}
