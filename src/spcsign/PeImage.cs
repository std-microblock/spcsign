namespace SpcSign;

/// <summary>
/// PE parsing, Authenticode image hashing, certificate-table patching, checksum.
/// Layout rules follow the Windows PE spec: the SECURITY directory entry holds a
/// file offset (not an RVA) and WIN_CERTIFICATE entries are 8-byte aligned.
/// </summary>
public sealed class PeImage
{
    public byte[] Raw;
    public readonly int Lfanew;
    public readonly ushort NumberOfSections;
    public readonly ushort SizeOfOptionalHeader;
    public readonly bool IsPe32Plus;
    public readonly int OptStart;          // offset of the optional header
    public readonly int ChecksumOffset;    // where the 4-byte PE checksum lives
    public readonly int DataDirOffset;     // start of the 16 data directory entries
    public readonly int CoffSymbolPtr;     // COFF PointerToSymbolTable (lfanew+12)
    public readonly int CoffSymbolCount;   // COFF NumberOfSymbols (lfanew+16)

    public const int DirSecurityIndex = 4; // IMAGE_DIRECTORY_ENTRY_SECURITY

    public PeImage(byte[] raw)
    {
        if (raw.Length < 0x100 || raw[0] != 'M' || raw[1] != 'Z') throw new InvalidDataException("not a PE file (no MZ)");
        Lfanew = BitConverter.ToInt32(raw, 0x3C);
        if (Lfanew < 0 || Lfanew + 24 > raw.Length) throw new InvalidDataException("bad e_lfanew");
        if (raw[Lfanew] != 'P' || raw[Lfanew + 1] != 'E') throw new InvalidDataException("no PE signature");
        NumberOfSections = BitConverter.ToUInt16(raw, Lfanew + 6);
        SizeOfOptionalHeader = BitConverter.ToUInt16(raw, Lfanew + 20);
        OptStart = Lfanew + 4 + 20;
        ushort magic = BitConverter.ToUInt16(raw, OptStart);
        IsPe32Plus = magic == 0x20B;
        if (magic != 0x10B && !IsPe32Plus) throw new InvalidDataException($"unknown optional header magic 0x{magic:X}");
        ChecksumOffset = OptStart + 64;
        DataDirOffset = OptStart + (IsPe32Plus ? 112 : 96);
        CoffSymbolPtr = Lfanew + 12;
        CoffSymbolCount = Lfanew + 16;
        Raw = raw;
    }

    /// <summary>(offset, size) of the certificate table in file bytes; (0,0) when unsigned.</summary>
    public (int Offset, int Size) SecurityDir
    {
        get
        {
            int va = BitConverter.ToInt32(Raw, DataDirOffset + DirSecurityIndex * 8);
            int size = BitConverter.ToInt32(Raw, DataDirOffset + DirSecurityIndex * 8 + 4);
            return (va, size);
        }
    }

    /// <summary>
    /// Authenticode image hash, "skip" model per the PE spec: the excluded regions
    /// (CheckSum field, SECURITY data-directory entry, certificate table, COFF symbol
    /// table) never enter the hash stream — they are not zeroed but skipped over.
    /// </summary>
    public byte[] ComputeImageHash(System.Security.Cryptography.HashAlgorithmName alg)
    {
        int certDirEntry = DataDirOffset + DirSecurityIndex * 8;
        var (certOff, _) = SecurityDir;
        int end = certOff != 0 ? certOff : Raw.Length;
        if (certOff > Raw.Length) throw new InvalidDataException("certificate table offset beyond EOF");

        // COFF symbol table: its pointer/count fields are skipped and the table itself
        // is excluded from the end of the hashed region (rare on modern PE images).
        int skip1Start = 0, skip1Len = 0;
        if (BitConverter.ToInt32(Raw, CoffSymbolPtr) != 0)
        {
            skip1Start = CoffSymbolPtr;
            skip1Len = 8;
            int symPtr = BitConverter.ToInt32(Raw, CoffSymbolPtr);
            if (symPtr > 0 && symPtr < end) end = symPtr;
        }

        using var ms = new MemoryStream(Raw.Length);
        ms.Write(Raw, 0, ChecksumOffset);
        ms.Write(Raw, ChecksumOffset + 4, certDirEntry - (ChecksumOffset + 4));
        if (skip1Len > 0)
        {
            ms.Write(Raw, certDirEntry, skip1Start - certDirEntry);
            ms.Write(Raw, skip1Start + skip1Len, end - (skip1Start + skip1Len));
        }
        else
        {
            ms.Write(Raw, certDirEntry + 8, end - (certDirEntry + 8));
        }

        return alg.Name == "SHA1"
            ? System.Security.Cryptography.SHA1.HashData(ms.GetBuffer().AsSpan(0, (int)ms.Length))
            : System.Security.Cryptography.SHA256.HashData(ms.GetBuffer().AsSpan(0, (int)ms.Length));
    }

    /// <summary>Strips the certificate table: truncates the file and zeroes the directory entry.</summary>
    public void StripSignature()
    {
        var (certOff, _) = SecurityDir;
        if (certOff == 0) return;
        if (certOff > Raw.Length) throw new InvalidDataException("certificate table offset beyond EOF");
        Array.Resize(ref Raw, certOff);
        Array.Clear(Raw, DataDirOffset + DirSecurityIndex * 8, 8);
    }

    /// <summary>Appends one WIN_CERTIFICATE (PKCS_SIGNED_DATA) entry and updates the SECURITY directory.</summary>
    public void AppendCertificate(byte[] signedDataDer)
    {
        StripSignature();
        int entryLen = 8 + signedDataDer.Length;
        int pad = (8 - (Raw.Length & 7)) & 7;
        int offset = Raw.Length + pad;

        Array.Resize(ref Raw, offset + entryLen);
        if (pad > 0) Array.Clear(Raw, offset - pad, pad);
        BitConverter.GetBytes((uint)entryLen).CopyTo(Raw, offset);
        BitConverter.GetBytes((ushort)0x0200).CopyTo(Raw, offset + 4); // WIN_CERT_REVISION_2_0
        BitConverter.GetBytes((ushort)0x0002).CopyTo(Raw, offset + 6); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        signedDataDer.CopyTo(Raw, offset + 8);

        BitConverter.GetBytes((uint)offset).CopyTo(Raw, DataDirOffset + DirSecurityIndex * 8);
        BitConverter.GetBytes((uint)entryLen).CopyTo(Raw, DataDirOffset + DirSecurityIndex * 8 + 4);

        RecomputeChecksum();
    }

    /// <summary>Returns the concatenated raw PKCS#7 blobs from the certificate table.</summary>
    public List<byte[]> ReadCertificates()
    {
        var result = new List<byte[]>();
        var (off, size) = SecurityDir;
        if (off == 0 || size == 0) return result;
        int p = off, end = Math.Min(off + size, Raw.Length);
        while (p + 8 <= end)
        {
            uint len = BitConverter.ToUInt32(Raw, p);
            if (len < 8 || p + len > end) break;
            ushort type = BitConverter.ToUInt16(Raw, p + 6);
            if (type == 0x0002)
                result.Add(Raw[(p + 8)..(p + (int)len)]);
            p += (int)((len + 7) & ~7u); // entries are 8-byte aligned
        }
        return result;
    }

    /// <summary>Classic PE checksum: sum of 16-bit words with carry folding, plus file length.</summary>
    public void RecomputeChecksum()
    {
        uint old = BitConverter.ToUInt32(Raw, ChecksumOffset);
        Array.Clear(Raw, ChecksumOffset, 4);
        ulong sum = 0;
        int i = 0;
        for (; i + 1 < Raw.Length; i += 2) sum += (uint)(Raw[i] | (Raw[i + 1] << 8));
        if (i < Raw.Length) sum += Raw[i];
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        uint cks = (uint)(sum + (ulong)Raw.Length);
        BitConverter.GetBytes(cks).CopyTo(Raw, ChecksumOffset);
        _ = old;
    }

    public void Save(string path) => File.WriteAllBytes(path, Raw);
}
