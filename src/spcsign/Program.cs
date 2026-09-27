using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SpcSign;

// spcsign — a self-contained Authenticode PKCS#7 producer.
//
//   spcsign probe    <signedFile> [--out DIR]      extract SPC templates from a known-good signature
//   spcsign init-tsa [--out DIR] [--name CN] [--password P]
//   spcsign trust-tsa [--dir DIR]                  install the TSA root into CurrentUser\Root
//   spcsign sign     [options] <file>              strip, build PKCS#7, patch PE
//   spcsign strip    <file>
//   spcsign dump     <file>                        ASN.1 dump of the embedded PKCS#7
//   spcsign hash     [--sha1] <file>               image hash vs embedded digest self-check
//   spcsign check    <file>                        .NET SignedCms structural verification
//   spcsign export   <file> [--out DIR]            dump embedded certificates
//
// sign options:
//   --cert THUMB|SUBSTR     pick certificate from CurrentUser\My (default: first with a code-signing EKU)
//   --pfx F --password P    load signer from a PFX instead of the store
//   --sha1                  SHA-1 digest (legacy driver-signing default)
//   --chain CER             additional chain certificates to embed (repeatable)
//   --tsa-pfx F [--tsa-password P]   local TSA leaf PFX (from init-tsa)
//   --tsa-root CER                  TSA root to embed in the message (optional)
//   --tsa-time 2010-06-01T00:00:00Z signing time to assert (default: now; must fall inside the signer validity)
//   --no-tsa                omit the countersignature
//   --templates DIR         SPC template dir (default: <repo>/spc-templates)

int Exit(string msg) { Console.Error.WriteLine("error: " + msg); return 1; }

if (args.Length == 0) { PrintUsage(); return 2; }
try
{
    switch (args[0])
    {
        case "probe": return CmdProbe(args[1..]);
        case "init-tsa": return CmdInitTsa(args[1..]);
        case "trust-tsa": return CmdTrustTsa(args[1..]);
        case "sign": return CmdSign(args[1..]);
        case "hash": return CmdHash(args[1..]);
        case "check": return CmdCheck(args[1..]);
        case "export": return CmdExport(args[1..]);
        case "strip": return CmdStrip(args[1..]);
        case "dump": return CmdDump(args[1..]);
        default: PrintUsage(); return 2;
    }
}
catch (Exception ex)
{
    return Exit(ex.Message);
}

static void PrintUsage()
{
    Console.WriteLine("""
        spcsign probe    <signedFile> [--out DIR]
        spcsign init-tsa [--out DIR] [--name CN] [--password P]
        spcsign trust-tsa [--dir DIR]
        spcsign sign     [--cert THUMB|SUBSTR|--pfx F --password P] [--chain CER ...]
                         [--sha1] (SHA-1 digest, the legacy driver-signing default)
                         [--tsa-pfx F --tsa-password P --tsa-root CER --tsa-time T|--no-tsa]
                         [--templates DIR] <file>
        spcsign strip    <file>
        spcsign hash     [--sha1] <file>
        spcsign check    <file>
        spcsign export   <file> [--out DIR]
        spcsign dump     <file>
        """);
}

static Dictionary<string, List<string>> ParseOpts(string[] args, out List<string> positional)
{
    var opts = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
    positional = [];
    for (int i = 0; i < args.Length; i++)
    {
        string a = args[i];
        if (a.StartsWith("--", StringComparison.Ordinal))
        {
            string key = a[2..];
            if (key is "no-tsa" or "sha1") { opts[key] = ["true"]; continue; }
            if (i + 1 >= args.Length) throw new ArgumentException($"option --{key} needs a value");
            string value = args[++i];
            if (!opts.TryGetValue(key, out var list)) opts[key] = list = [];
            list.Add(value);
        }
        else positional.Add(a);
    }
    return opts;
}

static string? Opt(Dictionary<string, List<string>> opts, string key)
    => opts.TryGetValue(key, out var l) && l.Count > 0 ? l[0] : null;

static string RepoRelative(string dir)
{
    // running from <repo>/src/spcsign/bin/... : walk up until the repo root
    // (the directory containing spc-templates/ or tsa/) is found.
    for (string? d = AppContext.BaseDirectory; d is not null; d = Path.GetDirectoryName(d))
    {
        if (Directory.Exists(Path.Combine(d, "spc-templates")) || Directory.Exists(Path.Combine(d, "tsa")))
            return Path.Combine(d, dir);
    }
    return Path.Combine(AppContext.BaseDirectory, dir);
}

// ---------------------------------------------------------------- probe

static int CmdProbe(string[] args)
{
    var opts = ParseOpts(args, out var pos);
    if (pos.Count != 1) throw new ArgumentException("probe needs exactly one signed file");
    var pe = new PeImage(File.ReadAllBytes(pos[0]));
    var certs = pe.ReadCertificates();
    if (certs.Count == 0) throw new InvalidOperationException("no PKCS#7 certificate table entry found");

    string outDir = Opt(opts, "out") ?? RepoRelative("spc-templates");
    Directory.CreateDirectory(outDir);

    // Walk: ContentInfo(signedData) -> SignedData -> encapContentInfo -> eContent -> SpcIndirectDataContent
    byte[] sd = certs[0];
    var r = new AsnReader(sd, AsnEncodingRules.DER);
    var ci = r.ReadSequence();
    string contentType = ci.ReadObjectIdentifier();
    if (contentType != Oids.SignedData) throw new InvalidOperationException($"not a signedData: {contentType}");
    var explicitSd = ci.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
    var signedData = explicitSd.ReadSequence();
    signedData.ReadInteger();          // version
    signedData.ReadSetOf();            // digestAlgorithms
    var encap = signedData.ReadSequence();
    string eContentType = encap.ReadObjectIdentifier();
    if (eContentType != Oids.SpcIndirectData) throw new InvalidOperationException($"unexpected eContentType {eContentType}");
    // Microsoft's Authenticode flavor: the [0] EXPLICIT shell wraps the SpcIndirectDataContent DER directly
    // (no OCTET STRING middle layer). Read the raw TLV so both flavors work.
    var eContent = encap.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
    byte[] spcIndirect = eContent.ReadEncodedValue().ToArray();

    var spc = new AsnReader(spcIndirect, AsnEncodingRules.DER);
    var spcSeq = spc.ReadSequence();
    byte[] dataDer = spcSeq.ReadEncodedValue().ToArray(); // `data` field, saved verbatim as the template
    spcSeq.ReadEncodedValue();                       // digestInfo — recomputed per file, not templated
    File.WriteAllBytes(Path.Combine(outDir, "spc_data.bin"), dataDer);

    // signerInfos[0].signedAttrs: keep the SPC-specific attributes verbatim.
    if (signedData.HasData)
    {
        _ = signedData.ReadSetOf(true, new Asn1Tag(TagClass.ContextSpecific, 0)); // certificates [0]
    }
    byte[] attrsDer = [];
    if (signedData.HasData)
    {
        var signerInfos = signedData.ReadSetOf();
        var signer = signerInfos.ReadSequence();
        signer.ReadInteger();          // version
        signer.ReadSequence();         // sid
        signer.ReadSequence();         // digestAlgorithm
        if (signer.HasData)
        {
            var attrs = signer.ReadSetOf(true, new Asn1Tag(TagClass.ContextSpecific, 0));
            using var ms = new MemoryStream();
            while (attrs.HasData)
            {
                byte[] attr = attrs.ReadEncodedValue().ToArray();
                var ar = new AsnReader(attr, AsnEncodingRules.DER);
                var aseq = ar.ReadSequence();
                string oid = aseq.ReadObjectIdentifier();
                if (oid == Oids.SpcStatementType || oid == Oids.SpcSpOpusInfo)
                    ms.Write(attr);
            }
            attrsDer = ms.ToArray();
        }
    }
    File.WriteAllBytes(Path.Combine(outDir, "spc_attrs.bin"), attrsDer);

    Console.WriteLine($"templates written to {outDir}");
    Console.WriteLine($"  spc_data.bin  {dataDer.Length} bytes (SpcAttributeTypeAndOptionalValue)");
    Console.WriteLine($"  spc_attrs.bin {attrsDer.Length} bytes (statementType/opusInfo)");
    return 0;
}

// ---------------------------------------------------------------- init-tsa

static int CmdInitTsa(string[] args)
{
    var opts = ParseOpts(args, out _);
    string outDir = Opt(opts, "out") ?? RepoRelative("tsa");
    string name = Opt(opts, "name") ?? "spcsign Local TSA";
    string password = Opt(opts, "password") ?? "spcsign";
    Directory.CreateDirectory(outDir);

    var (rootPfx, rootCer, leafPfx, leafCer) = TsaGen.Generate(name, password);
    string rootPfxPath = Path.Combine(outDir, "tsa-root.pfx");
    string rootCerPath = Path.Combine(outDir, "tsa-root.cer");
    string leafPfxPath = Path.Combine(outDir, "tsa-leaf.pfx");
    string leafCerPath = Path.Combine(outDir, "tsa-leaf.cer");
    File.WriteAllBytes(rootPfxPath, rootPfx);
    File.WriteAllBytes(rootCerPath, rootCer);
    File.WriteAllBytes(leafPfxPath, leafPfx);
    File.WriteAllBytes(leafCerPath, leafCer);

    Console.WriteLine($"TSA material written to {outDir}");
    Console.WriteLine($"  {Path.GetFileName(rootCerPath)}  (install into CurrentUser\\Root: spcsign trust-tsa)");
    Console.WriteLine($"  {Path.GetFileName(leafPfxPath)} (pass to `sign --tsa-pfx`, password '{password}')");
    return 0;
}

// ---------------------------------------------------------------- trust-tsa

static int CmdTrustTsa(string[] args)
{
    var opts = ParseOpts(args, out _);
    string dir = Opt(opts, "dir") ?? RepoRelative("tsa");
    string cerPath = Path.Combine(dir, "tsa-root.cer");
    if (!File.Exists(cerPath)) throw new FileNotFoundException($"run init-tsa first ({cerPath} missing)");
    using var root = X509CertificateLoader.LoadCertificateFromFile(cerPath);
    using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    store.Add(root);
    Console.WriteLine($"installed '{root.Subject}' into CurrentUser\\Root");
    return 0;
}

// ---------------------------------------------------------------- sign

static int CmdSign(string[] args)
{
    var opts = ParseOpts(args, out var pos);
    if (pos.Count != 1) throw new ArgumentException("sign needs exactly one file");
    string file = pos[0];

    string templateDir = Opt(opts, "templates") ?? RepoRelative("spc-templates");
    var tpl = SpcTemplates.Load(templateDir);

    // signer certificate + key
    X509Certificate2 cert;
    RSA key;
    string? pfx = Opt(opts, "pfx");
    if (pfx is not null)
    {
        (cert, key) = CertLoader.FromPfx(pfx, Opt(opts, "password") ?? "");
    }
    else
    {
        string? sel = Opt(opts, "cert");
        if (sel is not null) (cert, key) = CertLoader.FromStore(sel);
        else
        {
            // default: first code-signing cert in the store
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2? pick = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(c =>
                c.HasPrivateKey && HasEku(c, "1.3.6.1.5.5.7.3.3"));
            if (pick is null) throw new InvalidOperationException("no code-signing certificate in CurrentUser\\My; pass --cert or --pfx");
            (cert, key) = (pick, pick.GetRSAPrivateKey() ?? throw new InvalidOperationException("key is not RSA"));
        }
    }
    byte[] signerDer = cert.Export(X509ContentType.Cert);

    // extra chain certificates
    var chain = new List<byte[]>();
    if (opts.TryGetValue("chain", out var chainFiles))
        foreach (string f in chainFiles) chain.Add(CertLoader.LoadCer(f));

    // timestamp (deferred: the TST imprints the signer signature, built in two passes below)
    bool wantTsa = !opts.ContainsKey("no-tsa");
    string? tsaPfx = Opt(opts, "tsa-pfx") ?? (wantTsa ? Path.Combine(RepoRelative("tsa"), "tsa-leaf.pfx") : null);
    string tsaPassword = Opt(opts, "tsa-password") ?? "spcsign";
    string? tsaRoot = Opt(opts, "tsa-root");
    if (wantTsa && (tsaPfx is null || !File.Exists(tsaPfx)))
        throw new FileNotFoundException($"TSA pfx not found ({tsaPfx}); run init-tsa or pass --no-tsa");

    // image hash over the stripped image, then the signed PKCS#7
    bool sha1 = opts.ContainsKey("sha1");
    var pe = new PeImage(File.ReadAllBytes(file));
    pe.StripSignature();
    byte[] imageHash = pe.ComputeImageHash(sha1 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256);
    byte[] spcDer = Authenticode.BuildSpcIndirectData(tpl.DataDer, imageHash, sha1);

    byte[] pkcs7;
    DateTimeOffset genTime = default;
    if (!wantTsa)
    {
        pkcs7 = Authenticode.BuildSignedPkcs7(signerDer, key, spcDer, imageHash, chain, tpl, null, sha1);
    }
    else
    {
        // pass 1: sign without the token; pass 2: imprint that signature into the TST, re-sign with it attached.
        byte[] bareSig = ExtractSignature(Authenticode.BuildSignedPkcs7(signerDer, key, spcDer, imageHash, chain, tpl, null, sha1));
        string? tsaTime = Opt(opts, "tsa-time");
        genTime = tsaTime is null
            ? DateTimeOffset.UtcNow
            : DateTimeOffset.Parse(tsaTime, null, System.Globalization.DateTimeStyles.AssumeUniversal);
        var tsaCerts = CertLoader.AllCertsFromPfx(tsaPfx!, tsaPassword);
        byte[] tsaLeaf = tsaCerts.First(HasTimestampingEku);
        var tsaExtra = tsaCerts.Where(c => !c.SequenceEqual(tsaLeaf)).ToList();
        if (tsaRoot is not null) tsaExtra.Add(CertLoader.LoadCer(tsaRoot));
        // the message certificate set must include the TSA certificates: the verifier
        // resolves the countersigner from the same PKCS#7 certificate collection.
        chain.Add(tsaLeaf);
        string defaultTsaRoot = Path.Combine(RepoRelative("tsa"), "tsa-root.cer");
        chain.Add(tsaRoot is not null ? CertLoader.LoadCer(tsaRoot)
             : File.Exists(defaultTsaRoot) ? CertLoader.LoadCer(defaultTsaRoot) : tsaExtra.FirstOrDefault() ?? tsaLeaf);
        (_, RSA tsaKey) = CertLoader.FromPfx(tsaPfx!, tsaPassword);
        byte[] countersign = Timestamp.BuildCountersign(bareSig, tsaKey, tsaLeaf, genTime);
        pkcs7 = Authenticode.BuildSignedPkcs7(signerDer, key, spcDer, imageHash, chain, tpl, countersign, sha1);
    }

    pe.AppendCertificate(pkcs7);
    pe.Save(file);
    Console.WriteLine($"signed: {file}");
    Console.WriteLine($"  signer: {cert.Subject}");
    Console.WriteLine($"  digest: {(sha1 ? "SHA-1" : "SHA-256")}, PKCS#7 {pkcs7.Length} bytes{(wantTsa ? $", countersignature @ {genTime:yyyy-MM-ddTHH:mm:ssZ}" : "")}");
    return 0;
}

static bool HasEku(X509Certificate2 c, string oidValue) =>
    c.Extensions.OfType<X509EnhancedKeyUsageExtension>()
        .Any(e => e.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == oidValue));

static bool HasTimestampingEku(byte[] certDer)
{
    using X509Certificate2 c = X509CertificateLoader.LoadCertificate(certDer);
    return HasEku(c, "1.3.6.1.5.5.7.3.8");
}

/// <summary>Pulls the signature OCTET STRING out of a bare SignerInfo (for the TST imprint).</summary>
static byte[] ExtractSignature(byte[] pkcs7Der)
{
    var r = new AsnReader(pkcs7Der, AsnEncodingRules.DER);
    var ci = r.ReadSequence();
    ci.ReadObjectIdentifier();
    var explicitSd = ci.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
    var signedData = explicitSd.ReadSequence();
    signedData.ReadInteger();
    signedData.ReadSetOf();
    signedData.ReadSequence();  // encapContentInfo
    signedData.ReadSetOf(true, new Asn1Tag(TagClass.ContextSpecific, 0)); // certificates
    var signerInfos = signedData.ReadSetOf();
    var signer = signerInfos.ReadSequence();
    signer.ReadInteger();
    signer.ReadSequence();      // sid
    signer.ReadSequence();      // digestAlgorithm
    signer.ReadSetOf(true, new Asn1Tag(TagClass.ContextSpecific, 0)); // signedAttrs
    signer.ReadSequence();      // signatureAlgorithm
    return signer.ReadOctetString().ToArray();
}

// ---------------------------------------------------------------- hash

static int CmdHash(string[] args)
{
    var opts = ParseOpts(args, out var pos);
    if (pos.Count != 1) throw new ArgumentException("hash needs exactly one file");
    bool sha1 = opts.ContainsKey("sha1");
    var pe = new PeImage(File.ReadAllBytes(pos[0]));
    byte[] h = pe.ComputeImageHash(sha1 ? System.Security.Cryptography.HashAlgorithmName.SHA1 : System.Security.Cryptography.HashAlgorithmName.SHA256);
    Console.WriteLine((sha1 ? "image hash (SHA-1):   " : "image hash (SHA-256): ") + Convert.ToHexString(h));
    foreach (byte[] c in pe.ReadCertificates())
    {
        // print the digest embedded in the first PKCS#7 for comparison
        var r = new AsnReader(c, AsnEncodingRules.DER);
        var ci = r.ReadSequence();
        ci.ReadObjectIdentifier();
        var sd = ci.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
        sd.ReadInteger();
        sd.ReadSetOf();
        var encap = sd.ReadSequence();
        string ct = encap.ReadObjectIdentifier();
        var content = encap.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        byte[] spc = content.ReadEncodedValue().ToArray();
        var spcSeq = new AsnReader(spc, AsnEncodingRules.DER).ReadSequence();
        spcSeq.ReadEncodedValue(); // data
        var digestInfo = spcSeq.ReadSequence();
        digestInfo.ReadSequence(); // alg
        byte[] digest = digestInfo.ReadOctetString();
        Console.WriteLine("embedded digest:     " + Convert.ToHexString(digest));
        Console.WriteLine(ct == Oids.SpcIndirectData ? "match: " + digest.SequenceEqual(h) : $"(content type {ct})");    }
    return 0;
}

// ---------------------------------------------------------------- check

static int CmdCheck(string[] args)
{
    if (args.Length != 1) throw new ArgumentException("check needs exactly one file");
    var pe = new PeImage(File.ReadAllBytes(args[0]));
    var certs = pe.ReadCertificates();
    if (certs.Count == 0) throw new InvalidOperationException("no embedded PKCS#7");

    var cms = new System.Security.Cryptography.Pkcs.SignedCms();
    cms.Decode(certs[0]);
    Console.WriteLine("CMS decode: OK");
    foreach (var si in cms.SignerInfos)
    {
        Console.WriteLine($"signer: {si.Certificate?.Subject}");
        Console.WriteLine($"  digest alg: {si.DigestAlgorithm.Value}");
        foreach (var attr in si.SignedAttributes)
            Console.WriteLine($"  signed attr:   {attr.Oid.Value} {attr.Oid.FriendlyName} ({attr.Values.Count} value(s))");
        foreach (var attr in si.UnsignedAttributes)
            Console.WriteLine($"  unsigned attr: {attr.Oid.Value} {attr.Oid.FriendlyName} ({attr.Values.Count} value(s))");
        foreach (var cs in si.CounterSignerInfos)
            Console.WriteLine($"  countersigner: {cs.Certificate?.Subject}");
    }
    try
    {
        cms.CheckSignature(true); // verify signatures only, ignore certificate chains
        Console.WriteLine("CheckSignature(onlySigned): OK — CMS structure and signatures are cryptographically valid");
        return 0;
    }
    catch (Exception ex)
    {
        Console.WriteLine("CheckSignature FAILED: " + ex.Message);
        return 1;
    }
}

// ---------------------------------------------------------------- export

static int CmdExport(string[] args)
{
    var opts = ParseOpts(args, out var pos);
    if (pos.Count != 1) throw new ArgumentException("export needs exactly one file");
    string outDir = Opt(opts, "out") ?? Path.Combine(".cache", "exported-certs");
    Directory.CreateDirectory(outDir);
    var pe = new PeImage(File.ReadAllBytes(pos[0]));
    var certs = pe.ReadCertificates();
    if (certs.Count == 0) throw new InvalidOperationException("no embedded PKCS#7");
    var cms = new System.Security.Cryptography.Pkcs.SignedCms();
    cms.Decode(certs[0]);
    int n = 0;
    foreach (var c in cms.Certificates)
    {
        n++;
        string name = $"cert{n:D2}-{c.Thumbprint[..8]}.cer";
        string p = Path.Combine(outDir, name);
        File.WriteAllBytes(p, c.Export(X509ContentType.Cert));
        Console.WriteLine($"{name}  {c.Subject}");
    }
    Console.WriteLine($"{n} certificate(s) exported to {outDir}");
    return 0;
}

// ---------------------------------------------------------------- strip / dump

static int CmdStrip(string[] args)
{
    if (args.Length != 1) throw new ArgumentException("strip needs exactly one file");
    var pe = new PeImage(File.ReadAllBytes(args[0]));
    var (off, size) = pe.SecurityDir;
    if (off == 0) { Console.WriteLine("not signed"); return 0; }
    pe.StripSignature();
    pe.Save(args[0]);
    Console.WriteLine($"stripped {size} bytes of certificate table from {args[0]}");
    return 0;
}

static int CmdDump(string[] args)
{
    if (args.Length != 1) throw new ArgumentException("dump needs exactly one file");
    var pe = new PeImage(File.ReadAllBytes(args[0]));
    var certs = pe.ReadCertificates();
    Console.WriteLine($"PE: {(pe.IsPe32Plus ? "PE32+" : "PE32")}, sections {pe.NumberOfSections}, file {pe.Raw.Length} bytes");
    var (off, size) = pe.SecurityDir;
    Console.WriteLine($"certificate table: offset 0x{off:X}, size {size}, entries {certs.Count}");
    foreach (byte[] c in certs)
    {
        Console.WriteLine($"-- PKCS#7 ({c.Length} bytes) --");
        var r = new AsnReader(c, AsnEncodingRules.DER);
        DerUtil.Dump(r, "  ", Console.Out);
    }
    return certs.Count > 0 ? 0 : 1;
}
