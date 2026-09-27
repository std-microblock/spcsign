# spcsign

A self-contained Authenticode signer for Windows PE files (EXE / DLL / SYS).
It builds the PKCS#7 `SignedData` structure by hand — DER encoding, message
digest, RSA signature, certificate table patching — with no dependency on
`signtool.exe`, the Windows SDK, or any external timestamp server.

```
spcsign sign --cert MYCERT --chain ca-intermediate.cer --chain ca-cross.cer driver.sys
signtool verify /kp driver.sys      → Successfully verified
```

## Why

The usual alternatives are heavyweight or fragile:

- `signtool.exe` requires the Windows SDK and an RFC 3161 timestamp server for
  non-expiring signatures.
- Forking / hooking a signing tool (API hooking of `mssign32`, faking system
  time) is brittle and touches process internals.

spcsign is a single .NET console project: given a code-signing certificate and
a certificate chain, it produces a byte-accurate Authenticode signature that
`wintrust` (and therefore `signtool verify /kp`, `/pa`, and driver loading)
accepts. Timestamps come from a local TSA that the tool itself generates.

## Authenticode details implemented here

These are the parts that are easy to get wrong; each was reverse-engineered
against signatures known to pass kernel-policy verification:

- **Image hash — the skip model.** The digest covers the file linearly but
  *skips* (not zeroes) the PE checksum field, the certificate-table data
  directory entry, and everything from the certificate table to EOF. The COFF
  symbol-table pointer/count and the symbol table itself are skipped too.
- **Flat eContent.** Microsoft's `encapContentInfo` wraps the
  `SpcIndirectDataContent` DER directly in an `[0] EXPLICIT` shell — there is
  no OCTET STRING layer.
- **messageDigest attribute** = hash of the *value part* of the
  `SpcIndirectDataContent` SEQUENCE (its content bytes, without the TLV
  header).
- **Legacy PKCS#9 countersignature** (`1.2.840.113549.1.9.6`): the TSA
  `SignerInfo` carries `contentType=id-data`, `signingTime` (UTCTime) and
  `messageDigest = SHA-1(main signature)`, written in that non-DER-sorted
  order, and is embedded as the unsigned attribute of the main signer. The
  RFC 3161 `TSTInfo` format is *not* what `wintrust` looks for on the legacy
  code paths.
- **Empty opusInfo.** The `spcSpOpusInfo` attribute must carry an empty
  SEQUENCE — a populated one (program name / URL) is rejected by the driver
  verification path.
- **Attribute order** matches legacy `mssign32` output (`opusInfo`,
  `contentType`, `statementType`, `messageDigest`).
- **Message certificate set** must include the signer chain *and* the TSA
  certificates, so the verifier can resolve the countersigner from the PKCS#7
  itself.

## Usage

```
spcsign probe    <signedFile> [--out DIR]      extract SPC templates from a known-good signature
spcsign init-tsa [--out DIR] [--name CN] [--password P]
spcsign trust-tsa [--dir DIR]                  install the TSA root into CurrentUser\Root
spcsign sign     [options] <file>              strip, build PKCS#7, patch PE
spcsign strip    <file>                        remove the certificate table
spcsign hash     [--sha1] <file>               image hash vs embedded digest self-check
spcsign check    <file>                        .NET SignedCms structural verification
spcsign export   <file> [--out DIR]            dump embedded certificates
spcsign dump     <file>                        ASN.1 dump of the embedded PKCS#7
```

`sign` options:

| Option | Meaning |
|---|---|
| `--cert THUMB\|SUBSTR` | pick a certificate from `CurrentUser\My` (default: first with a code-signing EKU) |
| `--pfx F --password P` | load the signer from a PFX instead of the store |
| `--sha1` | SHA-1 digest (the legacy driver-signing default) |
| `--chain CER` | extra chain certificate to embed (repeatable) |
| `--tsa-pfx F --tsa-password P` | local TSA leaf PFX (from `init-tsa`) |
| `--tsa-root CER` | TSA root to embed in the message |
| `--tsa-time T` | signing time to assert (default: now; must fall inside the signer validity) |
| `--no-tsa` | omit the countersignature |
| `--templates DIR` | SPC template dir (default: `<repo>/spc-templates`) |

## Workflow

1. Generate the local TSA once (root + leaf with the timeStamping EKU) and
   trust its root:

   ```
   spcsign init-tsa
   spcsign trust-tsa
   ```

   The generated material lands in `tsa/` (git-ignored; it contains private
   keys). `trust-tsa` installs the root into `CurrentUser\Root`. Any machine
   that should verify the timestamps needs the same root — for a fleet, deploy
   it via GPO / `certutil -addstore Root tsa-root.cer` as administrator.

2. Sign:

   ```
   spcsign sign --sha1 --cert MYCERT \
       --chain intermediate.cer --chain cross.cer \
       --tsa-time 2010-06-01T00:00:00Z target.sys
   ```

   The signer certificate must be in `CurrentUser\My` with its private key, or
   supplied as a PFX. `--chain` certificates (intermediate / cross-signed CAs)
   get embedded into the message so verification can build the full chain.

3. Verify with the real thing:

   ```
   signtool verify /kp /v target.sys
   ```

## SPC templates

`spc-templates/spc_data.bin` (SpcPeImageData) and `spc_attrs.bin`
(statementType / opusInfo) are the two verbatim DER blobs embedded into every
signature. The shipped defaults are the generic ones; `spcsign probe` extracts
fresh templates from any existing signature if you need different ones.

## Requirements & limitations

- .NET 10 SDK to build; runs on Windows (the PE writer and store access are
  Windows-only).
- RSA keys only; SHA-1 or SHA-256 digests; PE32 and PE32+; single signature
  per file.
- The countersignature uses the legacy PKCS#9 form (what `signtool timestamp
   /t` produces), not RFC 3161.

## License

MIT — see [LICENSE](LICENSE).
