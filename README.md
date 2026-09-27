# spcsign

A self-contained Authenticode signer for Windows PE files (EXE / DLL / SYS).

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
