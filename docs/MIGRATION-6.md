# Migrating to PortEx 6

PortEx 6 replaces the signature scanner. The new scanner is faster, matches
patterns at locations like the entry point, the overlay, resources, sections or
.NET streams, and reads all bundled signatures from one database format.

All breaking changes of PortEx 6 are in signature scanning. If your code does
not use signatures, upgrading only needs the new version number. Otherwise,
this guide shows the replacement for every removed class and method. The
signature format itself is described in [SIGNATURES.md](SIGNATURES.md).

PortEx 6 also parses and verifies Authenticode signatures, see
[Authenticode signatures](#authenticode-signatures). This adds anomalies and a
report section for signed files.

* [Quick reference](#quick-reference)
* [Dependency](#dependency)
* [Signatures of a PEData](#signatures-of-a-pedata)
* [MatchedSignature becomes SignatureMatch](#matchedsignature-becomes-signaturematch)
* [Signature names](#signature-names)
* [Scanning without PEData](#scanning-without-pedata)
* [Your own PEiD databases](#your-own-peid-databases)
* [Signatures defined in code](#signatures-defined-in-code)
* [File types](#file-types)
* [Java wrappers](#java-wrappers)
* [Reports and PortexAnalyzer output](#reports-and-portexanalyzer-output)
* [Results that change](#results-that-change)
* [Removed classes and methods](#removed-classes-and-methods)
* [Visualizer and structure map](#visualizer-and-structure-map)
* [Authenticode signatures](#authenticode-signatures)
* [Scala](#scala)

## Quick reference

| PortEx 5 | PortEx 6 |
|---|---|
| `PEData.getSignatures()` | `PEData.getSignatureMatches()` |
| `PEData.getPEIDSignatures()` | `PEData.getSignatureMatches(LocationKind.ENTRY_POINT, LocationKind.SECTION)` |
| `PEData.getOverlaySignatures()` | `PEData.getSignatureMatches(LocationKind.OVERLAY)` |
| `PEData.getResourceSignatures()` | `PEData.getSignatureMatches(LocationKind.RESOURCE)` |
| `PEData.getMSDOSSignatures()` | `PEData.getSignatureMatches(LocationKind.MSDOS_HEADER)` |
| `MatchedSignature` | `SignatureMatch` |
| `SignatureScanner.newInstance()` | `DefaultSignatures.getPEScanner()` |
| `SignatureScanner.loadSignatures(file)` | `PEiDImporter.load(file)` |
| `SignatureScanner.loadOverlaySigs()` | `DefaultSignatures.getInstallers()` |
| `new SignatureScanner(signatures).scanAll(file, epOnly)` | `new SignatureScanner(db).scan(PELoader.loadPE(file))` |
| `new Signature(...)`, `Signature.apply(...)` | `SignatureDatabase.parse(text, name)` |
| `FileTypeScanner(file).scanAt(0)` | `FileTypeScanner.scan(file)` |
| `Jar2ExeScanner.scan()` returns `MatchedSignature` | returns `SignatureMatch` |
| `ReportCreator.peidReport()` | `ReportCreator.signatureReport()` |
| signature names like `[UPX v0.89.6]` | `UPX v0.89.6`, without the outer brackets |

## Dependency

Maven:

```xml
<dependency>
   <groupId>io.github.struppigel</groupId>
   <artifactId>portex_2.12</artifactId>
   <version>6.0.0</version>
</dependency>
```

sbt:

```scala
libraryDependencies += "io.github.struppigel" % "portex_2.12" % "6.0.0"
```

## Signatures of a PEData

The five signature getters of `PEData` are replaced by one method that takes
the locations you are interested in. Without arguments it returns the matches
in all locations except the whole file, see [below](#results-that-change).

Before:

```java
PEData data = PELoader.loadPE(file);
for (MatchedSignature sig : data.getPEIDSignatures()) {
    System.out.println(sig.getName() + " at 0x" + Long.toHexString(sig.getAddress()));
}
List<MatchedSignature> overlay = data.getOverlaySignatures();
```

After:

```java
PEData data = PELoader.loadPE(file);
for (SignatureMatch match : data.getSignatureMatches(LocationKind.ENTRY_POINT, LocationKind.SECTION)) {
    System.out.println(match.getName() + " at 0x" + Long.toHexString(match.getOffset()));
}
List<SignatureMatch> overlay = data.getSignatureMatches(LocationKind.OVERLAY);
```

Matches are ordered by location kind, region, offset and database order. Each
location kind is scanned once per `PEData` and cached, as before.

Resource signatures were matched to resources by comparing the address with
the start of the resource. Use the start of the matched region instead:

```java
long start = resource.rawBytesLocation().from();
for (SignatureMatch match : data.getSignatureMatches(LocationKind.RESOURCE)) {
    if (match.getRegionStart() == start) {
        System.out.println(match.getName());
    }
}
```

## MatchedSignature becomes SignatureMatch

| `MatchedSignature` | `SignatureMatch` |
|---|---|
| `getName()` | `getName()`, the name has no outer brackets anymore |
| `getAddress()` | `getOffset()` is the file offset of the match. `getRegionStart()` is the start of the matched resource, overlay or section |
| `getMatchedBytes()` | `getLength()`, see below |
| `getPattern()` | `getSignature().getClauses().get(0).getPattern().getSource()` |
| `isEpOnly()` | `getLocationKind() == LocationKind.ENTRY_POINT` |
| `toString()` | `toString()` has a new format: `NSIS at overlay+0x4 (file offset 0x21604, 15 bytes)` |

New information:

* `getLocationKind()` and `getLocationLabel()` tell where the signature matched,
  e.g. `RESOURCE` and `resource(RT_RCDATA/101/1033)`.
* `getRelativeOffset()` is the offset within the region.
* `getSignature()` gives access to the metadata of the signature, e.g.
  `getTypes()` (`packer`, `installer`, ...), `getVersion()` and `getDescription()`.
* `getClauseMatches()` lists the match of every pattern of signatures with
  several patterns.

`getMatchedBytes()` counted the bytes of the pattern that are not wildcards.
`getLength()` is the length of the match including wildcards. For patterns
without wildcards both are the same.

## Signature names

Names of signatures from PEiD style databases kept their brackets in PortEx 5.
PortEx 6 removes the outer brackets, everything else of the name is unchanged:

| PortEx 5 | PortEx 6 |
|---|---|
| `[NSIS]` | `NSIS` |
| `[Launch4j]` | `Launch4j` |
| `[[MSLRH] v0.32a -> emadicius]` | `[MSLRH] v0.32a -> emadicius` |
| `MS-DOS or Portable Executable` (file types had no brackets) | `MS-DOS or Portable Executable` |

If your code compares names, remove the brackets. Matching with `contains`
keeps working. This also affects texts that contain names: the anomaly
`Overlay has signature [NSIS]` is now `Overlay has signature NSIS`, and the
reverse engineering hint `Matches signature [MPRESS V0.77b -> MATCODE Software ...]`
is now `Matches signature MPRESS V0.77b -> MATCODE Software ...`.

The Inno Setup check of the MS-DOS header and the PyInstaller string check
were hard coded in PortEx 5. They are signatures now, named `InnoSetup`
(location `MSDOS_HEADER`) and `PyInstaller archive string` (location
`SECTION`).

## Scanning without PEData

`SignatureScanner.newInstance()` loaded the PEiD signatures. The bundled
databases are now available from `DefaultSignatures`, loaded once per process:

| Database | Content |
|---|---|
| `DefaultSignatures.getPackers()` | Packers, protectors and compilers, the former `userdb.txt` |
| `DefaultSignatures.getInstallers()` | Installers and archives in the overlay, the former `overlaysignatures` |
| `DefaultSignatures.getFileTypes()` | File type magic numbers, the former `customsigs_GCK.txt` |
| `DefaultSignatures.getJavaWrappers()` | Java wrappers, the former `javawrapperdb` |
| `DefaultSignatures.getPE()` | Packers, installers and file types, what `PEData` scans |

Before:

```java
SignatureScanner scanner = SignatureScanner.newInstance();
List<String> results = scanner.scanAllToString(file, true);
```

After:

```java
SignatureScanner scanner = DefaultSignatures.getPEScanner();
List<SignatureMatch> matches = scanner.scan(PELoader.loadPE(file), LocationKind.ENTRY_POINT);
```

The new scanner works on a parsed `PEData`, because most locations need the PE
structure. For files that are no PE files, `scanner.scanFile(file)` and
`scanner.scanBytes(bytes)` scan the locations `file` and `eof`.

Creating a `SignatureScanner` compiles its database. Create scanners once and
reuse them, they are immutable and thread-safe. PortEx 5 reloaded the
databases for every scanned file.

## Your own PEiD databases

`SignatureScanner.loadSignatures(file)` read a PEiD database. Use the
`PEiDImporter`, which converts PEiD databases to the new format while loading:

Before:

```java
List<Signature> signatures = SignatureScanner.loadSignatures(new File("userdb.txt"));
SignatureScanner scanner = new SignatureScanner(signatures);
List<String> results = scanner.scanAllToString(file, false);
```

After:

```java
SignatureDatabase peid = PEiDImporter.load(new File("userdb.txt"));
peid.getWarnings().forEach(System.out::println);
SignatureScanner scanner = new SignatureScanner(peid);
List<SignatureMatch> matches = scanner.scan(PELoader.loadPE(file));
```

Signatures with `ep_only = true` are matched at the entry point, all others
anywhere in the file, which is what `scanAll(file, false)` did. Malformed
entries are skipped and listed in `getWarnings()` instead of failing the
whole file.

The importer also understands the keys `at_offset`, `until_offset`,
`section_start_only`, `is_dot_net` and `in_section`, which PortEx 5 ignored.
`PEiDImportOptions` matches the signatures without `ep_only` somewhere else,
e.g. at the start of the overlay like the former overlay database:

```java
PEiDImportOptions options = new PEiDImportOptions("overlay", true, false);
SignatureDatabase db = PEiDImporter.load(new File("overlaysigs.txt"), options);
```

To convert a PEiD database to the new format once:

```java
SignatureDatabase peid = PEiDImporter.load(userdb);
try (Writer out = new FileWriter(target)) {
    SignatureDatabaseWriter.write(peid, out);
}
```

Databases in the new format are loaded with `SignatureDatabase.load(file)`.
Combine them with the bundled signatures with `SignatureDatabase.merge`:

```java
SignatureDatabase db = SignatureDatabase.load(new File("mysignatures.sig"));
SignatureDatabase combined = SignatureDatabase.merge(DefaultSignatures.getPE(), db);
List<SignatureMatch> matches = new SignatureScanner(combined).scan(data);
```

## Signatures defined in code

The old `Signature` took an array of `Option[Byte]`. Signatures are now
written in the database format, also in code:

Before:

```java
Signature sig = Signature.apply("My packer", true, "60 BE ?? ?? ?? ?? 8D BE");
SignatureScanner scanner = new SignatureScanner(Arrays.asList(sig));
```

After:

```java
SignatureDatabase db = SignatureDatabase.parse(
        "[My packer]\n" +
        "pattern = 60 BE ?? ?? ?? ?? 8D BE\n" +
        "at = entrypoint\n", "inline");
List<SignatureMatch> matches = new SignatureScanner(db).scan(data);
```

`Signature` is still the name of the class for one signature, but it has a new
API: name, patterns with their locations, conditions and metadata.

### Matching at a given offset

`scanAt(file, offset)` matched all signatures at one file offset. If the offset
belongs to a location, use that location in the signature, e.g.
`at = overlay + 0x34` or `at = file + 0x400`. For an arbitrary offset, read the
bytes there and scan them, the location `file` then starts at that offset:

```java
byte[] window = new byte[4096];
int read;
try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
    raf.seek(offset);
    read = Math.max(0, raf.read(window));
}
List<SignatureMatch> types = FileTypeScanner.scan(Arrays.copyOf(window, read));
```

A single pattern can be checked with `Pattern.parse("4D 5A").matchAt(bytes, index)`.

## File types

Before:

```java
List<String> report = FileTypeScanner.apply(file).scanAtReport(0);
```

After:

```java
for (SignatureMatch type : FileTypeScanner.scan(file)) {
    System.out.println(type.getName() + ", " + type.getLength() + " bytes matched");
}
```

`FileTypeScanner` is now an object with `scan(File)` and `scan(byte[])`. The
file type signatures are also part of the `PEData` scan: they match at the
start of the overlay and of every resource.

## Java wrappers

`Jar2ExeScanner` keeps its methods, `scan()` returns `SignatureMatch` instead
of `MatchedSignature`. The names lost their brackets, the constants
`Jar2ExeScanner.ZipSignature()` and `Jar2ExeScanner.ClassSignature()` hold the
names of the ZIP and class file signatures. The report of `createReport()` is
unchanged.

```java
Jar2ExeScanner scanner = new Jar2ExeScanner(file);
for (SignatureMatch match : scanner.scan()) {
    if (match.getName().equals(Jar2ExeScanner.ZipSignature())) {
        System.out.println("zip at 0x" + Long.toHexString(match.getOffset()));
    }
}
```

## Reports and PortexAnalyzer output

* `ReportCreator.peidReport()` is now `ReportCreator.signatureReport()`. Its
  title is `Signatures` instead of `PEID Signatures`, and it lists the matches
  in all locations except the overlay and resources, which have their own
  sections.
* Matches are printed as
  `Armadillo v4.x at entrypoint+0x0 (file offset 0x1a9f5, 190 bytes)` instead
  of `[Armadillo v4.x] bytes matched: 2 at address: 0x1a9f5` with a pattern
  line.
* The file type report for files that are no PE files keeps its format.
* The new section `Authenticode Signatures` (`ReportCreator.authenticodeReport()`,
  part of `specialSectionReports()`) describes the certificate table, the
  signatures, signers, timestamps, certificates and the integrity checks.
* The data directory table shows the certificate table address as file offset,
  marked with `*`, and the section that contains it physically.

If you parse the output of PortexAnalyzer, adjust to the new line format and
to names without brackets.

## Results that change

PortEx 6 finds every match that PortEx 5 found on the test corpus of PortEx,
with these intended differences:

* **Offsets of overlay signatures with leading wildcards.** Signatures that
  skipped bytes with leading `??` are anchored with an offset now. They report
  the offset of the actual bytes: `Inno Setup Installer with Stub` is reported
  at the start of the overlay plus 0x34. `getRegionStart()` is the start of the
  overlay, which PortEx 5 reported as address.
* **Settings of the old databases that were ignored are honoured.** Overlay
  signatures with `at_offset` match at that offset, those with `until_offset`
  anywhere in the first bytes of the overlay, and the .NET Reactor signatures
  require .NET files.
* **Signatures that PortEx 5 never scanned.** The .NET Reactor signatures with
  `in_section` are searched in the section of the entry point and in executable
  sections.
* **The entry point.** No entry point signatures are reported for files whose
  entry point is 0, and a signature match must end within the section of the
  entry point.
* **More locations.** `getSignatureMatches()` without arguments scans all
  locations except `file`, also `section`, `eof` and the others of
  [SIGNATURES.md](SIGNATURES.md). The bundled databases use the entry point,
  sections, the overlay, resources and the MS-DOS header, so the default
  results only grow by the signatures listed above. The location `file` is
  excluded, because every PE file would match the file type signature of PE
  files at offset 0; pass `LocationKind.FILE` explicitly if you want it.
* **The certificate table address is a file offset.** For
  `DataDirectoryKey.CERTIFICATE_TABLE`, `DataDirEntry.getFileOffset`,
  `DataDirEntry.maybeGetSectionTableEntry`, `SectionLoader.maybeGetFileOffsetFor`,
  `SectionLoader.maybeGetSectionHeader` and `SectionLoader.hasValidPointer` no
  longer convert the address as an RVA. Before, they gave wrong results if the
  offset was within the virtual range of a section.
* **`INVALID_DATA_DIR` for the certificate table** is reported if the table
  starts outside of the file, with a description that says that the signature
  was probably stripped.
* **More anomalies for signed files.** `PEAnomalyScanner` includes the new
  `CertificateScanning`. Most signed files get at least `CERT_SHA1_DIGEST`
  (deprecated) because of SHA-1 timestamps or certificates. See
  [Authenticode signatures](#authenticode-signatures).
* **Hashing of signed files.** `PEData.loadAll()` and the anomaly scanner now
  verify the signatures of signed files, which reads the whole file once. Both
  can be cancelled with `Thread.interrupt()`.

## Removed classes and methods

| Removed | Replacement |
|---|---|
| `tools.sigscanner.MatchedSignature` | `SignatureMatch` |
| `tools.sigscanner.SignatureScannerManager` | `PEData.getSignatureMatches(...)`, internally `PESignatureMatches` |
| `tools.sigscanner.SignatureTree` | none, the scanner compiles databases internally |
| old API of `tools.sigscanner.SignatureScanner`: `newInstance()`, `scanAt`, `scanAll`, `scanAllToString`, `findAllEPMatches`, `findAllEPFalseMatches`, `maybeGetEntryPoint`, `loadSignatures`, `loadOverlaySigs`, `toMatchedSignature`, the inner class `SignatureMatch` | `SignatureScanner` with `scan`, `scanFile` and `scanBytes`, `DefaultSignatures`, `PEiDImporter` |
| old API of `tools.sigscanner.Signature`: the constructor with `Option[Byte]` patterns, `apply`, `bytesMatched`, `signatureString`, `hex2bytes` | `SignatureDatabase.parse` and the new `Signature` |
| old API of `tools.sigscanner.FileTypeScanner`: `apply(file)`, `scanAt`, `scanAtReport` | `FileTypeScanner.scan(file)` |
| the package `tools.sigscanner.v2` | the new scanner, which supports its pattern syntax and scan locations |
| `ScalaIOUtil.bytes2hex(Array[Option[Byte]], String)` | none |
| `ReportCreator.peidReport()` | `ReportCreator.signatureReport()` |
| the files `data/userdb.txt`, `data/overlaysignatures`, `data/javawrapperdb` and `data/customsigs_GCK.txt` in the jar | `data/signatures/*.sig`, or `DefaultSignatures` |

## Visualizer and structure map

PortEx 6 adds a structure map and a visualization engine. Code that uses
`Visualizer` keeps working: its public methods are unchanged, and the images
keep their size and, by default, their look.

### Fixes in the default images

* The legend no longer depends on the order of calls. Entry Point and Overlay
  no longer disappear after `createEntropyImage` or `createBytePlot`.
* Resource types of one file no longer appear in the legend of the next file.
* `createLegendImage` before any other call shows the byte plot and entropy
  part instead of throwing a `NullPointerException`.
* Entropy images no longer color one pixel after the end of the file, and
  empty files no longer throw an `ArithmeticException`.
* Some structures are colored more exactly: the .NET metadata root includes
  all stream headers, the Rich header includes its XOR key, and relocation
  blocks of size 0 cover their 8 byte header.

### New in the Visualizer

* `PEData` overloads: `createImage(PEData)`, `createEntropyImage(PEData)`,
  `createBytePlot(PEData)`, `createLegendImage(PEData, boolean, boolean, boolean)`
  and `writeImage(PEData, File[, String])`. The visualizer keeps the structures
  of the last file, so creating several images parses the file once.
* `VisualizerBuilder.setLegacyStyle(false)` switches to the look of the
  interactive visualization:
  * each byte plot pixel shows the most frequent byte class of its bytes
    instead of the first byte
  * the entropy is the mean of the entropies of 256 byte windows instead of
    the entropy of one 100 byte window
  * smaller structures are drawn on top of larger ones instead of a fixed order
  * the MSDOS stub, the PE signature, bound imports, TLS, load config,
    exception and certificate tables and unmapped bytes are colored
  * resource types have fixed colors that are the same for every file
  * the legend lists only the structures of the file
* New `ColorableItem` constants, appended so that the ordinals of the existing
  ones stay the same: `PE_SIGNATURE`, `MSDOS_STUB`, `BOUND_IMPORT_SECTION`,
  `EXCEPTION_SECTION`, `CERTIFICATE_TABLE`, `TLS_SECTION`,
  `LOAD_CONFIG_SECTION`, `UNMAPPED` and `SIGNATURE_MATCH`.
  `VisualizerBuilder.getDefaultColors()` returns all default colors.

### New packages

* `tools.layout`: `StructureMap` maps file offsets to the structures found
  there, innermost first: headers and their fields, sections, imports per DLL,
  exports, relocations, debug data, resources, .NET metadata, the certificate
  table with its entries, signatures and certificates, declared data
  directories, overlay, unmapped bytes and markers for the entry point,
  signature matches, anomalies and your own regions.
* `tools.visualizer.engine`: `ByteStatistics` (entropy and byte classes of any
  range after one pass over the file), `CachedByteSource`, and `ViewMapping`
  and `Viewport` to convert between offsets, cells and pixels.
* `tools.visualizer.render`: thread-safe renderers for byte plot, entropy,
  structure, hex and ASCII tracks, `RegionColorScheme`, `LegendRenderer` and
  `VisualizationRenderer` for composite images.

```java
PEData data = PELoader.loadPE(file);
StructureMap map = StructureMap.of(data);
for (FileRegion region : map.regionsAt(0x80)) {
    System.out.println(region.getPath() + " " + region); // Headers > PE Signature [0x80,0x84)
}
```

### PortexAnalyzer

* `-l`, `--loc` and `--location` print all structures at an offset, innermost
  first, with half-open ranges, e.g.
  `0x80: PE Signature [0x80,0x84) < Headers [0x0,0x200)`. The labels of former
  versions are printed in a line `0x80: hints: ...`. Invalid offsets set exit
  code 1.
* `--layout` prints all structures of the file with their ranges.
* `-p <imagefile> --from <offset> --to <offset>` draws a range of the file;
  ranges of up to 4 KB show hex bytes.

## Authenticode signatures

The new package `parser.sections.cert` parses the attribute certificate table
(data directory entry 4): the WIN_CERTIFICATE entries, the PKCS#7 signatures,
the embedded X.509 certificates, signers, legacy countersignatures, RFC 3161
timestamps, nested signatures and page hashes. It needs no extra dependency;
X.509 certificates are additionally offered as `java.security.cert.X509Certificate`.

```java
PEData data = PELoader.loadPE(file);
Optional<CertificateTable> table = data.loadCertificateTable();
for (AuthenticodeSignature signature : data.loadAuthenticodeSignatures()) {
    Optional<AuthenticodeCertificate> signer = signature.getSigner()
            .flatMap(SignerInfo::getSignerCertificate);
    System.out.println(signature.getLabel() + " by "
            + signer.map(AuthenticodeCertificate::getSubjectName).orElse("unknown"));
}
Optional<AuthenticodeVerification> verification = data.loadAuthenticodeVerification();
```

`SectionLoader.maybeLoadCertificateTable()`, `CertificateTable.load(PEData)` and
`AuthenticodeVerifier.verify(PEData)` do the same without caching.

**Integrity only.** `AuthenticodeVerifier` checks that the image digest
matches the file, that the messageDigest attribute matches the signed content,
the signer signature, the signature of each embedded certificate by its
embedded issuer, and the timestamps. `VerificationStatus.VALID` means the file
was not modified after signing and the signature is consistent. It does not
mean that the signer is trusted: PortEx knows no trusted roots and checks no
revocation or expiry policy.

**The image digest** is computed over the whole file without the checksum, the
certificate table entry and the certificate table. For files with contiguous
sections this is the same as the per-section algorithm of the Authenticode
specification, and it does not depend on section headers, so malformed headers
can not lead to out-of-bounds reads.

**Robustness.** The parser uses its own ASN.1 reader with an explicit stack, so
deep nesting can not overflow the call stack, and every length is checked
against the available bytes before it is used. Sizes and counts are limited by
the constants of `CertificateTable`, e.g. `MAX_TABLE_READ_SIZE` (4 MiB),
`MAX_DER_DEPTH` (64), `MAX_CERTIFICATES` (64 per signature) and
`MAX_NESTING_DEPTH` (4). Malformed data never throws, it is reported as
`CertificateIssue` by `getIssues()` of the table, the signatures and the
verification.

**Anomalies.** The issues are anomalies with the prefix `CERT_`, typed like the
other anomalies of PortEx:

* data directory entry (`DataDirAnomaly`): `CERT_DIR_NOT_ALIGNED`,
  `CERT_DIR_SIZE_EXCEEDS_FILE`, `CERT_DIR_TOO_SMALL`
* WIN_CERTIFICATE header fields (`FieldAnomaly`): `CERT_INVALID_LENGTH`,
  `CERT_INVALID_REVISION`, `CERT_INVALID_TYPE` (wrong),
  `CERT_DEPRECATED_REVISION` (deprecated), `CERT_RESERVED_TYPE` (reserved),
  `CERT_UNSUPPORTED_TYPE` (non-default)
* structural malformations (`StructureAnomaly`, key
  `PEStructureKey.CERTIFICATE_TABLE`), e.g. `CERT_TABLE_TRUNCATED`,
  `CERT_TABLE_IN_SECTION`, `CERT_TABLE_NOT_LAST`, `CERT_TABLE_MISPLACED`,
  `CERT_MULTIPLE_ENTRIES`, `CERT_DATA_AFTER_PKCS7` (CVE-2013-3900),
  `CERT_MALFORMED_PKCS7`, `CERT_LARGE_UNAUTH_ATTRIBUTE`
* fields of the signature (`AuthenticodeAnomaly`, key `AuthenticodeFieldKey`),
  e.g. `CERT_IMAGE_DIGEST_MISMATCH` (modified file or copied signature),
  `CERT_EXPLICIT_EC_PARAMETERS` (CurveBall, CVE-2020-0601),
  `CERT_INVALID_ECDSA_VALUE` (Psychic Signatures, CVE-2022-21449),
  `CERT_WEAK_DIGEST` and `CERT_SHA1_DIGEST` (deprecated),
  `CERT_SELF_SIGNED_SIGNER` and `CERT_UNKNOWN_UNAUTH_ATTRIBUTE` (non-default)

A table that starts outside of the file is reported as `INVALID_DATA_DIR`,
exceeded limits as `EXHAUSTIVE_DATA`.

**Structure map and visualizer.** The certificate table is no longer a
declared-only region: it has the children `WIN_CERTIFICATE`,
`PKCS7_SIGNED_DATA`, `CERTIFICATE` and `CERTIFICATE_PADDING`, and in
`Detail.FINE` the header fields and `SIGNER_INFO`.
`RegionType.CERTIFICATE_TABLE.isDeclaredDirectory()` is false now.

**Overlay.** The certificate table usually lies at the end of the file. It
stays part of the overlay, as before and as in other tools.

**PortexAnalyzer.** `--dump certificates` writes each signature as `.p7b` file
and each embedded certificate as `.cer` file; `--dump all` includes them.

## Scala

The Scala API mirrors the Java API. Methods with a leading underscore return
Scala collections:

```scala
val db = SignatureDatabase.load(new File("mysignatures.sig"))
val scanner = SignatureScanner(db)
val matches: IndexedSeq[SignatureMatch] = scanner._scan(data, Set(LocationKind.OVERLAY))
val fileTypes: IndexedSeq[SignatureMatch] = FileTypeScanner._scan(file)
val lenient = SignatureDatabase.parse(text, "mysignatures.sig", lenient = true)
```

`PEData.getSignatureMatches` returns a Java list, use `asScala` as for the
other `PEData` getters.
