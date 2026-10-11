# Signatures

PortEx detects packers, protectors, compilers, installers, embedded files and
file types with byte signatures. A signature is a byte pattern with wildcards,
plus the locations of a PE file where the pattern is matched, for example the
entry point, the overlay, the resources or the executable sections. Signatures
can also combine several patterns and declarative conditions, such as an
imported function or a string of the .NET metadata.

This page explains the signature database format, how patterns and locations
work, and how to scan files with your own signatures.

* [Quick start](#quick-start)
* [Database format](#database-format)
* [Patterns](#patterns)
* [Locations: `at` and `in`](#locations-at-and-in)
* [Location reference](#location-reference)
* [Several patterns](#several-patterns)
* [Conditions](#conditions)
* [Metadata](#metadata)
* [Examples](#examples)
* [Scanning from Java and Scala](#scanning-from-java-and-scala)
* [Performance tips](#performance-tips)
* [Forward compatibility](#forward-compatibility)
* [Migrating from PortEx 5](#migrating-from-portex-5)

## Quick start

PortEx scans PE files with its bundled signatures when you ask for the matches:

```java
PEData data = PELoader.loadPE(new File("sample.exe"));
for (SignatureMatch match : data.getSignatureMatches()) {
    System.out.println(match.getName() + " at " + match.getLocationLabel()
            + " offset 0x" + Long.toHexString(match.getOffset()));
}
```

A signature database is a text file with entries like this one:

```portex-sig
[UPX 2.90 LZMA]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF
at = entrypoint
type = packer
```

Scan with your own database:

```java
SignatureDatabase db = SignatureDatabase.load(new File("mysignatures.sig"));
SignatureScanner scanner = new SignatureScanner(db);
List<SignatureMatch> matches = scanner.scan(data);
```

## Database format

* Files are UTF-8 encoded, a byte order mark is allowed. Lines end with LF or CRLF.
* Lines that start with `;` or `#` are comments. Comments must be on their own
  line, because `;` and `#` can be part of patterns.
* An entry starts with the signature name in brackets. The name is everything
  between the first `[` and the last `]` of the line, so names may contain
  brackets themselves: `[[MSLRH] v0.32a -> emadicius]` has the name
  `[MSLRH] v0.32a -> emadicius`.
* The following lines are `key = value` pairs. Keys are case-insensitive.
* Several entries may have the same name, e.g. different patterns for the same
  packer. Exact duplicates are dropped with a warning.

| Key | Meaning |
|---|---|
| `pattern` | The byte pattern, see [Patterns](#patterns) |
| `at` | Locations where the pattern must match exactly at the start, see [Locations](#locations-at-and-in) |
| `in` | Locations that are searched for the pattern |
| `pattern.N`, `at.N`, `in.N` | Further patterns that must match too, see [Several patterns](#several-patterns) |
| `requires`, `section`, `import`, `export`, `resource`, `version_info.<Key>`, `dotnet_string`, `dotnet_us`, `dotnet_type` | Conditions, see [Conditions](#conditions) |
| `type`, `version`, `options`, `lang`, `author`, `url`, `description`, `extensions`, `x-...` | Metadata, see [Metadata](#metadata) |

Every entry needs a pattern with at least one location, or at least one
condition.

Malformed entries cause an error that names the file, line and column, e.g.
`mysignatures.sig:57:14: incomplete byte, expected a second hex digit or '?'`.
Databases can also be loaded leniently, then malformed entries are skipped
and listed as warnings of the database.

## Patterns

A pattern is a sequence of elements. Whitespace between elements is optional
and hex digits are case-insensitive, so `CAFEBABE` and `ca fe ba be` are the
same pattern.

| Element | Matches | Example |
|---|---|---|
| `4D` | the byte 0x4D | `4D 5A` matches `MZ` |
| `??` or `..` | any byte | `E8 ?? ?? ?? ??` |
| `4?` | high nibble 4, any low nibble | `4?` matches 0x40 to 0x4F |
| `?A` | any high nibble, low nibble A | `?A` matches 0x0A, 0x1A, ... 0xFA |
| `**` | any byte except 00 | |
| `%%` | printable ASCII, 0x20 to 0x7F | |
| `%&` | ASCII digit, 0x30 to 0x39 | `'v' %& '.' %&` matches `v3.1` |
| `!%` | not printable ASCII | |
| `_%` | neither printable ASCII nor 00 | |
| `[4]` | skips exactly 4 bytes | `01 [4] 02` |
| `[2-8]` | skips 2 to 8 bytes | |
| `[-8]` | skips 0 to 8 bytes | |
| `[16-]` | skips at least 16 bytes, at most 1 MiB | |
| `( A \| B )` | one of the branches | `(55 8B EC \| 53 56 57)` |
| `'text'` or `"text"` | the text as UTF-8, which is ASCII for ASCII text | `'PYZ'` |
| `w'text'` | the text as UTF-16LE | `w'Setup'` |
| `i'text'` | the text with ASCII letters in any case | `i'kernel32'` matches `KERNEL32` |
| `aw'text'` | the text as ASCII or UTF-16LE, same as `('text' \| w'text')` | |
| `$$`, `$$$$`, `$$$$$$$$` | follows a relative jump, see below | `E8 $$$$$$$$ 55 8B EC` |
| `##`, `####`, `########` | follows an absolute address, see below | `68 ######## 'MZ'` |

Jump bounds are decimal numbers or hex numbers with the prefix `0x`, e.g.
`[0x10-0x20]`. Groups can be nested, and their branches can have different
lengths and contain jumps and strings. A pattern needs at least one element
that is not a wildcard or jump.

```portex-pattern
60 BE ?? ?? ?? ?? 8D BE
CA FE BA BE
4D 5A [0x3A] 80 00 00 00
(55 8B EC | 53 56 57) 83 EC ?? 
'MZ' ** %% %& !% _%
EF BE AD DE 'Null' ?? 'oftInst'
```

### Strings

Strings are written in single or double quotes. Inside a string, `?` is a
literal question mark: `'PK??'` matches the text `PK??`. To combine text
and wildcards, close the string: `'PK' ?? ?? 'NOS_PO'`.

Escape sequences: `\\` backslash, `\'` and `\"` quotes, `\n`, `\r`, `\t`,
`\0`, and `\xHH` for a raw byte (in `w` strings `\xHH` is the UTF-16 code
unit 00HH). Characters outside ASCII are encoded as UTF-8: `'é'` is `C3 A9`,
use `'\xE9'` for the single byte E9.

Modifiers before the quote change the encoding:

| Modifier | Bytes for `'Ab'` |
|---|---|
| none | `41 62` |
| `w` | `41 00 62 00` |
| `i` | `41 62`, `41 42`, `61 62` or `61 42` |
| `wi` | `41 00 62 00` with letters in any case |
| `aw` | `41 62` or `41 00 62 00` |
| `awi` | any of the above |

Put a space between hex bytes and a string with modifiers, because `a` is also
a hex digit: write `AB aw'x'`, not `ABaw'x'`.

```portex-pattern
'PYZ'
w'***messages***'
i'kernel32.dll'
aw'Setup'
awi'This program'
'MEI\x0C\x0B\x0A\x0B\x0E'
```

### Follow tokens

Follow tokens read an address and continue matching where it points to, e.g.
at the target of a call. This is useful for packer stubs that jump around.

* `$$`, `$$$$`, `$$$$$$$$` and `$` 16 times read a signed displacement of 1, 2,
  4 or 8 bytes. Matching continues at the end of the displacement plus its
  value, e.g. `E8 $$$$$$$$` follows a call with a 32 bit displacement.
* `##`, `####`, `########` and `#` 16 times read a virtual address of 1, 2, 4
  or 8 bytes. Matching continues at the file offset of that address, e.g.
  `68 ########` follows `push address`.

Addresses are converted between file offsets and virtual addresses with the
section table of the PE file. For files that are no PE files, addresses are
file offsets. If the target is not within the file, the pattern does not
match. The reported length of a match ends after the first follow token.

## Locations: `at` and `in`

A pattern is matched in locations of the file. Each location resolves to
zero, one or more regions, e.g. `section` resolves to one region per section.

`at = <location>` anchors the pattern: the match must start exactly at the
start of each region. An offset moves the anchor:

```
at = overlay            ; match at the start of the overlay
at = overlay + 0x34     ; match 0x34 bytes after the start of the overlay
at = eof - 0x18         ; match 0x18 bytes before the end of the file
at = eof                ; the match must end at the end of the file
```

`in = <location>` searches the regions. A window limits where matches may
start, relative to the region start. The end of the window is exclusive, and
every match must end within its region.

```
in = file                     ; anywhere in the file
in = overlay[0-0x100]         ; matches that start in the first 0x100 bytes of the overlay
in = overlay[0x100]           ; the same
in = section(.rdata)[0x40-]   ; matches that start at least 0x40 bytes after the section start
in = eof[0x1000]              ; matches that start in the last 0x1000 bytes of the file
in = eof                      ; the last 0x10000 bytes
```

Offsets and window bounds are decimal numbers or hex numbers with the prefix
`0x`. Offsets are only allowed with `at` and windows only with `in`.

A key can list several locations separated by commas, and `at` and `in` can
both be used. One match in any of them is enough. Each match is reported with
its location.

```
at = overlay, resource, file
in = section(executable)
```

## Location reference

| Location | Region | Notes |
|---|---|---|
| `file` | The whole file | Works for all files |
| `eof` | The end of the file | Works for all files, see `at` and `in` above |
| `image` | The file without its overlay | |
| `msdos_header` | Bytes 0 to 0x40 | |
| `msdos_stub` | From 0x40 to the PE signature | |
| `rich_header` | The Rich header | The Rich header is XOR encoded in the file |
| `headers` | From 0 to SizeOfHeaders | |
| `overlay` | From the end of the last section to the end of the file | No region if there is no overlay |
| `entrypoint` | From the entry point to the end of its section | No region if the entry point is 0 or outside the file |
| `export` | From each exported function to the end of its section | Forwarded exports are skipped |
| `export(<name>)` | Exported functions with matching names | `*` is a wildcard, case-sensitive |
| `section` | The raw data of each section | Sections without raw data are skipped |
| `section(<name>)` | Sections with matching names | `*` is a wildcard, case-sensitive, quote names with special characters: `section(".text 2")` |
| `section(#0)`, `section(#-1)` | The section with that index | 0 is the first section, -1 the last |
| `section(executable)` | Sections with the characteristic IMAGE_SCN_MEM_EXECUTE | |
| `section(code)` | Sections with the characteristic IMAGE_SCN_CNT_CODE | |
| `section(entrypoint)` | The section that contains the entry point | |
| `resource` | The data of each resource | |
| `resource(<type>[/<name>[/<language>]])` | Resources with matching type, name and language | Types are names like `RT_RCDATA` or numbers, `*` is a wildcard, case-insensitive |
| `manifest` | Same as `resource(RT_MANIFEST)` | |
| `datadir(<key>)` | The range a data directory entry declares | Keys: `EXPORT_TABLE`, `IMPORT_TABLE`, `RESOURCE_TABLE`, `EXCEPTION_TABLE`, `CERTIFICATE_TABLE`, `BASE_RELOCATION_TABLE`, `DEBUG`, `ARCHITECTURE`, `GLOBAL_PTR`, `TLS_TABLE`, `LOAD_CONFIG_TABLE`, `BOUND_IMPORT`, `IAT`, `DELAY_IMPORT_DESCRIPTOR`, `CLR_RUNTIME_HEADER`, `RESERVED` |
| `certificate` | The Authenticode certificate table | |
| `debug_data` | The data of each debug directory entry, e.g. the CodeView record with the PDB path | |
| `dotnet` | The .NET metadata, including all streams | |
| `dotnet_stream(<name>)` | One stream of the .NET metadata: `#~`, `#Strings`, `#US`, `#Blob` or `#GUID` | |

All locations except `file` and `eof` only exist in PE files. Regions are
clipped to the file. A location that does not exist in a file, such as the
overlay of a file without overlay, has no regions and nothing matches there.

## Several patterns

A signature can have several patterns that must all match, each with its own
locations. The first pattern uses the keys `pattern`, `at` and `in`, further
patterns use the keys with a number: `pattern.2`, `at.2`, `in.2`,
`pattern.3`, and so on.

```portex-sig
[Installer stub with message table]
pattern = E8 $$$$$$$$ 55 8B EC
at = entrypoint
pattern.2 = w'***messages***'
at.2 = overlay
type = installer
```

The match is reported at the location of the first pattern. The further
patterns are only checked if the first one matched, so put the most specific
or cheapest pattern first. `SignatureMatch.getClauseMatches()` lists the
match of every pattern.

To detect something with alternative patterns where any of them may match,
write several entries with the same name.

## Conditions

Conditions check properties of the PE file that are not byte patterns. All
conditions of a signature must hold, in addition to its patterns. A key can
have several comma separated values, all of them must hold, and a key can be
used several times.

| Key | Holds if | Example |
|---|---|---|
| `requires` | the file has all the listed properties | `requires = dotnet, pe32` |
| `section` | a section has the name | `section = .UPX0` |
| `import` | the DLL or function is imported, including delay-load imports | `import = kernel32.dll!VirtualAlloc` |
| `export` | a function with the name is exported | `export = DllRegisterServer` |
| `resource` | a resource matches the type, name and language | `resource = RT_RCDATA/PYTHON*` |
| `version_info.<Key>` | the version information has the key with the value | `version_info.ProductName = WinRAR` |
| `dotnet_string` | the #Strings heap contains the string, e.g. a type, method or namespace name | `dotnet_string = ConfusedByAttribute` |
| `dotnet_us` | the #US heap contains the user string, e.g. a string literal | `dotnet_us = "Hello World!"` |
| `dotnet_type` | the TypeDef table contains the type, written as `Namespace.Name` | `dotnet_type = SmartAssembly.Attributes.PoweredByAttribute` |

Properties of `requires`:

| Property | Meaning |
|---|---|
| `dotnet` | .NET assembly |
| `native` | no .NET assembly |
| `pe32`, `pe32+` | 32 bit or 64 bit PE format |
| `x86`, `x64` | machine type i386 or AMD64 |
| `dll` | DLL |
| `driver` | subsystem native, used by drivers |
| `console`, `gui` | subsystem Windows console or Windows GUI |
| `overlay` | has an overlay |
| `signed` | has an Authenticode certificate table entry; the signature is not verified |
| `rich` | has a Rich header |
| `tls` | has a TLS directory |

Values:

* A plain value must be equal to the property, e.g. `section = .text`.
* `"quoted"` values can contain commas and leading or trailing spaces.
* `/regex/` values are Java regular expressions that must be found in the
  property, use `^` and `$` to match the whole property. The flags `i`, `s`
  and `m` may follow, e.g. `/^upx\d$/i`.
* `!` negates a value: `requires = !dotnet`, `section = !.text`.

Comparisons are case-sensitive, except for DLL names of imports, keys of the
version information and resource selectors. Regular expressions for imports
are matched against lower case DLL names and `dll!function` strings.

A signature can consist of conditions only. Such signatures are reported with
the location kind `METADATA` and without offset.

```portex-sig
[Example .NET library]
dotnet_type = Example.Library.Entry
requires = dotnet
type = library
```

## Metadata

Metadata keys describe a signature and do not influence matching.

| Key | Meaning |
|---|---|
| `type` | Comma separated categories: `packer`, `protector`, `cryptor`, `installer`, `sfx`, `compiler`, `linker`, `library`, `tool`, `joiner`, `format`, `archive` |
| `version` | Version of the detected software |
| `options` | Free text, e.g. options of the detected software |
| `lang` | Programming language |
| `author`, `url` | Origin of the signature |
| `description` | Description of the signature |
| `extensions` | Comma separated file extensions of file types |
| `x-...` | Your own keys, e.g. `x-reference` |

## Examples

A packer at the entry point:

```portex-sig
[UPX 2.90 LZMA]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF
at = entrypoint
type = packer
```

An installer whose data starts 0x34 bytes after the start of the overlay:

```portex-sig
[Inno Setup Installer with Stub]
pattern = 'Inno'
at = overlay + 0x34
type = installer
```

A file type in the overlay, in resources and at the start of the file:

```portex-sig
[ZIP archive]
pattern = 50 4B 03 04
at = overlay, resource, file
extensions = ZIP, JAR
```

A .NET protector by a string literal and a type name:

```portex-sig
[Example protector]
pattern = w'Protected by Example'
in = dotnet_stream(#US)
dotnet_string = ExampleProtectorAttribute
requires = dotnet
type = protector
```

The end of central directory record of a ZIP file appended to a file:

```portex-sig
[ZIP end of central directory]
pattern = 50 4B 05 06
in = eof[0x10000]
type = archive
```

The cookie at the end of PyInstaller files:

```portex-sig
[PyInstaller cookie]
pattern = 'MEI' 0C 0B 0A 0B 0E
at = eof - 0x18, eof - 0x58
type = installer
```

A string in the first bytes of a section:

```portex-sig
[PyInstaller archive string]
pattern = 'PyInstaller archive'
in = section(.rdata)[0-0x1500]
type = installer
```

A packer by its section names and entry point:

```portex-sig
[UPX 64 bit]
pattern = 53 56 57 55 48 8D 35
at = entrypoint
section = UPX0, UPX1
requires = pe32+
type = packer
```

A library that is only detected by an import:

```portex-sig
[Visual Basic 6 runtime]
import = msvbvm60.dll
type = library
```

These entries are malformed:

```portex-sig-invalid
[offset after the end of file]
pattern = 01 02
at = eof + 4
```

```portex-sig-invalid
[window with at]
pattern = 01 02
at = overlay[0-0x10]
```

```portex-sig-invalid
[only wildcards]
pattern = ?? ?? [4]
at = file
```

## Scanning from Java and Scala

### Bundled signatures

`PEData.getSignatureMatches()` scans the bundled databases for packers,
installers and file types (see `DefaultSignatures`). It scans all locations
except `file`, because every PE file would match the file type signature of
PE files at offset 0. Each location kind is scanned once per `PEData` and the
result is cached. Ask for specific locations to scan less:

```java
List<SignatureMatch> all = data.getSignatureMatches();
List<SignatureMatch> overlay = data.getSignatureMatches(LocationKind.OVERLAY);
List<SignatureMatch> entryPoint = data.getSignatureMatches(LocationKind.ENTRY_POINT, LocationKind.SECTION);
```

For files that are no PE files, `FileTypeScanner.scan(file)` determines the
file type. `Jar2ExeScanner` searches for Java wrappers with the bundled
`javawrappers.sig`.

### Your own signatures

```java
SignatureDatabase db = SignatureDatabase.load(new File("mysignatures.sig"));
// or skip malformed entries and look at the warnings
SignatureDatabase lenient = SignatureDatabase.load(new File("mysignatures.sig"), true);
lenient.getWarnings().forEach(System.out::println);

// combine with the bundled signatures
SignatureDatabase combined = SignatureDatabase.merge(DefaultSignatures.getPE(), db);

SignatureScanner scanner = new SignatureScanner(combined);
List<SignatureMatch> matches = scanner.scan(data);                         // all locations
List<SignatureMatch> overlay = scanner.scan(data, LocationKind.OVERLAY);  // some locations
List<SignatureMatch> plain = scanner.scanFile(new File("unknown.bin"));   // file and eof only, no PE parsing
```

In Scala, the methods with a leading underscore return Scala collections:

```scala
val db = SignatureDatabase.load(new File("mysignatures.sig"))
val scanner = SignatureScanner(db)
val matches: IndexedSeq[SignatureMatch] = scanner._scan(data, Set(LocationKind.OVERLAY))
```

Creating a `SignatureScanner` compiles the database, so create it once and
reuse it. Scanners are immutable and can be shared between threads.
`ScanOptions` sets the maximum number of matches per signature (10000 by
default) and the backtracking limit of a single match attempt.

Scans check the interruption flag of the thread and throw an
`AnalysisInterruptedException` if it is set.

### PEiD databases

`PEiDImporter` converts PEiD databases like `userdb.txt`:

```java
SignatureDatabase peid = PEiDImporter.load(new File("userdb.txt"));
List<SignatureMatch> matches = new SignatureScanner(peid).scan(data, LocationKind.ENTRY_POINT);
```

Signatures with `ep_only = true` are matched at the entry point, all others
anywhere in the file. `PEiDImportOptions` sets another location for them, e.g.
`new PEiDImportOptions("overlay", true, false)` matches them at the start of
the overlay. The importer understands `at_offset` and `until_offset` (hex),
`section_start_only`, `is_dot_net`, `in_section` and quoted strings. Lines that
are no valid UTF-8 are read as windows-1252, and HTML entities in names are
decoded. Use `SignatureDatabaseWriter` to save the converted signatures in the
format of this page.

### Matches

| Method | Value |
|---|---|
| `getName()`, `getSignature()` | The matched signature |
| `getLocationKind()` | Kind of the location of the first pattern, `METADATA` for signatures without pattern |
| `getLocationLabel()` | The matched region, e.g. `section(.text)` or `resource(RT_RCDATA/101/1033)` |
| `getOffset()` | File offset of the match, -1 for signatures without pattern |
| `getRelativeOffset()` | Offset relative to the start of the region |
| `getLength()` | Number of matched bytes, up to the first follow token |
| `getRegion()`, `getRegionStart()`, `getRegionEnd()` | The matched region |
| `getClauseMatches()` | The match of every pattern of the signature |

Matches are ordered by location kind, region, offset and database order.

## Performance tips

* Searching with `in` is fast if the pattern contains a literal of at least two
  bytes: all such signatures are searched at once. Literals after a follow
  token or after a jump without upper bound do not count. Patterns without
  such a literal are checked at every position, which is slow for big
  regions. A warning in `SignatureScanner.getWarnings()` lists these
  signatures.
* Prefer `at` to `in`, and search windows like `overlay[0-0x100]` to whole
  regions.
* Long literals and rare bytes make searches faster than common bytes like
  00, FF, 90 or CC.
* Put the cheapest or most specific pattern first if a signature has several.
* Conditions are evaluated after the first pattern matched. Signatures with
  conditions only parse what their conditions need: section names and header
  fields are cheap, imports, resources and version information are moderate,
  .NET metadata is the most expensive.

## Forward compatibility

Keys that PortEx does not know cause an error, or the signature is skipped
when loading leniently. Ignoring them would turn a signature with a newer
condition into a signature with fewer conditions, which causes false
positives. The keys `linker_version`, `rich_version`, `entropy`, `imphash` and
`priority` are reserved for future versions. Use `x-` keys for your own data.

## Migrating from PortEx 5

PortEx 6 replaces the signature scanner. Code that uses the signature API of
PortEx 5 needs changes, see [MIGRATION-6.md](MIGRATION-6.md). This section is
about signature databases.

The old databases were converted to the format of this page:

| PortEx 5 | PortEx 6 |
|---|---|
| `userdb.txt` | `data/signatures/packers.sig` |
| `overlaysignatures` | `data/signatures/installers.sig` |
| `customsigs_GCK.txt` | `data/signatures/filetypes.sig` |
| `javawrapperdb` | `data/signatures/javawrappers.sig` |

| PortEx 5 database | PortEx 6 database |
|---|---|
| `signature = ...` | `pattern = ...` |
| `ep_only = true` | `at = entrypoint` |
| overlay signatures | `at = overlay` |
| `at_offset = 19A0` (was ignored) | `at = overlay + 0x19A0` |
| `until_offset = 100` (was ignored) | `in = overlay[0-0x100]` |
| leading `?? ?? ??` to skip bytes | `at = overlay + 0x3` |
| `is_dot_net = true` (was ignored) | `requires = dotnet` |
| file type CSV `name,hex,extensions` | `[name]`, `pattern = hex`, `at = overlay, resource, file`, `extensions = ...` |
| names in brackets, e.g. `[NSIS]` | names without the outer brackets, e.g. `NSIS` |

Behaviour changes:

* `at_offset`, `until_offset` and `is_dot_net` of the old databases are
  honoured now. PortEx 5 parsed and then ignored them.
* The signatures of userdb.txt with `in_section` are searched in the section of
  the entry point; PortEx 5 never scanned them.
* The entry point region ends at the end of its section, and there is no
  entry point region if the entry point is 0.
* The check for the "PyInstaller archive" string in .rdata and the Inno Setup
  check of the MS-DOS header are signatures in installers.sig now.
