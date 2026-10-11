; PortEx signature database: Java wrappers, searched in the whole file
; Format: see docs/SIGNATURES.md
; Converted from javawrapperdb of PortEx 5 by SignatureDbConverter

[PKZIP Archive File]
pattern = 50 4B 03 04
in = file
description = PZIP Magic Number (weak indication for embedded zip)

[Jar Manifest]
pattern = 4D 45 54 41 2D 49 4E 46 2F 4D 41 4E 49 46 45 53 54 2E 4D 46
in = file
description = Jar manifest (strong indication for embedded jar)

[Jar2Exe Products]
pattern = 4A 61 72 32 45 78 65 20 50 72 6F 64 75 63 74 73
in = file
description = Jar2Exe.com signature

[Launch4j]
pattern = 4C 61 75 6E 63 68 34 6A
in = file
description = Launch4j signature

[java.exe]
pattern = 6A 61 76 61 2E 65 78 65
in = file
description = Call to java.exe (strong indication for java wrapper)

[javaw.exe]
pattern = 6A 61 76 61 77 2E 65 78 65
in = file
description = Call to javaw.exe (strong indication for java wrapper)

[Jar2Exe Products]
pattern = 45 00 78 00 65 00 63 00 75 00 74 00 69 00 76 00 65 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 4A 00 61 00 72 00 32 00 45 00 78 00 65
in = file
description = Jar2Exe.com signature

[JSmooth]
pattern = 6A 73 6D 6F 6F 74 68
in = file
description = JSmooth signature

[Exe4j]
pattern = 45 58 45 34 4A
in = file
description = Exe4j signature, search in your temp folder for e4jxxxx.tmp file while application is running

[Exe4j]
pattern = 65 78 65 34 6A
in = file
description = Exe4j signature, search in your temp folder for e4jxxxx.tmp file while application is running

[CAFEBABE]
pattern = CA FE BA BE
in = file
description = .class file signature(s) found

