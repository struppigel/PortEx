; PortEx signature database: packers, protectors, cryptors, installers and SFX from Detect It Easy
; Format: see docs/SIGNATURES.md
;
; Converted from the PE rules of Detect It Easy by hors (https://github.com/horsicq/Detect-It-Easy),
; folder db/PE at commit c9f58b9b8d1bd251c99e60565246092ff6920b1f.
; The key author names the authors of the rule, the key url its source file.
; Entries with the key x-die-loss check less than the original rule.
; The rules that could not be converted are listed at the end of this file.
;
; MIT License
;
; Copyright (c) 2012-2026 hors<horsicq@gmail.com>
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.


; ======================================================================
; Packers
; ======================================================================

; packer_32LiTe.2.sg
[32LiTe 0.03a]
pattern = 60 06 FC 1E 07 BE ?? ?? ?? ?? 6A 04 68 ?? ?? ?? ?? 68
at = entrypoint
type = packer
version = 0.03a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_32LiTe.2.sg

; packer_Advanced_BAT_to_EXE_Converter.2.sg
[Advanced BAT to EXE Converter 2.X-4.X]
pattern = 55 8B EC 6A FF 68
at = entrypoint
pattern.2 = ?? 02 02 02 02 36 3A 38 39 3A
at.2 = overlay
type = packer
version = 2.X-4.X
lang = Batch
author = A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Advanced_BAT_to_EXE_Converter.2.sg

; packer_AHpacker.2.sg
[AHpacker 0.1]
pattern = 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 6A 40 FF D0 89 05
at = entrypoint
section = !"!EPack"
type = packer
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_AHpacker.2.sg
x-die-loss = DIE requires only the first and the last section not to be named !EPack, the entry requires no section with that name

; packer_Ahri.2.sg
[Ahri]
pattern = 64 8F 05 14 00 00 00 68 AD DE 00 00 68 EF BE 00
in = section(.ahri)
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Ahri.2.sg

; packer_AlushPacker.2.sg
[AlushPacker]
pattern = 00 ** ?? 00
at = section(.packed)
import = /vcruntime140/, /!VirtualProtect$/, /!GetCurrentProcess$/, /!GetModuleHandleA$/, /!MultiByteToWideChar$/, /!FlushInstructionCache$/
requires = rich
type = packer
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_AlushPacker.2.sg
x-die-loss = the five functions must be the first functions of the first imported library in this order, and more than two libraries must be imported

; packer_ANDpakk.2.sg
[ANDpakk 2.0.06]
pattern = 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4
at = entrypoint
type = packer
version = 2.0.06
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ANDpakk.2.sg

[ANDpakk 2.X]
section = ANDpakk2
type = packer
version = 2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ANDpakk.2.sg
x-die-loss = one section, one import with two thunks and the section position (first) are not checked

; packer_Anskya_NTPacker_Generator.2.sg
[Anskya NTPacker Generator]
pattern = 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Anskya_NTPacker_Generator.2.sg

; packer_aPack.2.sg
[aPack 0.62]
pattern = 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6
at = entrypoint
type = packer
version = 0.62
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_aPack.2.sg

[aPack 0.82]
pattern = 1E 06 8C CB BA ?? ?? 03 DA 8D ?? ?? ?? FC 33 F6 33 FF 48 4B 8E C0 8E DB
at = entrypoint
type = packer
version = 0.82
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_aPack.2.sg

[aPack 0.98 [-m]]
pattern = 1E 06 8C C8 8E D8 05 ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B2 ?? BD ?? ?? 33 C9 50 A4 BB ?? ?? 3B F3 76
at = entrypoint
type = packer
version = 0.98
options = -m
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_aPack.2.sg

[aPack 0.98b]
pattern = 8C CB BA ?? ?? 03 DA FC 33 F6 33 FF 4B 8E DB 8D ?? ?? ?? 8E C0 B9 ?? ?? F3 A5 4A 75
at = entrypoint
type = packer
version = 0.98b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_aPack.2.sg

[aPack 0.98b]
pattern = 93 07 1F 05 ?? ?? 8E D0 BC ?? ?? EA
at = entrypoint
type = packer
version = 0.98b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_aPack.2.sg

; packer_ASDPack.2.sg
[ASDPack 2.0]
pattern = 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00
at = entrypoint
type = packer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASDPack.2.sg

; packer_ASPack.2.sg
[ASPack 1.00b-1.07b]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5
at = entrypoint
type = packer
version = 1.00b-1.07b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.00b-1.07b]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5
at = entrypoint
type = packer
version = 1.00b-1.07b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.00-1.08.02]
pattern = 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9
at = entrypoint
type = packer
version = 1.08.00-1.08.02
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.00-1.08.02]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9
at = entrypoint
type = packer
version = 1.08.00-1.08.02
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.03]
pattern = 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD
at = entrypoint
type = packer
version = 1.08.03
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.03]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD
at = entrypoint
type = packer
version = 1.08.03
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.X [possibly]]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 01 EB
at = entrypoint
type = packer
version = 1.08.X
options = possibly
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.X [possibly]]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 01 EB
at = entrypoint
type = packer
version = 1.08.X
options = possibly
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.04]
pattern = 60 E8 41 06 00 00 EB 41
at = entrypoint
type = packer
version = 1.08.04
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.04]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 41 06 00 00 EB 41
at = entrypoint
type = packer
version = 1.08.04
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.X]
pattern = 60 EB ?? 5D FF E5 E8 ?? ?? ?? ?? 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D
at = entrypoint
type = packer
version = 1.08.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 1.08.X]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 EB ?? 5D FF E5 E8 ?? ?? ?? ?? 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D
at = entrypoint
type = packer
version = 1.08.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.000]
pattern = 60 E8 70 05 00 00 EB 4C
at = entrypoint
type = packer
version = 2.000
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.000]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 70 05 00 00 EB 4C
at = entrypoint
type = packer
version = 2.000
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.001]
pattern = 60 E8 72 05 00 00 EB 4C
at = entrypoint
type = packer
version = 2.001
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.001]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 72 05 00 00 EB 4C
at = entrypoint
type = packer
version = 2.001
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.1]
pattern = 60 E8 72 05 00 00 EB 33 87 DB 90 00
at = entrypoint
type = packer
version = 2.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.1]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 72 05 00 00 EB 33 87 DB 90 00
at = entrypoint
type = packer
version = 2.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.11]
pattern = 60 E9 3D 04 00 00
at = entrypoint
type = packer
version = 2.11
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.11]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E9 3D 04 00 00
at = entrypoint
type = packer
version = 2.11
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.11b]
pattern = 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00
at = entrypoint
type = packer
version = 2.11b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.11b]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00
at = entrypoint
type = packer
version = 2.11b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.11c-2.11d]
pattern = 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00
at = entrypoint
type = packer
version = 2.11c-2.11d
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.11c-2.11d]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00
at = entrypoint
type = packer
version = 2.11c-2.11d
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.11d]
pattern = 60 E8 02 00 00 00 EB 09 5D 55
at = entrypoint
type = packer
version = 2.11d
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.11d]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 02 00 00 00 EB 09 5D 55
at = entrypoint
type = packer
version = 2.11d
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.12-2.42]
pattern = 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01
at = entrypoint
type = packer
version = 2.12-2.42
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.12-2.42]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01
at = entrypoint
type = packer
version = 2.12-2.42
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.12b]
pattern = 90 60 E8 $$$$$$$$ 5D 45 55 C3
at = entrypoint
type = packer
version = 2.12b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.12b]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 90 60 E8 $$$$$$$$ 5D 45 55 C3
at = entrypoint
type = packer
version = 2.12b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.1X-2.39]
pattern = 60 E8 $$$$$$$$ 8B 2C 24 81 ED ?? ?? ?? ?? C3
at = entrypoint
type = packer
version = 2.1X-2.39
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.1X-2.39]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 60 E8 $$$$$$$$ 8B 2C 24 81 ED ?? ?? ?? ?? C3
at = entrypoint
type = packer
version = 2.1X-2.39
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.1X-2.39]
pattern = 90 60 E8 $$$$$$$$ 8B 2C 24 81 ED ?? ?? ?? ?? C3
at = entrypoint
type = packer
version = 2.1X-2.39
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.1X-2.39]
pattern = ( 75 00 E9 | 90 75 00 E9 | 90 90 75 00 E9 | 90 75 01 90 E9 | 90 75 01 FF E9 | 90 90 75 01 FF E9 | 90 90 90 75 00 E9 | 90 90 75 01 90 E9 | 90 90 90 75 01 90 E9 | 90 90 90 75 01 FF E9 ) $$$$$$$$ 90 60 E8 $$$$$$$$ 8B 2C 24 81 ED ?? ?? ?? ?? C3
at = entrypoint
type = packer
version = 2.1X-2.39
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

[ASPack 2.12-2.XX]
section = .aspack, .adata
type = packer
version = 2.12-2.XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ASPack.2.sg

; packer_AtomPePacker.2.sg
[AtomPePacker [x64 stub]]
pattern = 40 53 57 48 83 EC ** 65 48 8B 1C 25 ?? ?? ?? ?? FF 15 ** ?? ?? ?? BA ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 48 8B C8
at = entrypoint
section = .ATOM
requires = pe32+
type = packer
options = x64 stub
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_AtomPePacker.2.sg

[AtomPePacker [modified]]
pattern = 40 53 57 48 83 EC ** 65 48 8B 1C 25 ?? ?? ?? ?? FF 15 ** ?? ?? ?? BA ?? ?? ?? ?? 41 B8 ?? ?? ?? ?? 48 8B C8
at = entrypoint
section = !.ATOM
requires = pe32+
type = packer
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_AtomPePacker.2.sg

; packer_BatToExe.2.sg
[Bat To Exe]
pattern = 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3
at = entrypoint
pattern.2 = 78 9C 63 60 18 05 23 19 00 00 02 00 00 01
at.2 = resource(RT_RCDATA)
type = packer
lang = Batch
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BatToExe.2.sg

; packer_BeRoEXEPacker.2.sg
[BeRoEXEPacker 1.00 [LZBRR]]
pattern = 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8
at = entrypoint
type = packer
version = 1.00
options = LZBRR
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00 [LZBRR]]
pattern = 83 7C 24 08 01 0F 85
at = entrypoint
pattern.2 = 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC B2 80 33 DB A4 B3 02 E8
at.2 = entrypoint + 0xB
type = packer
version = 1.00
options = LZBRR
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00 [LZBRS]]
pattern = 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8
at = entrypoint
type = packer
version = 1.00
options = LZBRS
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00 [LZBRS]]
pattern = 83 7C 24 08 01 0F 85
at = entrypoint
pattern.2 = 60 BE ?? ?? ?? ?? BF ?? ?? ?? ?? FC AD 8D 1C 07 B0 80 3B FB 73 3B E8
at.2 = entrypoint + 0xB
type = packer
version = 1.00
options = LZBRS
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00 [LZMA]]
pattern = 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? B9
at = entrypoint
type = packer
version = 1.00
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00]
pattern = BA ?? ?? ?? ?? 8D B2 ?? ?? ?? ?? 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15
at = entrypoint
type = packer
version = 1.00
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00]
pattern = 60 FC B9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? F3 A4
at = entrypoint
type = packer
version = 1.00
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00 [LZMA]]
pattern = 60 68 ?? ?? ?? ?? 68 ?? ?? ?? 00 68 ?? ?? ?? ?? E8 ?? 04 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00
at = entrypoint
type = packer
version = 1.00
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00 [CTX1]]
pattern = 60 E8 00 00 00 00 5E 81 C6 ?? ?? 00 00 BF ?? ?? ?? ?? 60 81 EC 08 04 00 00 89 E3 57 FC 31 C0 B4
at = entrypoint
type = packer
version = 1.00
options = CTX1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker 1.00 [LZBRA]]
pattern = 60 C8 94 0C 00 60 FC BE ?? ?? ?? ?? AD 89 45 FC 33 C0 F7 D0 89 45 F8 F7 D0 B4 08 B9 23 03 00 00
at = entrypoint
type = packer
version = 1.00
options = LZBRA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker]
pattern = 52 C3 '(C)BeRo!PE' 00 00
at = image + 0x2
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

[BeRoEXEPacker [Special PE Header]]
pattern = 52 C3 'BeRo^fr!PE'
at = image + 0x2
type = packer
options = Special PE Header
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BeRoEXEPacker.2.sg

; packer_BoxedApp.2.sg
[BoxedApp]
section = .bxpck, .main
requires = tls
type = packer
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BoxedApp.2.sg
x-die-loss = DIE requires .main to be the section right after .bxpck and more than two sections

[BoxedApp demo]
pattern = 20 00 64 00 65 00 6D 00 6F 00 20
in = section(.bxpck)
section = .bxpck, .main
requires = tls
type = packer
version = demo
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BoxedApp.2.sg
x-die-loss = DIE requires .main to be the section right after .bxpck and more than two sections

[BoxedApp [modified]]
pattern = C2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
section = !.bxpck
requires = tls
type = packer
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BoxedApp.2.sg
x-die-loss = the number of imports (2) is not checked

[BoxedApp [modified]]
pattern = C2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
section = !.main
requires = tls
type = packer
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BoxedApp.2.sg
x-die-loss = the number of imports (2) is not checked

[BoxedApp demo [modified]]
pattern = C2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
pattern.2 = 20 00 64 00 65 00 6D 00 6F 00 20
in.2 = section(.bxpck)
section = !.main
requires = tls
type = packer
version = demo
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_BoxedApp.2.sg
x-die-loss = the number of imports (2) is not checked

; packer_CExe.2.sg
[CExe 1.0a]
pattern = 55 8B EC 81 EC 0C 02 ?? ?? 56 BE ?? ?? ?? ?? 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 ?? ?? ?? ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16
at = entrypoint
type = packer
version = 1.0a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_CExe.2.sg

; packer_CICompress.2.sg
[CICompress 1.0]
pattern = 6A 04 68 00 10 00 00 FF 35 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 97 BE ?? ?? ?? ?? E8 71 00 00 00 3B 05
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_CICompress.2.sg

; packer_Cxfreeze.2.sg
[CX_Freeze]
pattern = 'Unable to change DLL search path!'
in = section(.rdata)
pattern.2 = 25 00 6C 00 73 00 5C 00 6C 00 69 00 62 00 5C 00 6C 00 69 00 62 00 72 00 61 00 72 00 79 00 2E 00 7A 00 69 00 70 00 3B 00 25 00 6C 00 73 00 5C 00 6C 00 69 00 62 00
in.2 = section(.rdata)
pattern.3 = 'Out of memory creating sys.path!'
in.3 = section(.rdata)
pattern.4 = 'Unable to calculate directory of executable!'
in.4 = section(.rdata)
type = packer
lang = Python
author = horsicq, KDSS-Research, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Cxfreeze.2.sg

; packer_dePACK.2.sg
[dePack]
pattern = EB $$ 60 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 $$$$$$$$ 55 8B EC 60 55 8B 75 ?? 8B 7D ?? E8 ?? ?? ?? ?? EB ?? 8B 1C 24 C3
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_dePACK.2.sg

[dePack]
pattern = EB $$ 60 90 EB $$ 61 B8 ?? ?? ?? ?? FF E0
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_dePACK.2.sg

; packer_DxPack.2.sg
[DxPack 1.0]
pattern = 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84
at = entrypoint
pattern.2 = B9
at.2 = entrypoint + 0x20
section = coderpub
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack 1.0 [modified]]
pattern = 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84
at = entrypoint
pattern.2 = B9
at.2 = entrypoint + 0x20
section = !coderpub
type = packer
version = 1.0
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack 0.86]
pattern = 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84
at = entrypoint
pattern.2 = BD
at.2 = entrypoint + 0x20
section = coderpub
type = packer
version = 0.86
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack 0.86 [modified]]
pattern = 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84
at = entrypoint
pattern.2 = BD
at.2 = entrypoint + 0x20
section = !coderpub
type = packer
version = 0.86
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack]
pattern = 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84
at = entrypoint
section = coderpub
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack [modified]]
pattern = 60 E8 ?? ?? ?? ?? 5D 8B FD 81 ED ?? ?? ?? ?? 2B B9 ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 BD ?? ?? ?? ?? ?? 0F 84
at = entrypoint
section = !coderpub
type = packer
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack 1.0]
pattern = EB 03 C2 0C 00 55 8B EC 81 EC 00 10 00 00 B8 00 00 ?? ?? B9 00 10 00 00 BA 00 00 ?? ?? 89
at = entrypoint
section = coderpub
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack 1.0 [modified]]
pattern = EB 03 C2 0C 00 55 8B EC 81 EC 00 10 00 00 B8 00 00 ?? ?? B9 00 10 00 00 BA 00 00 ?? ?? 89
at = entrypoint
section = !coderpub
type = packer
version = 1.0
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack]
pattern = 55 8B EC
at = entrypoint
section = coderpub
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

[DxPack]
pattern = 88 0D ?? ?? ?? ?? CC
at = entrypoint
section = coderpub
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_DxPack.2.sg

; packer_EXE32Pack.2.sg
[Exe32Pack 1.4X]
pattern = 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 BE 5D 8B D5 81 ED
at = entrypoint
type = packer
version = 1.4X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_EXE32Pack.2.sg

; packer_ExE_Pack.2.sg
[ExE Pack 1.0-1.2]
pattern = 60 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 50 B8 ?? ?? ?? ?? FF 10 68 ?? ?? ?? ?? 6A 40 FF D0 89 05
at = entrypoint
section = "!EPack"
type = packer
version = 1.0-1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ExE_Pack.2.sg
x-die-loss = the section name !EPack is not checked to be the first section

[ExE Pack 1.4 lite final]
pattern = 90 90 90 90 61 B8 ?? ?? ?? ?? FF E0 55 8B EC 60 55 8B 75 08 8B 7D 0C E8 02 00 00 00 EB 04 8B 1C 24 C3 81 C3
at = entrypoint
type = packer
version = 1.4 lite final
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ExE_Pack.2.sg

[ExE Pack 1.4 lite final]
pattern = 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8
at = entrypoint
type = packer
version = 1.4 lite final
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ExE_Pack.2.sg

[ExE Pack 1.4]
section = .!ep
type = packer
version = 1.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ExE_Pack.2.sg
x-die-loss = the section name .!ep is not checked to be the last section

; packer_ezip.2.sg
[ezip 1.X]
pattern = E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C 25 00 00 E9 AE 15 00 00 E9 77 2B 00 00 E9 87 02 00 00 E9 70 2E
at = entrypoint
requires = overlay
type = packer
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ezip.2.sg

; packer_Fatpack.2.sg
[Fatpack [resources payload]]
pattern = 5D 00 00 10 00
at = resource(*/FPACK)
requires = native, pe32+, tls
type = packer
options = resources payload
author = DosX, Yosef Khaled
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Fatpack.2.sg
x-die-loss = the single import with import hash and a section with raw size 0 are not checked

[Fatpack [section payload]]
section = .fpack
requires = native, pe32+, tls
type = packer
options = section payload
author = DosX, Yosef Khaled
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Fatpack.2.sg
x-die-loss = the single import with import hash, a section with raw size 0 and the position of .fpack (last section) are not checked

; packer_FSG.2.sg
[FSG 1.31]
pattern = BE ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80
at = entrypoint
type = packer
version = 1.31
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.0]
pattern = BB ?? ?? ?? ?? BF ?? ?? ?? ?? BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.1]
pattern = BB ?? ?? ?? ?? BF ?? ?? ?? ?? BE ?? ?? ?? ?? FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16
at = entrypoint
type = packer
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Watcom C/C++ EXE]]
pattern = EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02
at = entrypoint
type = packer
version = 1.10
options = Watcom C/C++ EXE
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [WinRAR-SFX]]
pattern = 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0
at = entrypoint
type = packer
version = 1.10
options = WinRAR-SFX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [WinRAR-SFX]]
pattern = EB 01 02 EB 02 CD 20 B8 ?? ?? ?? ?? EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7
at = entrypoint
type = packer
version = 1.10
options = WinRAR-SFX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Borland C++ 1999]]
pattern = EB 02 CD 20 2B C8 68 ?? ?? ?? ?? EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9
at = entrypoint
type = packer
version = 1.10
options = Borland C++ 1999
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Borland C++]]
pattern = 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE ?? ?? ?? ?? 0F B6 C9 EB 02 CD 20 BB
at = entrypoint
type = packer
version = 1.10
options = Borland C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Borland Delphi/Borland C++]]
pattern = 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7
at = entrypoint
type = packer
version = 1.10
options = Borland Delphi/Borland C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Borland Delphi/Borland C++]]
pattern = EB 01 2E EB 02 A5 55 BB ?? ?? ?? ?? 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02
at = entrypoint
type = packer
version = 1.10
options = Borland Delphi/Borland C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Borland Delphi/Microsoft Visual C++/ASM]]
pattern = EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB ?? ?? ?? ?? EB 02 82 B8 EB 01 10 8D 05 F4
at = entrypoint
type = packer
version = 1.10
options = Borland Delphi/Microsoft Visual C++/ASM
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Borland Delphi/Microsoft Visual C++]]
pattern = C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7
at = entrypoint
type = packer
version = 1.10
options = Borland Delphi/Microsoft Visual C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Borland Delphi/Microsoft Visual C++]]
pattern = 1B DB E8 02 00 00 00 1A 0D 5B 68 ?? ?? ?? ?? E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00
at = entrypoint
type = packer
version = 1.10
options = Borland Delphi/Microsoft Visual C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Borland Delphi 2.0]]
pattern = EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB
at = entrypoint
type = packer
version = 1.10
options = Borland Delphi 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [MASM32/TASM32/Microsoft Visual Basic]]
pattern = F7 D8 0F BE C2 BE ?? ?? ?? ?? 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94
at = entrypoint
type = packer
version = 1.10
options = MASM32/TASM32/Microsoft Visual Basic
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [MASM32/TASM32]]
pattern = 03 F7 23 FE 33 FB EB 02 CD 20 BB ?? ?? ?? ?? EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B
at = entrypoint
type = packer
version = 1.10
options = MASM32/TASM32
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [MASM32]]
pattern = EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A
at = entrypoint
type = packer
version = 1.10
options = MASM32
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual Basic/MASM32]]
pattern = EB 02 09 94 0F B7 FF 68 ?? ?? ?? ?? 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual Basic/MASM32
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual Basic 5.0/6.0]]
pattern = C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 ?? ?? EF 80 F3 F6 2B C1 EB 01 DE 68 77
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual Basic 5.0/6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 4.X/LCC Win32 1.X]]
pattern = 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 4.X/LCC Win32 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 5.0/6.0]]
pattern = 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 5.0/6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0/7.0/ASM]]
pattern = E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB ?? ?? ?? ?? 8B FA EB 01 A8
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0/7.0/ASM
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0/7.0]]
pattern = 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 ?? ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0/7.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0/7.0]]
pattern = 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0/7.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0/7.0]]
pattern = F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0/7.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0/7.0]]
pattern = F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0/7.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0/ASM]]
pattern = F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0/ASM
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0]]
pattern = 03 DE EB 01 F8 B8 ?? ?? ?? ?? EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0]]
pattern = 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0]]
pattern = C1 CE 10 C1 F6 0F 68 ?? ?? ?? ?? 2B FA 5B 23 F9 8D 15 ?? ?? ?? ?? E8 01 00 00 00 B6 5E 0B
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0]]
pattern = E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE ?? ?? ?? ?? EB 02 61 E9 68 F4 00 00 00 C1 C8
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0]]
pattern = EB 01 4D 83 F6 4C 68 ?? ?? ?? ?? EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0]]
pattern = EB 02 AB 35 EB 02 B5 C6 8D 05 ?? ?? ?? ?? C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.10 [Microsoft Visual C++ 6.0]]
pattern = EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00
at = entrypoint
type = packer
version = 1.10
options = Microsoft Visual C++ 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.20 [Borland C++]]
pattern = C1 F0 07 EB 02 CD 20 BE ?? ?? ?? ?? 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F
at = entrypoint
type = packer
version = 1.20
options = Borland C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.20 [Borland Delphi/Borland C++]]
pattern = 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C1 F1 15 33 F7 80
at = entrypoint
type = packer
version = 1.20
options = Borland Delphi/Borland C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.20 [Borland Delphi/Microsoft Visual C++]]
pattern = 0F B6 D0 E8 01 00 00 00 0C 5A B8 ?? ?? ?? ?? EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E
at = entrypoint
type = packer
version = 1.20
options = Borland Delphi/Microsoft Visual C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.20 [MASM32/TASM32]]
pattern = 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9
at = entrypoint
type = packer
version = 1.20
options = MASM32/TASM32
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.20 [Microsoft Visual C++ 6.0/7.0]]
pattern = EB 02 CD 20 EB 01 91 8D 35 ?? ?? ?? ?? 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D
at = entrypoint
type = packer
version = 1.20
options = Microsoft Visual C++ 6.0/7.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.20 [Microsoft Visual C++ 6.0]]
pattern = C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE ?? ?? ?? ?? 49 EB 01 99 8D 1D F4 00 00 00 EB 01
at = entrypoint
type = packer
version = 1.20
options = Microsoft Visual C++ 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.31]
pattern = BB ?? ?? ?? ?? BF ?? ?? ?? ?? BE ?? ?? ?? ?? 53 BB ?? ?? ?? ?? B2 80 A4 B6 80 FF D3 73 F9
at = entrypoint
type = packer
version = 1.31
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.33]
pattern = BE ?? ?? ?? ?? AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73
at = entrypoint
type = packer
version = 1.33
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 1.3.3]
pattern = BE ?? ?? ?? ?? AD 97 AD 56 96 83 CD ?? EB
at = entrypoint
type = packer
version = 1.3.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

[FSG 2.0]
pattern = 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 ?? FF 13
at = entrypoint
type = packer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_FSG.2.sg

; packer_hmimys.2.sg
[hmimys 1.0]
pattern = 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_hmimys.2.sg

[hmimys 0.1]
pattern = 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8
at = entrypoint
type = packer
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_hmimys.2.sg

[hmimys 1.0]
pattern = E8 BA 00 00 00 ?? 00 00 00 00 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? 00 00 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_hmimys.2.sg

[hmimys 0.1]
pattern = BA ?? ?? ?? ?? FF E2 BA ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 02 83 C2 ?? B8 ?? ?? ?? ?? 89 02 83 C2 ?? FF E2
at = entrypoint
type = packer
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_hmimys.2.sg

[hmimys 0.1]
pattern = E8 00 00 00 00 5D 83 ED 05 6A 00 FF 95 E1 0E 00 00 89 85 85 0E 00 00 8B 58 3C 03 D8 81 C3 F8 00 00 00
at = entrypoint
type = packer
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_hmimys.2.sg

[hmimys 1.2]
pattern = E8 $$$$$$$$ 5E AD 50 AD 50 97 AD 50 AD 50 AD 50 E8 C0 01 00 00 AD 50 AD 93 87 DE B9
at = entrypoint
type = packer
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_hmimys.2.sg

[hmimys 1.3]
pattern = E8
at = entrypoint
section = hmimys
type = packer
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_hmimys.2.sg

; packer_HTML_executable.1.sg
[HTML Executable]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3
at = entrypoint
pattern.2 = 'GHE32'
at.2 = overlay
type = packer
lang = HTML
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_HTML_executable.1.sg

[HTML Executable]
pattern = 55 8B EC B9 ?? ?? ?? ?? 6A ?? 6A ?? 49 75 ?? 53 56 57 B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3
at = entrypoint
pattern.2 = 'HEEG'
at.2 = overlay
type = packer
lang = HTML
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_HTML_executable.1.sg

; packer_hXOR.2.sg
[hXOR 0.1]
pattern = 55 89 E5 83 EC 18 C7 04 24 02 00 00 00 FF 15 38 42 41 00 E8 F8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 18 C7 04 24 01 00 00 00 FF 15 38 42 41 00 E8 D8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D
at = entrypoint
type = packer
version = 0.1
author = KDSS-Research
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_hXOR.2.sg

; packer_JDPack.2.sg
[JDPack 1.01]
pattern = 60 E8 00 00 00 00 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 06 ?? ?? ?? 89 95 ?? ?? ?? ?? 83 BD
at = entrypoint
type = packer
version = 1.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_JDPack.2.sg

[JDPack 2.00]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 ?? ?? ?? E8 01 00 00 00
at = entrypoint
type = packer
version = 2.00
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_JDPack.2.sg

; packer_KByS.2.sg
[KByS 0.28b]
pattern = 60 E8 00 00 00 00 5E 83 EE 0A 8B 06 03 C2 8B 08 89 4E F3 83 EE 0F 56 52 8B F0 AD AD 03 C2 8B D8 6A 04 BF 00 10 00 00
at = entrypoint
type = packer
version = 0.28b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_KByS.2.sg

[KByS 0.28]
pattern = 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4
at = entrypoint
type = packer
version = 0.28
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_KByS.2.sg

[KByS 0.28]
pattern = B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 03 C2 FF E0 ?? ?? ?? ?? 60 E8 00 00 00 00
at = entrypoint
type = packer
version = 0.28
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_KByS.2.sg

[KByS 0.28b]
pattern = 68 ?? ?? ?? ?? 90 B8 ?? ?? ?? ?? C3 60 8B 74 24 ?? 8B 7C 24
at = entrypoint
type = packer
version = 0.28b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_KByS.2.sg

; packer_kkrunchy.2.sg
[kkrunchy 0.23 alpha 2 [modified]]
pattern = BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 45 04 89 45 54 50 C7 45 10
at = entrypoint
section = !kkrunchy
type = packer
version = 0.23 alpha 2
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_kkrunchy.2.sg

[kkrunchy 0.23 alpha 2]
pattern = BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 45 04 89 45 54 50 C7 45 10
at = entrypoint
section = kkrunchy
type = packer
version = 0.23 alpha 2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_kkrunchy.2.sg

[kkrunchy 0.2X [modified]]
pattern = BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF
at = entrypoint
section = !kkrunchy
type = packer
version = 0.2X
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_kkrunchy.2.sg

[kkrunchy 0.2X]
pattern = BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF
at = entrypoint
section = kkrunchy
type = packer
version = 0.2X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_kkrunchy.2.sg

[kkrunchy [modified]]
pattern = BD ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? FC FF 4D 08 31 D2 8D 7D 30 BE
at = entrypoint
section = !kkrunchy
type = packer
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_kkrunchy.2.sg

[kkrunchy]
pattern = BD ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? FC FF 4D 08 31 D2 8D 7D 30 BE
at = entrypoint
section = kkrunchy
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_kkrunchy.2.sg

[kkrunchy [modified]]
pattern = 'MZfarbrauschPE'
at = image
section = !kkrunchy
type = packer
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_kkrunchy.2.sg

[kkrunchy]
pattern = 'MZfarbrauschPE'
at = image
section = kkrunchy
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_kkrunchy.2.sg

; packer_longwasu.2.sg
[longwasu]
pattern = E8 C5 03 00 00 E9 74 FE FF FF 55 8B EC 6A 00 FF 15 10 20 40 00 FF 75 08 FF 15 3C 20 40 00
at = entrypoint
requires = pe32, rich
section = .packed
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_longwasu.2.sg

; packer_MEW.2.sg
[MEW 1.0]
pattern = 33 C0 E9 $$$$$$$$ BE ?? ?? ?? ?? AC 91 AD 95 AD 92 AD 51 56 87 F2 97 FC B2 ?? 33 DB A4 B3 ?? FF 55
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MEW.2.sg

[MEW SE 1.0]
pattern = E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C
at = entrypoint
type = packer
version = SE 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MEW.2.sg

[MEW SE 1.1-1.2]
pattern = E9 $$$$$$$$ BE ?? ?? ?? ?? 8B DE AD AD 50 AD 97 B2
at = entrypoint
type = packer
version = SE 1.1-1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MEW.2.sg

[MEW]
pattern = BE 5B 00 ?? ?? AD 91 AD 93 53 AD 96 56 5F AC C0 C0
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MEW.2.sg

[MEW 10 1.0]
pattern = 2B C0 E9 D0 90 FF FF 6A E0 E8 38 2B 23 70 0E A3 1C 50 40 18 18 68 24 51 10 07 E5 65 F8 E8 AF 70 22 DD 15 D8 02 3B 55 8B 00 EC 53 57 56 81 7D 0C 10 60
at = entrypoint
type = packer
version = 10 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MEW.2.sg

; packer_mkfPack.2.sg
[mkfPack]
pattern = E8 $$$$$$$$ 5B 81 EB ?? ?? ?? ?? 8B 93 ?? ?? ?? ?? 53 6A ?? 68 ?? ?? ?? ?? 52 6A ?? FF 93 ?? ?? ?? ?? 5B 8B F0 8B BB ?? ?? ?? ?? 03 FB 56 57 E8 ?? ?? ?? ?? 83 C4 ?? 8D 93 ?? ?? ?? ?? 52 53 FF E6
at = entrypoint
type = packer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_mkfPack.2.sg

; packer_MoleBox.2.sg
[MoleBox 2.3.3-2.6.4]
pattern = E8 00 00 00 00 60 E8 $$$$$$$$ E8 $$$$$$$$ E8 $$$$$$$$ 55 8B EC 83 EC ?? 56 57 6A ?? FF 15 ?? ?? ?? ?? 89 45 ?? 68 ?? ?? ?? ?? 6A ?? FF 15
at = entrypoint
type = packer
version = 2.3.3-2.6.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MoleBox.2.sg

[MoleBox 2.3.3-2.6.4]
pattern = E8 00 00 00 00 60 E8 $$$$$$$$ E8 $$$$$$$$ 8B 44 24 ?? 50 8B 44 24 ?? 50 E8 $$$$$$$$ 55 8B EC 83 EC ?? 53 56 57 6A ?? FF 15
at = entrypoint
type = packer
version = 2.3.3-2.6.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MoleBox.2.sg

[MoleBox 2.0.0-2.3.0]
pattern = 60 E8 $$$$$$$$ E8 $$$$$$$$ E8 $$$$$$$$ 55 8B EC 83 EC ?? 56 57 6A ?? FF 15 ?? ?? ?? ?? 89 45 ?? 68 ?? ?? ?? ?? 6A ?? FF 15
at = entrypoint
type = packer
version = 2.0.0-2.3.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MoleBox.2.sg

[MoleBox 2.36]
pattern = EB $$ B8 ?? ?? ?? ?? 83 38 ?? 74 ?? 50 FF 70 ?? FF 30 50 83 04 24 ?? E8 $$$$$$$$ 55 8B EC A1 ?? ?? ?? ?? 53 56 8B 75 ?? 85 C0 57 8B DE 75 ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15
at = entrypoint
type = packer
version = 2.36
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MoleBox.2.sg

; packer_mPack.2.sg
[mPack 0.0.2]
pattern = E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 E8 AA 00 00 00 4E
at = entrypoint
type = packer
version = 0.0.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_mPack.2.sg

[mPack 0.0.3]
pattern = 55 8B EC 83 ?? ?? 33 C0 89 45 F0 B8 ?? ?? ?? ?? E8 67 C4 FF FF 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF
at = entrypoint
type = packer
version = 0.0.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_mPack.2.sg

; packer_MPRESS.2.sg
[MPRESS]
pattern = ( 'It\'s .NET EXE' | 'Win32 .EXE.\x0D\x0A' | 'Win64 .EXE.\x0D\x0A' | 'Win32 .DLL.\x0D\x0A' | 'Win64 .DLL.\x0D\x0A' )
at = image + 0x2E
type = packer
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg
x-die-loss = version read from file

[MPRESS 0.71-0.75]
pattern = 57 56 53 51 52 55 E8 $$$$$$$$ E8 $$$$$$$$ 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 ?? 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 ?? 74 ?? 88 04 31 EB
at = entrypoint
requires = native
type = packer
version = 0.71-0.75
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg

[MPRESS 0.77]
pattern = 60 E8 $$$$$$$$ E8 $$$$$$$$ 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 ?? 8B C8 AD 2B C8 03 F1 8B C8 49 8A 44 39 ?? 74 ?? 88 04 31 EB
at = entrypoint
requires = native
type = packer
version = 0.77
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg

[MPRESS 0.85-0.97]
pattern = 60 E8 $$$$$$$$ 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 ?? 8B C8 50 AD 2B C8 03 F1 8B C8 57 49 8A 44 39 ?? 74 ?? 88 04 31 EB
at = entrypoint
requires = native
type = packer
version = 0.85-0.97
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg

[MPRESS 1.27]
pattern = 60 E8 $$$$$$$$ 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 ?? 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 ?? 74 ?? 88 04 31 EB
at = entrypoint
requires = native
type = packer
version = 1.27
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg

[MPRESS 2.01-2.12]
pattern = 60 E8 $$$$$$$$ 58 05 ?? ?? ?? ?? 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 ?? 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 ?? 88 04 31 75
at = entrypoint
requires = native
type = packer
version = 2.01-2.12
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg

[MPRESS 0.71-0.92]
pattern = 57 56 53 51 52 41 50 E8 $$$$$$$$ 48 8D 05 ?? ?? ?? ?? 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 ?? 48 8B C8 AD 2B C8 48 03 F1 8B C8 FF C9 8A 44 39 ?? 74 ?? 88 04 31 EB
at = entrypoint
requires = native, pe32+
type = packer
version = 0.71-0.92
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg

[MPRESS 0.97]
pattern = 57 56 53 51 52 41 50 48 8D 05 ?? ?? ?? ?? 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 ?? 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 FF C9 8A 44 39 ?? 74 ?? 88 04 31 EB
at = entrypoint
requires = native, pe32+
type = packer
version = 0.97
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg

[MPRESS 1.27-2.12]
pattern = 57 56 53 51 52 41 50 48 8D 05 ?? ?? ?? ?? 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 ?? 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 ?? 88 04 31 75
at = entrypoint
requires = native, pe32+
type = packer
version = 1.27-2.12
author = ajax, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_MPRESS.2.sg

; packer_Mystic_Compressor.2.sg
[Mystic Compressor]
pattern = 55 8B EC 83 EC ?? 6A ?? FF 35 ?? ?? ?? ?? 6A ?? FF 15 ?? ?? ?? ?? 8D 55 ?? 52 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A ?? FF 35
at = entrypoint
type = packer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Mystic_Compressor.2.sg

[Mystic Compressor]
pattern = 55 8B EC 83 C4 ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 89 45 ?? 68 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? 89 45 ?? 8D 55 ?? 52 6A ?? 68
at = entrypoint
type = packer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Mystic_Compressor.2.sg

; packer_NakedPacker.2.sg
[NakedPacker 1.0 [by BigBoote]]
pattern = 60 FC 0F B6 05 ?? ?? ?? ?? ?? ?? 75 31 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9A 00 00 00 A3
at = entrypoint
type = packer
version = 1.0
options = by BigBoote
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NakedPacker.2.sg

[NakedPacker]
pattern = 60
at = entrypoint
section = .naked1
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NakedPacker.2.sg

; packer_NeoLite.2.sg
[NeoLite 1.0]
pattern = 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 1.0]
pattern = E9 $$$$$$$$ 8B 44 ?? ?? 23 05 ?? ?? ?? ?? E8 $$$$$$$$ 53 51 52 56 57 C8 ?? ?? ?? 50 81 ED ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 8B 1D
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 1.0]
pattern = E9
at = entrypoint
pattern.2 = 'NeoLite'
at.2 = entrypoint + 0x1D
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 1.0]
pattern = E9
at = entrypoint
pattern.2 = 'NeoLite'
at.2 = entrypoint + 0x21
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 2.0]
pattern = E9 A6 00 00 00
at = entrypoint
type = packer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 2.0]
pattern = 8B 44 24 04 23 05 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 FE 05 ?? ?? ?? ?? 0B C0 74
at = entrypoint
type = packer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 1.01]
pattern = E9 $$$$$$$$ 8B 44 24 ?? 8D 54 24 ?? 2E 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 09 C0 74 ?? 2E FF 35
at = entrypoint
type = packer
version = 1.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 1.01]
pattern = E9 $$$$$$$$ E9 $$$$$$$$ 8B 44 24 ?? 8D 54 24 ?? 2E 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 09 C0 74 ?? 2E FF 35
at = entrypoint
type = packer
version = 1.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite]
pattern = E9 $$$$$$$$ E9 $$$$$$$$ 8B 44 24 ?? 8D 54 24 ?? 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 2.0]
pattern = E9 $$$$$$$$ 8B 44 24 ?? 8D 54 24 ?? 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25
at = entrypoint
type = packer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

[NeoLite 2.0]
pattern = E9 $$$$$$$$ 8B 44 24 ?? 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FE 05 ?? ?? ?? ?? FF E0
at = entrypoint
type = packer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NeoLite.2.sg

; packer_NetPacker.2.sg
[NetPacker]
requires = dotnet
dotnet_us = Packed.exetemp_c.dat
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NetPacker.2.sg

; packer_netshrink.2.sg
[.netshrink 2.01 Demo [Encrypted/Password mode]]
pattern = 20 FE 2B 13 60 28 ?? ?? ?? ?? 13 ?? 20 3B 28 13 60 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 16 1F 40 28 ?? ?? ?? ?? 26
in = section(#0)
requires = dotnet
dotnet_string = " "
type = packer
version = 2.01 Demo
options = Encrypted/Password mode
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_netshrink.2.sg

[.netshrink 2.01 Demo [Encrypted/Password mode]]
pattern = 20 AD 65 13 32 28 ?? ?? ?? ?? 13 ?? 20 68 66 13 32 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 16 1F 40 28 ?? ?? ?? ?? 26
in = section(#0)
requires = dotnet
dotnet_string = " "
type = packer
version = 2.01 Demo
options = Encrypted/Password mode
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_netshrink.2.sg

[.netshrink 2.01 Demo]
pattern = 20 B9 05 9F 07 28 ?? ?? ?? ?? 13 ?? 20 66 05 9F 07 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 16 1F 40 28 ?? ?? ?? ?? 26
in = section(#0)
requires = dotnet
dotnet_string = " "
type = packer
version = 2.01 Demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_netshrink.2.sg

[.netshrink 2.01 Demo]
pattern = 20 E6 EA 19 BE 28 ?? ?? ?? ?? 13 ?? 20 39 EA 19 BE 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 16 1F 40 28 ?? ?? ?? ?? 26
in = section(#0)
requires = dotnet
dotnet_string = " "
type = packer
version = 2.01 Demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_netshrink.2.sg

[.netshrink 2.9+]
pattern = 'stub_2.netrsrc.resources'
in = section(#0)
requires = dotnet
dotnet_string = " "
type = packer
version = 2.9+
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_netshrink.2.sg

; packer_NETZ.2.sg
[.NETZ]
pattern = 00 'NetzStarter' 00 'netz' 00
in = section(#0)
dotnet_string = NetzStarter
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NETZ.2.sg

; packer_NodeJS_Nexe.2.sg
[nexe]
pattern = 'nexe~~sentinel'
in = section(#1)
export = napi_wrap
requires = overlay
type = packer
lang = JavaScript
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NodeJS_Nexe.2.sg
x-die-loss = the overlay size (at least 0x100) is not checked

; packer_NodeJS_Pkg.2.sg
[pkg]
pattern = 'pkg/prelude/bootstrap.js'
in = section(#1)
export = napi_wrap
requires = overlay
type = packer
lang = JavaScript
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NodeJS_Pkg.2.sg
x-die-loss = the overlay size (at least 0x100) is not checked

; packer_NOS_Packer.2.sg
[NOS Packer]
pattern = 50 E8 00 00 00 00 5B 81 EB ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B D9 8B F3 81 EB ?? ?? ?? ?? 8B FB 81 EB ?? ?? ?? ?? 57 51 56 E8 ?? ?? ?? ?? 83 C4 ?? 8B AB ?? ?? ?? ?? 8D 2C 2B 4D 8A 4D ?? 80 F9 ?? 74 ?? 83 ED ?? 8B D3 2B 53
at = entrypoint
type = packer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NOS_Packer.2.sg

; packer_nPack.2.sg
[nPack 1.1.150.2006.Beta]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8
at = entrypoint
pattern.2 = E0 01 00 00 E8 EC 06
at.2 = entrypoint + 0x2A
section = .nPack
type = packer
version = 1.1.150.2006.Beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.150.2006.Beta [modified]]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8
at = entrypoint
pattern.2 = E0 01 00 00 E8 EC 06
at.2 = entrypoint + 0x2A
section = !.nPack
type = packer
version = 1.1.150.2006.Beta
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.200.2006.Beta]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8
at = entrypoint
pattern.2 = EC 01 00 00 E8 F8 06
at.2 = entrypoint + 0x2A
section = .nPack
type = packer
version = 1.1.200.2006.Beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.200.2006.Beta [modified]]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8
at = entrypoint
pattern.2 = EC 01 00 00 E8 F8 06
at.2 = entrypoint + 0x2A
section = !.nPack
type = packer
version = 1.1.200.2006.Beta
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.XXX]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8
at = entrypoint
section = .nPack
type = packer
version = 1.1.XXX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.XXX [modified]]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 5E 00 00 00 E8
at = entrypoint
section = !.nPack
type = packer
version = 1.1.XXX
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.250.2006.Beta]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8
at = entrypoint
pattern.2 = 04 02 00 00
at.2 = entrypoint + 0x2F
section = .nPack
type = packer
version = 1.1.250.2006.Beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.250.2006.Beta [modified]]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8
at = entrypoint
pattern.2 = 04 02 00 00
at.2 = entrypoint + 0x2F
section = !.nPack
type = packer
version = 1.1.250.2006.Beta
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.300.2006.Beta]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8
at = entrypoint
pattern.2 = 2D 02 00 00
at.2 = entrypoint + 0x2F
section = .nPack
type = packer
version = 1.1.300.2006.Beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.300.2006.Beta [modified]]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8
at = entrypoint
pattern.2 = 2D 02 00 00
at.2 = entrypoint + 0x2F
section = !.nPack
type = packer
version = 1.1.300.2006.Beta
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.800.2008.Beta]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8
at = entrypoint
pattern.2 = 48 02 00 00
at.2 = entrypoint + 0x2F
section = .nPack
type = packer
version = 1.1.800.2008.Beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.800.2008.Beta [modified]]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8
at = entrypoint
pattern.2 = 48 02 00 00
at.2 = entrypoint + 0x2F
section = !.nPack
type = packer
version = 1.1.800.2008.Beta
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.XXX]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8
at = entrypoint
section = .nPack
type = packer
version = 1.1.XXX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack 1.1.XXX [modified]]
pattern = 83 3D ?? ?? ?? ?? ?? 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 9C 00 00 00 E8
at = entrypoint
section = !.nPack
type = packer
version = 1.1.XXX
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg

[nPack]
pattern = 83 3C 24 ?? 0F 84 ?? ?? ?? ?? 8D 64 24
at = entrypoint
section = .nPack
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg
x-die-loss = import hash of the first import library not checked

[nPack [modified]]
pattern = 83 3C 24 ?? 0F 84 ?? ?? ?? ?? 8D 64 24
at = entrypoint
section = !.nPack
type = packer
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_nPack.2.sg
x-die-loss = import hash of the first import library not checked

; packer_NsPack.2.sg
[NsPack 3.7]
pattern = 9C 60 E8 ?? ?? ?? ?? ?? 83 ?? ?? 8D 8D ?? ?? ?? ?? 80 39 ?? 0F ?? ?? ?? ?? ?? C6 01 ?? 8B C5
at = entrypoint
type = packer
version = 3.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NsPack.2.sg

[NsPack 3.1]
pattern = 9C 60 E8 ?? ?? ?? ?? 5D 83 ED ?? 8D 9D ?? ?? ?? ?? 8A 03 3C ?? 74 ?? 8D 9D ?? ?? ?? ?? 8A 03
at = entrypoint
type = packer
version = 3.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NsPack.2.sg

[NsPack 3.6]
pattern = 9C 60 E8 ?? ?? ?? ?? 5D 83 ED ?? 8D 85 ?? ?? ?? ?? 83 38 ?? 0F ?? ?? ?? ?? ?? C7 00 ?? ?? ?? ?? 8B D5
at = entrypoint
type = packer
version = 3.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NsPack.2.sg

[NsPack 3.5]
pattern = 9C 60 E8 ?? ?? ?? ?? 5D 83 ED ?? 8D 85 ?? ?? ?? ?? 80 38 ?? 0F ?? ?? ?? ?? ?? C6 00 ?? 8B D5
at = entrypoint
type = packer
version = 3.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NsPack.2.sg

[NsPack 2.9]
pattern = 9C 60 E8 ?? ?? ?? ?? 5D B8 ?? ?? ?? ?? 2B E8 8D B5 ?? ?? ?? ?? 8A 06 3C ?? 74 ?? 8B F5
at = entrypoint
type = packer
version = 2.9
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NsPack.2.sg

[NsPack 2.3-2.9]
pattern = E9 $$$$$$$$ E9 $$$$$$$$ E9 $$$$$$$$ 9C 60 E8 ?? ?? ?? ?? 5D B8 ?? ?? ?? ?? 2B E8 8D B5 ?? ?? ?? ?? 8B 06
at = entrypoint
type = packer
version = 2.3-2.9
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NsPack.2.sg

[NsPack 3.3]
pattern = 9C 60 E8 ?? ?? ?? ?? 5D 83 ED ?? 8D 85 ?? ?? ?? ?? 80 38 ?? 74 ?? 8D 85 ?? ?? ?? ?? 80 38 ?? 0F 84 ?? ?? ?? ?? C6 00 ?? 8B D5
at = entrypoint
type = packer
version = 3.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NsPack.2.sg

; packer_NTPacker.2.sg
[NTPacker 1.0]
pattern = 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 ?? ?? ?? ?? E8 ?? ?? FF FF 33 C0 55 68
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NTPacker.2.sg

[NTPacker 2.0]
pattern = 4B 57 69 6E 64 6F 77 73 00 10 55 54 79 70 65 73 00 00 3F 75 6E 74 4D 61 69 6E 46 75 6E 63 74 69 6F 6E 73 00 00 47 75 6E 74 42 79 70 61 73 73 00 00 B7 61 50 4C 69 62 75 00 00 00
at = entrypoint
type = packer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NTPacker.2.sg

; packer_NTShell.2.sg
[NTSHELL 5.0]
pattern = 55 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? EB $$ EB $$ 8D 85 ?? ?? ?? ?? 8D BD ?? ?? ?? ?? EB $$ 8D B5 ?? ?? ?? ?? EB $$ 8B CF EB $$ 2B C8 4F FD EB $$ 33 DB EB $$ 8A 07 EB $$ D2 C8 EB $$ 2A ?? ?? EB $$ E8
at = entrypoint
type = packer
version = 5.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_NTShell.2.sg

; packer_Nuitka.2.sg
[Nuitka]
pattern = '__nuitka_version__'
in = section(.rdata)
import = /^python/
type = packer
lang = Python
author = KDSS-Research, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Nuitka.2.sg
x-die-loss = version read from file (name of the python DLL)

[Nuitka [OneFile]]
pattern = 'NUITKA_ONEFILE_PARENT'
in = section(.rdata)
type = packer
options = OneFile
lang = Python
author = KDSS-Research, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Nuitka.2.sg

; packer_Origami.2.sg
[Origami]
requires = dotnet
dotnet_string = EntryPointNotFoundException
dotnet_us = Origami could not find a valid EntryPoint to invoke
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Origami.2.sg

; packer_Pack_Master.2.sg
[Pack Master 1.0]
pattern = 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED ?? ?? ?? ?? E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Pack_Master.2.sg

; packer_Packanoid.2.sg
[Packanoid 1.0]
pattern = BF ?? ?? ?? ?? BE ?? ?? ?? ?? E8 9D 00 00 00 B8 ?? ?? ?? ?? 8B 30 8B 78 04 BB
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Packanoid.2.sg

; packer_Packed_Infected_PE.2.sg
[Packed-Infected-PE]
pattern = 55 89 E5 81 EC C8 00 00 00 31 C0 31 DB 64 A1 30 00 00 00 8A 58 02 83 FB 00
at = entrypoint
requires = pe32
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Packed_Infected_PE.2.sg

[Packed-Infected-PE]
pattern = AA 76 1A 7C 13 B7 38 BA 0B 68 48 BF FF 74 BA 0B
in = section(.infect)
requires = pe32
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Packed_Infected_PE.2.sg

; packer_Packman.2.sg
[Packman 0.0.0.1]
pattern = 0F 85 ?? FF FF FF 8D B3 ?? ?? ?? ?? EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36
at = entrypoint
type = packer
version = 0.0.0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Packman.2.sg

[Packman 0.0.0.1]
pattern = 60 E8 00 00 00 00 58 8D ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 8D
at = entrypoint
type = packer
version = 0.0.0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Packman.2.sg

[Packman 1.0]
pattern = 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Packman.2.sg

; packer_Packter.2.sg
[Packter]
pattern = 55 B9 60 00 00 00 48 89 E5 41 57 41 56
at = entrypoint
section = .pack, .stub
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Packter.2.sg
x-die-loss = .stub is not checked to be the last section

; packer_PACKWIN.2.sg
[PACKWIN 1.01p]
pattern = 8C C0 FA 8E D0 BC ?? ?? FB 06 0E 1F 2E ?? ?? ?? ?? 8B F1 4E 8B FE 8C DB 2E ?? ?? ?? ?? 8E C3 FD F3 A4 53 B8 ?? ?? 50 CB
at = entrypoint
type = packer
version = 1.01p
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PACKWIN.2.sg

; packer_PE-PACK.sg
[PE-PACK 0.99]
pattern = 60 E8 00 00 00 00 5D 83 ED ?? 80 BD ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8B C5 2B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 89
at = entrypoint
type = packer
version = 0.99
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PE-PACK.sg

[PE-PACK 1.0]
pattern = 74 ?? E9 $$$$$$$$ 60 E8 ?? ?? ?? ?? 5D 83 ED ?? 80 ?? ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? ?? 8B C5 2B ?? ?? ?? ?? ?? 89
at = entrypoint
type = packer
version = 1.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PE-PACK.sg

; packer_PE64shell.2.sg
[PE64shell]
section = .coleak
requires = native
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PE64shell.2.sg
x-die-loss = .coleak must be the last section and read/write/execute, and the file must have no imports

; packer_PE_File_Packer.2.sg
[PE File Packer]
pattern = ?? C0 ED FE 00 DA ED FE 00 DA ED FE CC CC CC CC
in = section(.araara)
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PE_File_Packer.2.sg

; packer_PE_Runtime_Packer.2.sg
[PE Runtime Packer]
pattern = 65 48 8B 04 25 60 00 00 00 48 8B 40 10 48 8D B0 00 10 00 00 B9 ?? ?? ?? ?? B3 ?? 30 1E 48 FF C6 FF C9
at = entrypoint
requires = pe32+
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PE_Runtime_Packer.2.sg

; packer_PECompact.2.sg
[PECompact 0.90-0.92]
pattern = EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5
at = entrypoint
type = packer
version = 0.90-0.92
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 0.94]
pattern = EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02
at = entrypoint
type = packer
version = 0.94
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 1.68-1.84]
pattern = EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85
at = entrypoint
type = packer
version = 1.68-1.84
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 1.00-1.3X]
pattern = EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85
at = entrypoint
type = packer
version = 1.00-1.3X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 1.00-1.3X]
pattern = EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85
at = entrypoint
type = packer
version = 1.00-1.3X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 1.84]
pattern = 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81
at = entrypoint
type = packer
version = 1.84
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.0 beta]
pattern = B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90
at = entrypoint
type = packer
version = 2.0 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.X beta version]
pattern = B8 ?? ?? ?? ?? 80 00 28 40
at = entrypoint
type = packer
version = 2.X beta version
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.02.2 or 3.03.21 beta]
pattern = B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00
at = entrypoint
type = packer
version = 3.02.2 or 3.03.21 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.20-3.02]
pattern = B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08
at = entrypoint
type = packer
version = 2.20-3.02
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.X]
pattern = B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC'
at = entrypoint
type = packer
version = 2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.X [Slim Loader]]
pattern = B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC'
at = entrypoint
pattern.2 = 32
at.2 = entrypoint + 0x1B
type = packer
version = 2.X
options = Slim Loader
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.53-2.76]
pattern = B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04
at = entrypoint
type = packer
version = 2.53-2.76
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.78a-3.11]
pattern = B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00
at = entrypoint
type = packer
version = 2.78a-3.11
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact]
pattern = B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.70]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' EE 4E 00 00
in.2 = image[0-0x600]
type = packer
version = 2.70
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.78a]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 10 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.78a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.79b1]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 13 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.79b1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.79bB]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 15 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.79bB
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.79bD]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 17 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.79bD
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.80+]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 1A 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.80+
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.80b1]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 1C 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.80b1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.80b5]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 20 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.80b5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.82]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 25 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.82
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.92.0]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 3D 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.92.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.93b3]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 40 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.93b3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.96.2]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 46 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.96.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.97b1]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 47 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.97b1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.98]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 48 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.98
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.98.04]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 4C 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.98.04
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.98.05]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 4D 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.98.05
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.98.06]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 4E 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.98.06
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.99b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 4F 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 2.99b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.00.2]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 54 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.00.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.01.3]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 58 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.01.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.02.1]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 5D 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.02.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.02.2]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 5E 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.02.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.5b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 63 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.5b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.9b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 67 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.9b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.10b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 69 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.10b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.12b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 6E 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.12b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.18b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 76 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.18b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.19b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 77 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.19b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.20b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 78 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.20b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.21b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 79 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.21b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 3.03.23b]
pattern = ( EB 06 68 ?? ?? ?? ?? C3 9C 60 BD ?? ?? ?? ?? B9 02 ?? ?? ?? B0 90 8D BD ?? ?? ?? ?? F3 AA 01 AD ?? ?? ?? ?? FF B5 | EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 ?? ?? ?? ?? 5D 55 58 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 50 B9 02 | EB $$ 9C 60 E8 $$$$$$$$ 8B C4 83 ?? ?? 93 8B E3 8B ?? ?? 81 EB ?? ?? ?? ?? 87 DD 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 83 C4 ?? 8B 44 24 ?? 50 50 5B 5D 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | EB $$ 9C 60 E8 $$$$$$$$ 5D 55 5B 81 ED ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 01 85 ?? ?? ?? ?? 66 C7 85 | 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 | B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 | B8 ?? ?? ?? ?? 80 00 28 40 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PECompact2' 00 | B8 ?? ?? ?? ?? 50 64 FF ?? ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 33 C0 89 08 | B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 'PEC' | B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 ?? ?? ?? ?? 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 | B8 ?? ?? ?? ?? 50 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 33 C0 89 08 00 00 00 00 | B8 ######## B8 ?? ?? ?? ?? 55 53 51 57 56 52 8D 98 )
at = entrypoint
pattern.2 = 'PEC2' 7C 4F 00 00
in.2 = image[0-0x600]
type = packer
version = 3.03.23b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.X-3.X [.NET]]
pattern = 00 'PEC2XO' 00 00 00 00 00 00 ?? 00 00 ?? '.rsrc' 00
in = image[0-0x200]
requires = dotnet
type = packer
version = 2.X-3.X
options = .NET
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

[PECompact 2.X-3.X [.NET]]
pattern = 'mscoree.dll' 00 00 00 'CorBindToRuntimeEx'
in = section(#0)
requires = dotnet
type = packer
version = 2.X-3.X
options = .NET
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PECompact.2.sg

; packer_PEEP.2.sg
[PE Enhanced Packer (PEEP)]
pattern = 'PKR2' 02
in = section(.packed)
requires = pe32+
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PEEP.2.sg

; packer_PEPacker_levanvn.2.sg
[PE Packer by levanvn]
pattern = 55 8B EC 81 EC 00 01 00 00 C7 45 F4 00 00 40 00 C7 45 ?? 00 10 00 00 8B 45 F4 03 45 ?? 89 45
at = entrypoint
requires = pe32
section = packed
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PEPacker_levanvn.2.sg

; packer_Petite.2.sg
[Petite 1.2]
pattern = 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08
at = entrypoint
type = packer
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 1.2]
pattern = 66 9C 60 E8 $$$$$$$$ 58 2C ?? 50 8B C8 8B D0 81 C1 ?? ?? ?? ?? 81 C2 ?? ?? ?? ?? 89 20 8B E1 50 81
at = entrypoint
type = packer
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 1.3]
pattern = 66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1
at = entrypoint
type = packer
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 1.4]
pattern = 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC
at = entrypoint
type = packer
version = 1.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 2.1-2.3]
pattern = 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8
at = entrypoint
type = packer
version = 2.1-2.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite]
pattern = B8 ?? ?? ?? ?? 66 9C 60 50 8D ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 83
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 1.3, 1.3a]
pattern = B8 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 ?? ?? ?? ?? 8B DC 8B E1 68
at = entrypoint
type = packer
version = 1.3, 1.3a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 2.1]
pattern = B8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50
at = entrypoint
type = packer
version = 2.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 2.2]
pattern = B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 66 9C 60 50
at = entrypoint
type = packer
version = 2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 2.2]
pattern = B8 ?? ?? ?? ?? 66 9C 60 50 33 DB 8D 90 ?? ?? ?? ?? 68 ?? ?? ?? ?? 83 3A ?? 0F 84 ?? ?? ?? ?? 8B 0A
at = entrypoint
type = packer
version = 2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 1.4-2.2]
pattern = B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 ?? 68 ?? ?? ?? ?? 6A ?? FF 50
at = entrypoint
type = packer
version = 1.4-2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

[Petite 2.4]
pattern = B8 ?? ?? ?? ?? 60 8D A8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 40 68 00 30 00 00 68 ?? ?? ?? ?? 6A 00 FF 90 ?? ?? ?? ?? 89 44 24 1C BB ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8B F8 50
at = entrypoint
type = packer
version = 2.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Petite.2.sg

; packer_PeX.2.sg
[PeX 0.99]
pattern = E9 $$$$$$$$ 60 E8 $$$$$$$$ 83 C4 04 E8
at = entrypoint
type = packer
version = 0.99
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PeX.2.sg

; packer_pinkie_pie.2.sg
[pinkie-pie 0.4]
pattern = 64 A1 30 00 00 00 8B 70 08 BB 00 01 00 00 31 C9
in = section(.kucd)
requires = pe32
type = packer
version = 0.4
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_pinkie_pie.2.sg

; packer_PKLITE.2.sg
[PKLITE32 1.1]
pattern = 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 $$$$$$$$ 55 8B EC A1
at = entrypoint
type = packer
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PKLITE.2.sg

[PKLITE32 1.1]
pattern = 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 44 24 ?? 50 E8 $$$$$$$$ 55 8B EC A1
at = entrypoint
type = packer
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PKLITE.2.sg

; packer_pkr_ce1a.2.sg
[pkr_ce1a]
pattern = E8 ?? ?? ?? ?? E9 $$$$$$$$ 6A ?? 68 ?? ?? ?? ?? E8
at = entrypoint
pattern.2 = 00 69 9A F9 74 ?? ?? ?? ?? 96 AA CB 46 00
in.2 = section(#1)
requires = pe32
import = kernel32.dll, /!IsDebuggerPresent$/, /!LoadLibrary[AW]$/
type = packer
author = Yosef Khaled, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_pkr_ce1a.2.sg
x-die-loss = number of sections (>= 4) not checked, KERNEL32.dll is not checked to be the first import library

; packer_ps2exe.2.sg
[PS2EXE]
requires = dotnet
dotnet_us = "^-([^: ]+)[ :]?([^:]*)$"
type = packer
lang = PowerShell
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_ps2exe.2.sg

; packer_py2exe.2.sg
[py2exe]
pattern = 12 34 56 78
at = resource
type = packer
lang = Python
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_py2exe.2.sg

; packer_PyInstaller.2.sg
[PyInstaller]
pattern = 78 DA
at = overlay
pattern.2 = 'PyInstaller: FormatMessageW failed.'
in.2 = section(.rdata)
requires = native
type = packer
lang = Python
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PyInstaller.2.sg
x-die-loss = Python version read from file

[PyInstaller [overlay]]
pattern = 78 DA
at = overlay
pattern.2 = 4D 45 49 0C 0B 0A 0B 0E
in.2 = overlay
requires = native
type = packer
options = overlay
lang = Python
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PyInstaller.2.sg
x-die-loss = Python version read from file

; packer_PyPePacker.2.sg
[PyPePacker]
pattern = 50 4B 03 04 14 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5F 5F 6D 61 69 6E 5F 5F 2E 70 79 0D 0A 66 72 6F 6D 20 50 79 50 65 4C 6F 61 64 65 72 20 69 6D 70 6F 72 74 20 28
at = overlay
import = python3.dll
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_PyPePacker.2.sg

; packer_QuestPowerGUI.2.sg
[Quest PowerGUI [Hide console]]
requires = dotnet, !console
dotnet_string = Quest.PowerGUI.ScriptRunner
type = packer
options = Hide console
lang = PowerShell
author = Arjan Onwezen, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_QuestPowerGUI.2.sg

[Quest PowerGUI]
requires = dotnet, console
dotnet_string = Quest.PowerGUI.ScriptRunner
type = packer
lang = PowerShell
author = Arjan Onwezen, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_QuestPowerGUI.2.sg

; packer_RLPack.2.sg
[RLPack 0.7.3 beta]
pattern = 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8
at = entrypoint
type = packer
version = 0.7.3 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 0.7.3 beta]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8
at = entrypoint
type = packer
version = 0.7.3 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.0 beta]
pattern = 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF
at = entrypoint
type = packer
version = 1.0 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.0 beta]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF
at = entrypoint
type = packer
version = 1.0 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.11-1.14 [aPlib]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF EB
at.2 = entrypoint + 0x18
type = packer
version = 1.11-1.14
options = aPlib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.11-1.14 [aPlib]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF EB
at.2 = entrypoint + 0x23
type = packer
version = 1.11-1.14
options = aPlib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.11-1.14 [LZMA]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF 6A
at.2 = entrypoint + 0x18
type = packer
version = 1.11-1.14
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.11-1.14 [LZMA]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF 6A
at.2 = entrypoint + 0x23
type = packer
version = 1.11-1.14
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.15-1.18 [aPlib]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 00 00 EB
at.2 = entrypoint + 0x1D
type = packer
version = 1.15-1.18
options = aPlib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.15-1.18 [aPlib]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 00 00 EB
at.2 = entrypoint + 0x28
type = packer
version = 1.15-1.18
options = aPlib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.15-1.18 [LZMA]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 00 00 6A
at.2 = entrypoint + 0x1D
type = packer
version = 1.15-1.18
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.15-1.18 [LZMA]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 00 00 6A
at.2 = entrypoint + 0x28
type = packer
version = 1.15-1.18
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.19-1.20 [aPlib]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF E8
at.2 = entrypoint + 0x37
type = packer
version = 1.19-1.20
options = aPlib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.19-1.20 [aPlib]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF E8
at.2 = entrypoint + 0x42
type = packer
version = 1.19-1.20
options = aPlib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.19-1.20 [LZMA]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF 6A
at.2 = entrypoint + 0x37
type = packer
version = 1.19-1.20
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.19-1.20 [LZMA]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF 6A
at.2 = entrypoint + 0x42
type = packer
version = 1.19-1.20
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.17 Full Edition [aPLib]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = EB 0F FF
at.2 = entrypoint + 0x38
type = packer
version = 1.17 Full Edition
options = aPLib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.17 Full Edition [aPLib]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = EB 0F FF
at.2 = entrypoint + 0x43
type = packer
version = 1.17 Full Edition
options = aPLib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.17 Full Edition [LZMA]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 6A 40 68
at.2 = entrypoint + 0x33
type = packer
version = 1.17 Full Edition
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.17 Full Edition [LZMA]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 6A 40 68
at.2 = entrypoint + 0x3E
type = packer
version = 1.17 Full Edition
options = LZMA
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.21 [aPLib]]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF E8
at.2 = entrypoint + 0x3C
type = packer
version = 1.21
options = aPLib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack 1.21 [aPLib]]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
pattern.2 = 33 FF E8
at.2 = entrypoint + 0x47
type = packer
version = 1.21
options = aPLib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack]
pattern = 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack]
pattern = 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04
at = entrypoint
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

[RLPack]
pattern = 60
at = entrypoint
section = .RLPack
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg
x-die-loss = number of imports (1) not checked

[RLPack 1.16-1.21]
pattern = EB $$ 9C 60 E8 ?? ?? ?? ?? 33 C0 8B C4 83 C0 ?? 93 8B E3
at = entrypoint
type = packer
version = 1.16-1.21
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_RLPack.2.sg

; packer_SC_Pack.2.sg
[SC Pack 0.2]
pattern = 55 8B EC 83 C4 ?? 53 56 57 8D 7D ?? 50 E8 ?? ?? ?? ?? 58 25 ?? ?? ?? ?? 05 ?? ?? ?? ?? 89 45
at = entrypoint
type = packer
version = 0.2
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_SC_Pack.2.sg

; packer_scr2exe.2.sg
[SCREEN2EXE/SCREEN2SWF]
pattern = E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B FF 55 8B EC 83 EC ?? 53 56
at = entrypoint
pattern.2 = 'Video created by SCREEN2EXE/SCREEN2SWF'
in.2 = section(.rdata)
requires = pe32
type = packer
author = sendersu, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_scr2exe.2.sg
x-die-loss = version read from file

; packer_SecuPack.2.sg
[SecuPack 1.5 [Soft Stuttgart]]
pattern = 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 00 E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A
at = entrypoint
type = packer
version = 1.5
options = Soft Stuttgart
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_SecuPack.2.sg

; packer_SerGreen_Appacker.2.sg
[SerGreen Appacker 1.XX]
pattern = '<SerGreen>'
at = overlay
requires = dotnet
type = packer
version = 1.XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_SerGreen_Appacker.2.sg

; packer_Simple_Pack.2.sg
[Simple Pack 1.0]
pattern = 60 E8 $$$$$$$$ 5B 8D 5B ?? 6A ?? FF 93 ?? ?? ?? ?? 89 C5 8B 7D ?? 8D 74 ?? ?? 8D BE ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 09 C0 75 ?? 8D 83 ?? ?? ?? ?? 50 6A ?? 68 ?? ?? ?? ?? 55 FF 93
at = entrypoint
type = packer
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Simple_Pack.2.sg

[Simple Pack 1.2X]
pattern = 60 E8 $$$$$$$$ 5B 8D 5B ?? BD ?? ?? ?? ?? 8B 7D ?? 8D 74 ?? ?? 8D BE ?? ?? ?? ?? 0F B7 76 ?? 4E 8B 47 ?? 09 C0 74 ?? 0F B7 47 ?? 09 C0 74 ?? 6A ?? 68 ?? ?? ?? ?? FF 77 ?? 6A ?? FF 93
at = entrypoint
type = packer
version = 1.2X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Simple_Pack.2.sg

[Simple Pack]
pattern = 60 50
at = entrypoint
section = .spack
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Simple_Pack.2.sg

[Simple Pack]
pattern = 55
at = entrypoint
section = .spack
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Simple_Pack.2.sg

; packer_SimpleDpack.2.sg
[SimpleDpack 0.5.1-0.5.3 [x64]]
pattern = 40 55 53 56 57 41 54 41 55 41 56 41 57
at = entrypoint
section = .dpack
type = packer
version = 0.5.1-0.5.3
options = x64
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_SimpleDpack.2.sg

[SimpleDpack 0.5.1-0.5.3 [x86]]
pattern = E8 27 00 00 00 E8 04 01 00 00 A1 28 ?? ?? ?? 03 05 24 ?? ?? ?? 83 25 AC ?? ?? ?? 00 A3 A8 ?? ?? ?? E8 1F 02 00 00 E8 CE FF FF FF
at = entrypoint
section = .dpack
type = packer
version = 0.5.1-0.5.3
options = x86
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_SimpleDpack.2.sg

; packer_SimplePackerByEronana.2.sg
[Eronana]
pattern = 60 68 00 ?? ?? ?? E8 17 FC FF FF 89 45 FC 61 FF 65 FC 00 00 00 00 00 00 00 00 00
at = entrypoint
section = .packer
type = packer
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_SimplePackerByEronana.2.sg

; packer_Sixxpack.2.sg
[Sixxpack 2.2]
pattern = 00 'actmp.dll' 00 'stub' 00 'Sixxpack' 00
in = section(#0)
requires = dotnet
dotnet_us = Data Error
type = packer
version = 2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Sixxpack.2.sg

[Sixxpack 2.4]
pattern = 00 21 ?? ?? ?? 'xpack!' 00 ?? ?? ?? ?? ?? ?? ?? ?? 'xpack' 00
in = section(#0)
requires = dotnet
dotnet_us = Data Error
type = packer
version = 2.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Sixxpack.2.sg

[Sixxpack 2.X]
requires = dotnet
dotnet_us = Data Error
dotnet_string = Sixxpack
type = packer
version = 2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Sixxpack.2.sg

; packer_Software_Compress.2.sg
[Software Compress 1.2]
pattern = E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00
at = entrypoint
type = packer
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Software_Compress.2.sg

[Software Compress 1.4 LITE]
pattern = E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00
at = entrypoint
type = packer
version = 1.4 LITE
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Software_Compress.2.sg

; packer_Squishy.2.sg
[Squishy]
pattern = 55 FC E8 25 00 00 00 48 8D 05 D5 00 00 00 E8 ?? ?? ?? 00 48 8B 05 20 01 00 00 48 8B 1D 21 01 00 00 E8
at = entrypoint
requires = pe32+
section = logicoma
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Squishy.2.sg

; packer_theArk.2.sg
[theArk]
requires = pe32
section = adr, have, 30cm, .tw
type = packer
author = KDSS-Research
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_theArk.2.sg

; packer_TinyLoad.2.sg
[TinyLoad 1.0 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 14 42 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 1.0
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 1.0]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 14 42 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 1.0
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 2.0 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 B4 31 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 2.0
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 2.0]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 B4 31 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 2.0
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 3.0 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 34 52 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 3.0
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 3.0]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 34 52 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 3.0
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 3.1 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 B4 53 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 3.1
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 3.1]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 B4 53 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 3.1
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 4.0 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 F4 63 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 4.0
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 4.0]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 F4 63 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 4.0
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 5.0 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 34 75 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 5.0
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 5.0]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 34 75 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 5.0
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 6.0 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 D4 85 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 6.0
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 6.0]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 D4 85 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 6.0
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.0 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 B4 C5 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 7.0
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.0]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 B4 C5 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 7.0
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.1 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 B4 E6 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 7.1
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.1]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 B4 E6 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 7.1
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.2 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 94 E7 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 7.2
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.2]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 94 E7 0D 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 7.2
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.3 [modified]]
pattern = 48 83 EC 28 48 8D 0D 35 87 0B 00 E8 50 93 01 00 45 31 C0 31 D2 31 C9 E8 64 93 01 00 45 31 C0
at = entrypoint
section = !.pxkey
type = packer
version = 7.3
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.3]
pattern = 48 83 EC 28 48 8D 0D 35 87 0B 00 E8 50 93 01 00 45 31 C0 31 D2 31 C9 E8 64 93 01 00 45 31 C0
at = entrypoint
section = .pxkey
type = packer
version = 7.3
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.4 [modified]]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 D4 39 0E 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = !.pxkey
type = packer
version = 7.4
options = modified
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

[TinyLoad 7.4]
pattern = 55 48 89 E5 48 83 EC 30 C7 45 FC FF 00 00 00 48 8B 05 D4 39 0E 00 C7 00 00 00 00 00 E8 0E 00 00 00 89 45 FC
at = entrypoint
section = .pxkey
type = packer
version = 7.4
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TinyLoad.2.sg

; packer_toxicmouse7.2.sg
[toxicmouse7]
pattern = E8 00 00 00 00 5E 83 EE 05 8B FE 81 E6 00 00 FF
in = section(.packed)
requires = pe32
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_toxicmouse7.2.sg

; packer_TPP_Pack.2.sg
[TPP Pack]
pattern = E8 $$$$$$$$ 5D 81 ED ?? ?? ?? ?? 60 E8 $$$$$$$$ 58 83 C0 ?? FF E0
at = entrypoint
type = packer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_TPP_Pack.2.sg

; packer_Uchiha.2.sg
[Uchiha]
pattern = 90 90 90 68 00 70 40 00 90 90 90 68 00 10 40 00
at = entrypoint
requires = pe32
section = .Uchiha
type = packer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Uchiha.2.sg

; packer_UPX.2.sg
[UPX]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57
at = entrypoint
requires = native, pe32
type = packer
author = horsicq, ajax, adoxa, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_UPX.2.sg
x-die-loss = version and compression options read from file

[UPX]
pattern = 80 7C [25] 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57
at = entrypoint
requires = native, pe32
type = packer
author = horsicq, ajax, adoxa, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_UPX.2.sg
x-die-loss = version and compression options read from file

[UPX 0.70]
pattern = 60 E8 00 00 00 00 58 83 E8 ?? 50 8D B8 ?? ?? ?? ?? 57 8D B0 ?? ?? ?? ?? 83 CD ?? 31 DB 90 90 90 90 01 DB 75
at = entrypoint
requires = native, pe32
type = packer
version = 0.70
author = horsicq, ajax, adoxa, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_UPX.2.sg
x-die-loss = compression options read from file

[UPX]
pattern = 53 56 57 55 48 8D 35 ?? ?? ?? ?? 48 8D BE ?? ?? ?? ?? 57
at = entrypoint
requires = native, pe32+
type = packer
author = horsicq, ajax, adoxa, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_UPX.2.sg
x-die-loss = version and compression options read from file

[UPX]
pattern = 48 89 [22] 53 56 57 55 48 8D 35 ?? ?? ?? ?? 48 8D BE ?? ?? ?? ?? 57
at = entrypoint
requires = native, pe32+
type = packer
author = horsicq, ajax, adoxa, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_UPX.2.sg
x-die-loss = version and compression options read from file

[UPX]
pattern = '$Id: UPX ' **
in = image[0-0x400]
requires = native
type = packer
author = horsicq, ajax, adoxa, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_UPX.2.sg
x-die-loss = version and compression options read from file

[UPX]
pattern = %% %% %% %% 00 'UPX!'
in = image[0-0x400]
requires = native
type = packer
author = horsicq, ajax, adoxa, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_UPX.2.sg
x-die-loss = version and compression options read from file

; packer_VPacker.2.sg
[VPacker 0.02.10]
pattern = 60 E8 $$$$$$$$ 55 8B EC 83 C4 ?? 53 56 57 8B 45 ?? 83 C0 ?? 8B 00 89 45 ?? 83 7D ?? ?? 75 ?? E8 ?? ?? ?? ?? 89 45 ?? E8 ?? ?? ?? ?? 8B 10
at = entrypoint
type = packer
version = 0.02.10
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_VPacker.2.sg

; packer_Windows_PE_Packer_by_Chenzs108.2.sg
[Windows PE Packer by Chenzs108]
pattern = 60 E8 E1 00 00 00 2E 00 02 00 00 00 00 00 00
at = entrypoint
requires = pe32, native
type = packer
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_Windows_PE_Packer_by_Chenzs108.2.sg
x-die-loss = number of sections (> 2), number of imports (1), import hash and flags of the last section (0xE0000040) not checked

; packer_WinUpack.2.sg
[(Win)Upack 0.1X/0.20/0.21/0.24 beta]
pattern = BE ?? ?? ?? ?? AD 8B F8 95 A5 33 C0 33
at = entrypoint
type = packer
version = 0.1X/0.20/0.21/0.24 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.21 beta]
pattern = BE ?? ?? ?? ?? AD 8B F8 6A 04 95 A5 33 C0 AB
at = entrypoint
type = packer
version = 0.21 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.24-0.27 beta/0.28 alpha]
pattern = BE ?? ?? ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5
at = entrypoint
type = packer
version = 0.24-0.27 beta/0.28 alpha
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.37 beta]
pattern = BE ?? ?? ?? ?? AD 50 FF 76 34 EB 7C 48 01
at = entrypoint
pattern.2 = 37
at.2 = entrypoint + 0x3E
type = packer
version = 0.37 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.38 beta]
pattern = BE ?? ?? ?? ?? AD 50 FF 76 34 EB 7C 48 01
at = entrypoint
pattern.2 = 38
at.2 = entrypoint + 0x3E
type = packer
version = 0.38 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.39 final]
pattern = BE ?? ?? ?? ?? AD 50 FF 76 34 EB 7C 48 01
at = entrypoint
pattern.2 = 39
at.2 = entrypoint + 0x3E
type = packer
version = 0.39 final
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.399]
pattern = BE ?? ?? ?? ?? AD 50 FF 76 34 EB 7C 48 01
at = entrypoint
pattern.2 = 3A
at.2 = entrypoint + 0x3E
type = packer
version = 0.399
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.22/0.23 beta]
pattern = 6A 07 BE ?? ?? ?? ?? AD 8B F8 59 95 F3 A5
at = entrypoint
type = packer
version = 0.22/0.23 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.32 beta [Patch]]
pattern = BE ?? ?? ?? ?? AD 50 ?? AD 91 F3 A5
at = entrypoint
type = packer
version = 0.32 beta
options = Patch
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.32 beta]
pattern = BE ?? ?? ?? ?? AD 50 ?? AD 91 ?? F3 A5
at = entrypoint
type = packer
version = 0.32 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.32 beta]
pattern = BE ?? ?? ?? ?? AD 50 ?? ?? AD 91 F3 A5
at = entrypoint
type = packer
version = 0.32 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.34]
pattern = BE ?? ?? ?? ?? AD 50 AD 50 66 BE ?? ?? 6A ?? BF
at = entrypoint
type = packer
version = 0.34
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.36 beta]
pattern = BE ?? ?? ?? ?? FF 36 E9 C3 00 00 00
at = entrypoint
type = packer
version = 0.36 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack [Alt stub]]
pattern = 60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E
at = entrypoint
type = packer
options = Alt stub
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.33]
pattern = 4D 5A 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 50 45 00 00 4C 01 02 00 4B 45 52 4E 45 4C 33 32
at = image
type = packer
version = 0.33
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack 0.32]
pattern = 4D 5A 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00
at = image
type = packer
version = 0.32
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

[(Win)Upack]
pattern = 4D 5A 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 50 45
at = image
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WinUpack.2.sg

; packer_WWPack32.2.sg
[WWPack32 1.XX]
pattern = 53 55 8B E8 33 DB EB $$ E8 00 00 00 00 5D 3E 80 7D ?? ?? 0F 84 ?? ?? ?? ?? 60 83 ED ?? 33 C0 33 C9
at = entrypoint
type = packer
version = 1.XX
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WWPack32.2.sg

[WWPack32 1.XX]
pattern = 53 55 8B E8 33 DB EB $$ E8 00 00 00 00 58 2D ?? ?? ?? ?? 8B E8 50
at = entrypoint
type = packer
version = 1.XX
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WWPack32.2.sg

[WWPack32 1.XX]
pattern = 53 55 50 8B E8 33 DB EB $$ E8 00 00 00 00 58 2D ?? ?? ?? ?? 8B E8 50
at = entrypoint
type = packer
version = 1.XX
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WWPack32.2.sg

[WWPack32]
requires = dll
section = .WWP32
type = packer
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_WWPack32.2.sg
x-die-loss = .WWP32 is not checked to be the last section

; packer_XComp.2.sg
[XComp]
pattern = 68 ?? ?? ?? ?? 9C 60 E8 $$$$$$$$ E8 $$$$$$$$ 5B 5D 83 3B 00
at = entrypoint
import = /!GetProcAddress$/, /!LoadLibraryA$/, /!VirtualAlloc$/, /!VirtualFree$/, /!VirtualProtect$/
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_XComp.2.sg
x-die-loss = import hash of the only import library approximated by its function names, number of imports (1) not checked

; packer_xor_packer.2.sg
[xor_packer [x64]]
pattern = 48 8D 05 F9 ?? ?? FF 48 B9
in = section(.new)
type = packer
options = x64
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_xor_packer.2.sg

; packer_XPack.2.sg
[XPack]
pattern = 68 ?? ?? ?? ?? 9C 60 E8 $$$$$$$$ E8 $$$$$$$$ 5B 5D 83 3B 00
at = entrypoint
import = /!GetProcAddress$/, /!LoadLibraryA$/, /!VirtualProtect$/, !/!VirtualAlloc$/, !/!VirtualFree$/
type = packer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_XPack.2.sg
x-die-loss = import hash of the only import library approximated by its function names, number of imports (1) not checked

; packer_yzPack.2.sg
[yzPack 1.0-1.1]
pattern = 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C
at = entrypoint
type = packer
version = 1.0-1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_yzPack.2.sg

[yzPack 1.2]
pattern = 4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9
at = entrypoint
type = packer
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_yzPack.2.sg

[yzPack 1.12]
pattern = 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9
at = entrypoint
type = packer
version = 1.12
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_yzPack.2.sg

[yzPack 2.0]
pattern = 25 ?? ?? ?? ?? 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3
at = entrypoint
type = packer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/packer_yzPack.2.sg


; ======================================================================
; Protectors
; ======================================================================

; protector_ACProtect.2.sg
[ACProtect 1.09g]
pattern = 60 F9 50 E8 01 00 00 00 ?? 58 58 49 50 E8 01 00 00 00 ?? 58 58 79 04 66 B9 B8 72 E8 01 00 00 00
at = entrypoint
type = protector
version = 1.09g
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ACProtect.2.sg

[ACProtect 1.41]
pattern = E8 01 00 00 00 ?? 83
at = entrypoint
type = protector
version = 1.41
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ACProtect.2.sg

[ACProtect 1.3X]
pattern = 60 50 E8 01 00 00 00 ?? 83
at = entrypoint
type = protector
version = 1.3X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ACProtect.2.sg

[ACProtect 1.4X]
pattern = 60 E8 01 00 00 00 ?? 83 04 24 06 C3
at = entrypoint
type = protector
version = 1.4X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ACProtect.2.sg

[ACProtect 1.90g]
pattern = 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 ?? 83 04 24 06 C3
at = entrypoint
type = protector
version = 1.90g
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ACProtect.2.sg

[ACProtect 2.0.X]
pattern = 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C3 C3
at = entrypoint
type = protector
version = 2.0.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ACProtect.2.sg

; protector_ActiveMark.2.sg
[ActiveMARK 5.X]
pattern = 00 'TMSAMVOH'
at = overlay
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ActiveMark.2.sg

; protector_Agile.2.sg
[Agile]
requires = dotnet
dotnet_string = ObfuscatedByAgileDotNetAttribute
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Agile.2.sg
x-die-loss = only reported by DIE if at most 2 protectors were detected

[Agile]
requires = dotnet
dotnet_string = <AgileDotNetRT>
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Agile.2.sg
x-die-loss = only reported by DIE if at most 2 protectors were detected

[Agile]
requires = dotnet
dotnet_string = AgileDotNetRT.dll
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Agile.2.sg
x-die-loss = only reported by DIE if at most 2 protectors were detected

[Agile]
requires = dotnet
dotnet_string = AgileDotNetRT64.dll
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Agile.2.sg
x-die-loss = only reported by DIE if at most 2 protectors were detected

; protector_AHTeam_EP_Protector.2.sg
[AHTeam EP Protector 0.3 [fake k.kryptor 9/kryptor a]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 60 E8 ?? ?? ?? ?? 5E B9 00 00 00 00 2B C0
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake k.kryptor 9/kryptor a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake Microsoft Visual C++ 7.0]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake Microsoft Visual C++ 7.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake ASPack 2.12]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake ASPack 2.12
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake ASProtect 1.0]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 60 E8 01 00 00 00 90 5D 81 ED 00 00 00 00
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake ASProtect 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake Borland Delphi 6.0-7.0]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake Borland Delphi 6.0-7.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake PCGuard 4.03-4.15]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake PCGuard 4.03-4.15
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake PE Lock NT 2.04]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake PE Lock NT 2.04
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake PE-Crypt 1.02]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake PE-Crypt 1.02
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake PESHiELD 2.X]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake PESHiELD 2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake PEtite 2.2]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = B8 00 00 00 00 68 00 00 00 00 64 FF 35 00
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake PEtite 2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake Spalsher 1.X-3.X]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 9C 60 8B 44 24 24 E8 00 00 00 00 5D 81 ED
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake Spalsher 1.X-3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake Stone's PE Encryptor 2.0]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake Stone's PE Encryptor 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake SVKP 1.3X]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake SVKP 1.3X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake tElock 0.61]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake tElock 0.61
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake VIRUS/I-Worm Hybris]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = EB 16 A8 54 00 00 47 41 42 4C 4B 43 47 43
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake VIRUS/I-Worm Hybris
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake VOB ProtectCD]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = 5F 81 EF 00 00 00 00 BE 00 00 40 00 8B 87
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake VOB ProtectCD
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake Xtreme-Protector 1.05]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = E8 00 00 00 00 5D 81 00 00 00 00 00 6A 45
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake Xtreme-Protector 1.05
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [fake ZCode 1.01]]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
pattern.3 = E9 12 00 00 00 00 00 00 00 00 00 00 00 00
at.3 = entrypoint + 0x32
type = protector
version = 0.3
options = fake ZCode 1.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3]
pattern = 90
at = entrypoint
pattern.2 = 90 FF E0
at.2 = entrypoint + 0x2F
type = protector
version = 0.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

[AHTeam EP Protector 0.3 [alt]]
pattern = 55 90 8B EC 90 6A FF 90 90
at = entrypoint
type = protector
version = 0.3
options = alt
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AHTeam_EP_Protector.2.sg

; protector_Alcatraz.2.sg
[Alcatraz]
section = .0Dev
requires = pe32+
type = protector
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Alcatraz.2.sg
x-die-loss = flags 0x60000020 of the .0Dev section not checked

; protector_Alienyze.2.sg
[Alienyze]
pattern = 55 8B EC
at = entrypoint
section = .alien
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Alienyze.2.sg
x-die-loss = no imports, more than 4 sections and file offset 0 of the first section not checked

[Alienyze demo]
pattern = 55 8B EC
at = entrypoint
pattern.2 = 54 00 68 00 69 00 73 00 20 00 6D 00 65 00 73 00 73 00 61 00 67 00 65 00 20 00 77 00 6F 00 6E 00 27 00 74 00 20 00 61 00
in.2 = image, overlay
section = .alien
type = protector
version = demo
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Alienyze.2.sg
x-die-loss = no imports, more than 4 sections and file offset 0 of the first section not checked

; protector_Anticrack_Software.2.sg
[AntiCrack Software Basic 1.09]
pattern = 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? 04
at = entrypoint
type = protector
version = 1.09
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Anticrack_Software.2.sg

[AntiCrack Software Basic 1.09]
pattern = 60 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 01 00 00 00 ?? 83 04 24 06 C3 ?? ?? ?? ?? ?? 00
at = entrypoint
type = protector
version = 1.09
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Anticrack_Software.2.sg

; protector_AntiDote.2.sg
[AntiDote 1.0 Beta]
pattern = E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50
at = entrypoint
type = protector
version = 1.0 Beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AntiDote.2.sg

[AntiDote 1.2 Beta]
pattern = 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74
at = entrypoint
type = protector
version = 1.2 Beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AntiDote.2.sg

[AntiDote 1.2 Demo]
pattern = E8 $$$$$$$$ E8 00 00 00 00 58 53 51 56 57 50 8B 1C 24 81
at = entrypoint
type = protector
version = 1.2 Demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AntiDote.2.sg

[AntiDote 1.2 Demo]
pattern = EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01
at = entrypoint
type = protector
version = 1.2 Demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AntiDote.2.sg

[AntiDote 1.4 SE]
pattern = 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50
at = entrypoint
type = protector
version = 1.4 SE
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AntiDote.2.sg

[AntiDote 1.2 Demo]
pattern = E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2
at = entrypoint
type = protector
version = 1.2 Demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AntiDote.2.sg

[AntiDote 1.4 osCE]
pattern = 68 95 01 00 00 E8 D0 FD FF FF 68 95 01 00 00 E8 C3 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68
at = entrypoint
type = protector
version = 1.4 osCE
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AntiDote.2.sg

[AntiDote 1.X]
pattern = 68 ?? ?? 00 00 E8 ?? FD FF FF 68 ?? ?? 00 00 E8 ?? FD FF FF 68 90 03 00 00 E8 ?? FD FF FF
at = entrypoint
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AntiDote.2.sg

; protector_ARM_Protector.2.sg
[ARM Protector 0.5]
pattern = E8 04 00 00 00 83 60 EB 0C 5D EB 05
at = entrypoint
pattern.2 = B3 0A 00 00
at.2 = entrypoint + 0x2A
section = .armp
type = protector
version = 0.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ARM_Protector.2.sg
x-die-loss = number of imports (none) not checked

[ARM Protector 0.5 [modified]]
pattern = E8 04 00 00 00 83 60 EB 0C 5D EB 05
at = entrypoint
pattern.2 = B3 0A 00 00
at.2 = entrypoint + 0x2A
section = !.armp
type = protector
version = 0.5
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ARM_Protector.2.sg
x-die-loss = number of imports (none) not checked

[ARM Protector 0.6]
pattern = E8 04 00 00 00 83 60 EB 0C 5D EB 05
at = entrypoint
pattern.2 = A1 0B 00 00
at.2 = entrypoint + 0x2A
section = .armp
type = protector
version = 0.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ARM_Protector.2.sg
x-die-loss = number of imports (none) not checked

[ARM Protector 0.6 [modified]]
pattern = E8 04 00 00 00 83 60 EB 0C 5D EB 05
at = entrypoint
pattern.2 = A1 0B 00 00
at.2 = entrypoint + 0x2A
section = !.armp
type = protector
version = 0.6
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ARM_Protector.2.sg
x-die-loss = number of imports (none) not checked

[ARM Protector 0.1b-0.3b]
pattern = E8 04 00 00 00 83 60 EB 0C 5D EB 05
at = entrypoint
section = .armp
type = protector
version = 0.1b-0.3b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ARM_Protector.2.sg
x-die-loss = number of imports (none) not checked

[ARM Protector 0.1b-0.3b [modified]]
pattern = E8 04 00 00 00 83 60 EB 0C 5D EB 05
at = entrypoint
section = !.armp
type = protector
version = 0.1b-0.3b
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ARM_Protector.2.sg
x-die-loss = number of imports (none) not checked

; protector_Armadillo.2.sg
[Armadillo 3.X-9.X]
pattern = 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08
at = entrypoint
type = protector
version = 3.X-9.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Armadillo.2.sg

[Armadillo 4.44a public build]
pattern = 55 8B EC 83 EC 0C 53 56 57 8B 45 08 50 FF 15 ?? ?? ?? ?? 83 C4 04 89 45 FC 8B 45 FC 51 B9 00 08 00 00 B9 06 00 00 00
at = entrypoint
type = protector
version = 4.44a public build
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Armadillo.2.sg

[Armadillo 5.00]
pattern = E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 ?? ?? ?? ?? E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B
at = entrypoint
type = protector
version = 5.00
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Armadillo.2.sg

[Armadillo 5.00 [DLL]]
pattern = 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68
at = entrypoint
type = protector
version = 5.00
options = DLL
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Armadillo.2.sg

[Armadillo 2.XX [CopyMem II]]
pattern = 6A ?? 8B B5 ?? ?? ?? ?? C1 E6 04 8B 85 ?? ?? ?? ?? 25 07 ?? ?? 80 79 05 48 83 C8 F8 40 33 C9 8A 88 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 81 E2 07 ?? ?? 80 79 05 4A 83 CA F8 42 33 C0 8A 82
at = entrypoint
type = protector
version = 2.XX
options = CopyMem II
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Armadillo.2.sg

[Armadillo 3.00]
pattern = 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9
at = entrypoint
type = protector
version = 3.00
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Armadillo.2.sg

[Armadillo 3.00a-3.70a]
pattern = 60 E8 ?? ?? ?? ?? 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB
at = entrypoint
type = protector
version = 3.00a-3.70a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Armadillo.2.sg

[Armadillo 6.X-9.X]
pattern = 'PDATA000'
at = section
type = protector
version = 6.X-9.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Armadillo.2.sg
x-die-loss = linker version 0x53.0x52 not checked

; protector_ArmDot.2.sg
[ArmDot]
pattern = 20 ?? ?? ?? ?? 8D ?? ?? ?? ?? FE 0E ?? ?? 20 ?? ?? ?? ?? 8D ?? ?? ?? ?? FE 0E ?? ?? 20 ?? ?? ?? ?? 8D ?? ?? ?? ?? FE 0E ?? ?? 20 ?? ?? ?? ??
in = section(#0)
pattern.2 = 20 ?? ?? ?? ?? FE 0C ?? ?? 3F ?? ?? 00 00 20 ?? ?? ?? ?? FE 0C ?? ?? 3D ?? ?? 00 00
in.2 = section(#0)
requires = dotnet
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ArmDot.2.sg

; protector_Arxan.2.sg
[Arxan GuardIT ~2013]
pattern = 40 50 40 51 40 52 40 53 55 56 57 9C 48 83 EC 38 FC B8 01 00 00 00 B9 FF FF 00 00 E0 FE
at = entrypoint
requires = pe32+, native
type = protector
version = GuardIT ~2013
author = securitystar
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Arxan.2.sg

; protector_ASM_Guard.2.sg
[ASM Guard 2.XX [shell mutation]]
section = ASMGUARD
requires = overlay
type = protector
version = 2.XX
options = shell mutation
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASM_Guard.2.sg
x-die-loss = number of resources (> 12) not checked

[ASM Guard]
resource = */NT.DLL
requires = overlay
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASM_Guard.2.sg
x-die-loss = number of resources (> 12) not checked

[ASM Guard 2.6]
pattern = 60
at = entrypoint
resource = */OBFUSCATE
requires = overlay
type = protector
version = 2.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASM_Guard.2.sg
x-die-loss = number of resources (> 12), first section not named .text, and OBFUSCATE being the first resource not checked

; protector_ASProtect.2.sg
[ASProtect 1.23-2.56]
pattern = 68 01 ?? ?? ?? E8 01 00 00 00 C3 C3
at = entrypoint
type = protector
version = 1.23-2.56
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect SKE 2.1-2.2]
pattern = 68 ######## 90 60 E8 $$$$$$$$ 5D 45 55 C3
at = entrypoint
type = protector
version = SKE 2.1-2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect SKE 2.3-2.5]
pattern = 68 ######## 60 E8 $$$$$$$$ 5D 45 55 C3
at = entrypoint
type = protector
version = SKE 2.3-2.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect SKE 2.1/2.2]
pattern = 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
type = protector
version = SKE 2.1/2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect SKE 2.1/2.2]
pattern = 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
type = protector
version = SKE 2.1/2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect SKE 2.3]
pattern = 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 E5 0B 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
type = protector
version = SKE 2.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect]
pattern = 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 ?? ?? 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect 1.0]
pattern = 60 E8 01 00 00 00 90 5D 81 ED ?? ?? ?? ?? BB ?? ?? ?? ?? 03 DD 2B 9D
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect 1.1 MTE]
pattern = 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9
at = entrypoint
type = protector
version = 1.1 MTE
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect 1.1 MTEb]
pattern = 90 60 E9 ?? 04
at = entrypoint
type = protector
version = 1.1 MTEb
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect MTEc]
pattern = 90 60 E8 1B ?? ?? ?? E9 FC
at = entrypoint
type = protector
version = MTEc
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect 1.1]
pattern = 60 E9 ?? 04 ?? ?? E9 ?? ?? ?? ?? ?? ?? ?? EE
at = entrypoint
type = protector
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect 1.1]
pattern = 60 E9 $$$$$$$$ 81 DA ?? ?? ?? ?? E8 $$$$$$$$ 0F BF FE 0F BF FD
at = entrypoint
type = protector
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect 1.23 RC4 build 08.07]
pattern = 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB ?? ?? ?? ?? 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
type = protector
version = 1.23 RC4 build 08.07
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect 1.1]
pattern = 60 E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 05 ?? ?? ?? ?? B9 ?? ?? ?? ?? AD 35 ?? ?? ?? ?? AB 49 75 F6 EB 04 5D 45 55 C3
at = entrypoint
type = protector
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect 1.11c]
pattern = 60 E8 $$$$$$$$ 5D 45 55 81 ED ?? ?? ?? ?? C3
at = entrypoint
type = protector
version = 1.11c
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

[ASProtect SKE 2.72+]
pattern = 60 E8 $$$$$$$$ 5D 45 55 C3
at = entrypoint
type = protector
version = SKE 2.72+
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ASProtect.2.sg

; protector_AT4RE.2.sg
[AT4RE 1.0]
pattern = 0F 31 33 C9 03 C8 EB $$ 0F 31 2B C1 3D ?? ?? ?? ?? 0F 83 ?? ?? ?? ?? E9 $$$$$$$$ B8 ?? ?? ?? ?? 33 F6 33 DB 8A 1C 06 80 EB
at = entrypoint
type = protector
version = 1.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AT4RE.2.sg

; protector_AZProtect_0001.2.sg
[AZProtect 0001 [modified]]
pattern = EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30
at = entrypoint
section = !AZPR0001
type = protector
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AZProtect_0001.2.sg

[AZProtect 0001]
pattern = EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30
at = entrypoint
section = AZPR0001
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_AZProtect_0001.2.sg

; protector_Babel_.NET.2.sg
[Babel .NET 1.0-2.X]
requires = dotnet
dotnet_string = BabelObfuscatorAttribute, !BabelAttribute
type = protector
version = 1.0-2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Babel_.NET.2.sg

[Babel .NET 3.X]
requires = dotnet
dotnet_string = !BabelObfuscatorAttribute, BabelAttribute
type = protector
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Babel_.NET.2.sg

; protector_bambam.2.sg
[bambam 0.01]
pattern = 6A 14 E8 9A 05 00 00 ?? ?? 53 68 ?? ?? ?? ?? E8 6C FD FF FF
at = entrypoint
section = .bedrock
type = protector
version = 0.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_bambam.2.sg

[bambam 0.01 [modified]]
pattern = 6A 14 E8 9A 05 00 00 ?? ?? 53 68 ?? ?? ?? ?? E8 6C FD FF FF
at = entrypoint
section = !.bedrock
type = protector
version = 0.01
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_bambam.2.sg

[bambam 0.1]
pattern = 4D 5A 90 EB $$ 52 E9 $$$$$$$$ EB $$ 64 A1 ?? ?? ?? ?? EB $$ 8B 48 ?? ?? ?? EB $$ 05 ?? ?? ?? ?? EB $$ 66 81 38
at = entrypoint
section = .bedrock
type = protector
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_bambam.2.sg

[bambam 0.1 [modified]]
pattern = 4D 5A 90 EB $$ 52 E9 $$$$$$$$ EB $$ 64 A1 ?? ?? ?? ?? EB $$ 8B 48 ?? ?? ?? EB $$ 05 ?? ?? ?? ?? EB $$ 66 81 38
at = entrypoint
section = !.bedrock
type = protector
version = 0.1
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_bambam.2.sg

; protector_BatchToApp.2.sg
[BatchToApp]
requires = dotnet
dotnet_string = GeneratedWithBatchToApp
dotnet_us = Unable to execute.
type = protector
lang = Batch
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_BatchToApp.2.sg

; protector_beria.2.sg
[Beria 0.07]
pattern = 83 EC 18 53 8B 1D 00 30 ?? ?? 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 ?? ?? FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 ?? ?? FF D3 8B F0
at = entrypoint
type = protector
version = 0.07
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_beria.2.sg

; protector_Berio.2.sg
[Berio 1.00 beta]
pattern = 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 01 12 00
at = entrypoint
type = protector
version = 1.00 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Berio.2.sg

[Berio 2.00 beta]
pattern = 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 01 74 01
at = entrypoint
type = protector
version = 2.00 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Berio.2.sg

; protector_BJFnt.2.sg
[.BJFnt 1.1b]
pattern = EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56
at = entrypoint
type = protector
version = 1.1b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_BJFnt.2.sg

[.BJFnt 1.2 RC]
pattern = EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB
at = entrypoint
type = protector
version = 1.2 RC
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_BJFnt.2.sg

[.BJFnt 1.3]
pattern = EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60
at = entrypoint
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_BJFnt.2.sg

; protector_ByfronTech.2.sg
[Byfron Technologies]
export = run
section = !.text, .byfron
type = protector
author = @justmazz_
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ByfronTech.2.sg
x-die-loss = flags 0x60000020 of the .byfron section not checked

[Byfron Technologies]
export = run
section = !.text, .byfron1
type = protector
author = @justmazz_
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ByfronTech.2.sg
x-die-loss = flags 0x02000040 of the .byfron1 section not checked

; protector_ByteGuard.2.sg
[ByteGuard]
pattern = %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %%
at = overlay
requires = dotnet
dotnet_us = C# version only supports level 1 and 3
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ByteGuard.2.sg
x-die-loss = global .cctor and first section named .text (or a UPX section) not checked

; protector_Cameyo.2.sg
[Cameyo]
pattern = 'MZ'
at = overlay
version_info.ProductName = Cameyo Application Virtualization
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Cameyo.2.sg
x-die-loss = version read from file

; protector_CliSecure.2.sg
[CliSecure 4.0-5.X]
requires = dotnet
dotnet_string = ObfuscatedByCliSecureAttribute
type = protector
version = 4.0-5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CliSecure.2.sg

[CliSecure]
requires = dotnet
dotnet_string = !ObfuscatedByCliSecureAttribute, CliSecureRd.dll
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CliSecure.2.sg

[CliSecure]
requires = dotnet
dotnet_string = !ObfuscatedByCliSecureAttribute, CliSecureRd64.dll
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CliSecure.2.sg

[CliSecure]
pattern = 'Cli' 00 'S' 00 'e' 00 'c' 00 'u' 00 'r' 00 'e'
in = section(#0)
requires = dotnet
dotnet_string = !ObfuscatedByCliSecureAttribute, !CliSecureRd.dll, !CliSecureRd64.dll
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CliSecure.2.sg

[CliSecure 4.5]
pattern = E9 $$$$$$$$ 55 8B EC 81 EC 4C 02 00 00 A1 ?? ?? ?? ?? 33 C5 89 45 F4 83
at = entrypoint
requires = native
type = protector
version = 4.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CliSecure.2.sg

; protector_Code-Lock.2.sg
[Code-Lock]
import = code-lock.ocx
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Code-Lock.2.sg

; protector_Code_Virtualizer.2.sg
[Code Virtualizer 1.3.1.0]
pattern = 60 9C FC E8 00 00 00 00 5F 81 EF ?? ?? ?? ?? 8B C7 81 C7 ?? ?? ?? ?? 3B 47 2C 75 02 EB 2E 89 47 2C B9 A7 00 00 00 EB 05 01 44 8F
at = entrypoint
type = protector
version = 1.3.1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Code_Virtualizer.2.sg

; protector_CodeCrypt.2.sg
[CodeCrypt 0.14b]
pattern = E9 ?? ?? ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F
at = entrypoint
pattern.2 = C5 02 00 00
at.2 = entrypoint + 0x1
type = protector
version = 0.14b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CodeCrypt.2.sg

[CodeCrypt 0.15b]
pattern = E9 ?? ?? ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F
at = entrypoint
pattern.2 = 31 03 00 00
at.2 = entrypoint + 0x1
type = protector
version = 0.15b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CodeCrypt.2.sg

[CodeCrypt 0.164]
pattern = E9 ?? ?? ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F
at = entrypoint
pattern.2 = 2E 03 00 00
at.2 = entrypoint + 0x1
pattern.3 = EB 03 FF 1D 34
at.3 = entrypoint + 0x14
type = protector
version = 0.164
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CodeCrypt.2.sg

[CodeCrypt 0.16b-0.163b]
pattern = E9 ?? ?? ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F
at = entrypoint
pattern.2 = 2E 03 00 00
at.2 = entrypoint + 0x1
type = protector
version = 0.16b-0.163b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CodeCrypt.2.sg

[CodeCrypt]
pattern = E9 ?? ?? ?? ?? EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CodeCrypt.2.sg

; protector_CodeVeil.2.sg
[CodeVeil 1.2]
pattern = E9 $$$$$$$$ E9 $$$$$$$$ 8B FF 60 E8 $$$$$$$$ 5E E8
at = entrypoint
type = protector
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CodeVeil.2.sg

[CodeVeil 4.X]
requires = dotnet
dotnet_string = ____KILL
type = protector
version = 4.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CodeVeil.2.sg

[CodeVeil 3.X-4.X]
requires = dotnet
dotnet_string = !____KILL
dotnet_us = E_TamperDetected
type = protector
version = 3.X-4.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CodeVeil.2.sg

; protector_Codewall.2.sg
[CodeWall 4.X [demo]]
requires = dotnet
dotnet_string = CodeWallTrialVersion
type = protector
version = 4.X
options = demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Codewall.2.sg

[CodeWall 4.X]
pattern = 91 61 D2 81 ?? ?? ?? ?? 11 ?? 17 58 13 ?? 11 ?? 11 ?? 32 ?? 28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 7E ?? ?? ?? ?? 2D ?? 73
in = section(#0)
requires = dotnet
dotnet_string = !CodeWallTrialVersion, !CodeWallTrialVersion
type = protector
version = 4.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Codewall.2.sg

; protector_Confuser.2.sg
[Confuser]
requires = dotnet
dotnet_string = ConfusedByAttribute
type = protector
author = Levis
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Confuser.2.sg
x-die-loss = version read from file

[ConfuserEx]
pattern = 'ConfuserEx v'
in = section(#1)
requires = dotnet
type = protector
author = Levis
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Confuser.2.sg
x-die-loss = version read from file

[ConfuserEx Bed's mod]
requires = dotnet
dotnet_string = /^вє∂ѕ ρяσтє¢тσя/
type = protector
version = Bed's mod
author = Levis
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Confuser.2.sg
x-die-loss = assembly name prefix approximated by any #Strings heap entry with that prefix

[ConfuserEx DotNetPatcher mod]
requires = dotnet
dotnet_string = ConfusedByAttribute, DotNetPatcherPackerAttribute
type = protector
version = DotNetPatcher mod
author = Levis
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Confuser.2.sg

[ConfuserEx DotNetPatcher mod]
pattern = 'ConfuserEx v'
in = section(#1)
requires = dotnet
dotnet_string = DotNetPatcherPackerAttribute
type = protector
version = DotNetPatcher mod
author = Levis
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Confuser.2.sg

; protector_CopyMinder.2.sg
[CopyMinder]
pattern = 83 25 ?? ?? ?? ?? EF 6A 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CopyMinder.2.sg

; protector_Crinkler.2.sg
[Crinkler 0.1-0.2]
pattern = B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9
at = entrypoint
type = protector
version = 0.1-0.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Crinkler.2.sg

[Crinkler 0.3-0.4]
pattern = B8 ?? ?? ?? ?? 31 DB 43 EB 58
at = entrypoint
type = protector
version = 0.3-0.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Crinkler.2.sg

; protector_Crunch.2.sg
[Crunch 4.0]
pattern = EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00
at = entrypoint
type = protector
version = 4.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Crunch.2.sg

[Crunch 5.0]
pattern = EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00
at = entrypoint
type = protector
version = 5.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Crunch.2.sg

[Crunch 1.0]
pattern = 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85
at = entrypoint
pattern.2 = 80 BD
at.2 = entrypoint + 0x20
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Crunch.2.sg

[Crunch 2.0]
pattern = 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85
at = entrypoint
pattern.2 = 55 BB
at.2 = entrypoint + 0x20
type = protector
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Crunch.2.sg

[Crunch]
pattern = 55 E8 ?? ?? ?? ?? 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Crunch.2.sg

; protector_CrypKey.2.sg
[CrypKey]
pattern = 8B 1D ?? ?? ?? ?? 83 FB 00 75 0A E8 3C 00 00 00 E8 ?? 0A 00 00 8B 44 24 08 50 E8 ?? 02 00 00 A1
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CrypKey.2.sg

[CrypKey 5.X-6.X]
pattern = E8 ?? ?? ?? ?? 58 83 E8 05 50 5F 57 8B F7 81 EF ?? ?? ?? ?? 83 C6 39 BA ?? ?? ?? ?? 8B DF B9 0B ?? ?? ?? 8B 06
at = entrypoint
type = protector
version = 5.X-6.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CrypKey.2.sg

[CrypKey 5.6.X]
pattern = E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8
at = entrypoint
type = protector
version = 5.6.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CrypKey.2.sg

[CrypKey 6.1X]
pattern = 83 3D ?? ?? ?? ?? 00 75 34 68 ?? ?? ?? ?? E8
at = entrypoint
type = protector
version = 6.1X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CrypKey.2.sg

[CrypKey [Core module]]
pattern = 8B 44 24 ?? 50 E8 $$$$$$$$ 55 8B EC 81 C4 ?? ?? ?? ?? 50 81 C4 ?? ?? ?? ?? 53 C7 45
at = entrypoint
type = protector
options = Core module
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CrypKey.2.sg

; protector_Cryptect.2.sg
[Cryptect]
pattern = 68 ?? ?? ?? ?? E8 $$$$$$$$ 50 52 E9 $$$$$$$$ 53 66 0F CB 56 0F B7 DF 9C 0F BF F3 81 D6 ?? ?? ?? ?? D2 E7 55 8B DA 57
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Cryptect.2.sg

[Cryptect]
pattern = 68 ?? ?? ?? ?? E8 $$$$$$$$ 52 51 66 99 0F CA 99 9C F5 50 C0 DE ?? D2 D4 0F B7 C3 55 0F AB E5 F8 56 57 66
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Cryptect.2.sg

; protector_CrypToCrack.2.sg
[CrypToCrack 0.9.2]
pattern = E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 ?? ?? 81 3E 50 45 00 00 75 26
at = entrypoint
type = protector
version = 0.9.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CrypToCrack.2.sg

[CrypToCrack 0.9.3]
pattern = 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1
at = entrypoint
type = protector
version = 0.9.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CrypToCrack.2.sg

; protector_CryptoObfuscator.2.sg
[Crypto Obfuscator 5.X]
pattern = 00 02 20 ?? ?? 00 0A 20 FF FF FF 00 28 ?? ?? ?? ?? 2A
in = section(#0)
requires = dotnet
dotnet_string = AssemblyInfoAttribute
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CryptoObfuscator.2.sg

[Crypto Obfuscator 5.X]
pattern = 02 91 20 3F FF FF FF 5F 1F 18 62 0A 06 7E ?? ?? ?? ?? 02 17 58 91 1F 10 62 60 0A 06 7E
in = section(#0)
requires = dotnet
dotnet_string = AssemblyInfoAttribute
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_CryptoObfuscator.2.sg

; protector_Daemon_Protect.2.sg
[Daemon Protect 0.6.7]
pattern = 60 60 9C 8C C9 32 C9 E3 $$ 9D 61 30 E2 30 E2 31 C0 55 E8
at = entrypoint
type = protector
version = 0.6.7
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Daemon_Protect.2.sg

; protector_DalKrypt.2.sg
[DalKrypt 1.0]
pattern = 68 ?? ?? ?? ?? 58 68 ?? ?? ?? ?? 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? ?? 72 EB FF E7
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DalKrypt.2.sg

; protector_DBPE.2.sg
[DBPE 1.53]
pattern = 9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA
at = entrypoint
type = protector
version = 1.53
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DBPE.2.sg

[DBPE 2.10]
pattern = 9C 6A 10 73 0B EB 02 C1 51 E8 06 ?? ?? ?? C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68
at = entrypoint
type = protector
version = 2.10
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DBPE.2.sg

[DBPE 2.10]
pattern = EB $$ 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED
at = entrypoint
pattern.2 = EB
at.2 = entrypoint + 0x5C
type = protector
version = 2.10
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DBPE.2.sg

[DBPE 2.33]
pattern = EB $$ 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED
at = entrypoint
pattern.2 = 9C
at.2 = entrypoint + 0x5C
type = protector
version = 2.33
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DBPE.2.sg

[DBPE]
pattern = EB $$ 9C 55 57 56 52 51 53 9C E8 ?? ?? ?? ?? 5D 81 ED
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DBPE.2.sg

; protector_DeepSea.2.sg
[DeepSea]
pattern = 'DeepSeaObfuscator'
in = section(#0)
requires = dotnet
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DeepSea.2.sg

[DeepSea 4.X [Evaluation]]
pattern = 'DeepSeaObfuscator' ?? 'Evaluation'
in = section(#0)
requires = dotnet
type = protector
version = 4.X
options = Evaluation
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DeepSea.2.sg

; protector_DNGuard.2.sg
[DNGuard]
requires = dotnet
dotnet_string = ZYXDNGuarder
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DNGuard.2.sg
x-die-loss = global .cctor not checked; DIE reports it only if at most 1 protector was detected

[DNGuard]
requires = dotnet
dotnet_string = HVMRuntm.dll
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DNGuard.2.sg
x-die-loss = global .cctor not checked; DIE reports it only if at most 1 protector was detected

[DNGuard]
pattern = 'A newer version of DNGuard Runtime library is needed to run this application.'
in = section(#0)
requires = dotnet
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DNGuard.2.sg
x-die-loss = global .cctor not checked; DIE reports it only if at most 1 protector was detected

[DNGuard]
pattern = 48 83 EC 28 E8 07 AD
at = entrypoint
pattern.2 = 'DNGuard'
in.2 = section(.rdata)
requires = pe32+
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DNGuard.2.sg
x-die-loss = import hash not checked

; protector_DotFix_Nice_Protect.2.sg
[DotFix NiceProtect 2.1-2.5]
pattern = E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8
at = entrypoint
type = protector
version = 2.1-2.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DotFix_Nice_Protect.2.sg

[DotFix NiceProtect]
pattern = 60 E8 55 00 00 00 8D BD ?? ?? ?? ?? 68 ?? ?? ?? ?? 03 3C 24 8B F7 90 68 ?? ?? ?? ?? 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D ?? ?? ?? ?? DB 1C 24 D1 E1 29
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DotFix_Nice_Protect.2.sg

[DotFix NiceProtect]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD ?? EB $$ 61 90 90 50 51 74 ?? 83 C8 ?? EB
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DotFix_Nice_Protect.2.sg

[DotFix NiceProtect 1.0-2.X]
pattern = E8 $$$$$$$$ EB $$ 5A EB $$ 52 4A EB $$ EB $$ B9 ?? ?? ?? ?? EB $$ EB $$ DD ?? EB $$ 80 34 11 ?? EB $$ EB $$ E2
at = entrypoint
type = protector
version = 1.0-2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DotFix_Nice_Protect.2.sg

[DotFix NiceProtect]
pattern = 60 BE
at = entrypoint
section = .
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DotFix_Nice_Protect.2.sg

; protector_Dotfuscator.2.sg
[Dotfuscator]
requires = dotnet
dotnet_string = DotfuscatorAttribute
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Dotfuscator.2.sg
x-die-loss = only reported by DIE if at most 2 protectors were detected

; protector_DragonArmor.2.sg
[DragonArmor 0.0.4.1 [modified]]
pattern = BF ?? ?? ?? ?? 83 C9 FF 33 C0 68 ?? ?? ?? ?? F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 11 0A 00 00 83 C4 0C 68
at = entrypoint
section = !/^(\.)?DAStub$/
type = protector
version = 0.0.4.1
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DragonArmor.2.sg

[DragonArmor 0.0.4.1]
pattern = BF ?? ?? ?? ?? 83 C9 FF 33 C0 68 ?? ?? ?? ?? F2 AE F7 D1 49 51 68 ?? ?? ?? ?? E8 11 0A 00 00 83 C4 0C 68
at = entrypoint
section = /^(\.)?DAStub$/
type = protector
version = 0.0.4.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DragonArmor.2.sg

; protector_DS.Sentinel_SuperPro.2.sg
[Sentinel SuperPro 6.4.0 [Automatic Protection]]
pattern = 68 ?? ?? ?? ?? 6A 01 6A 00 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C9 3D B7 00 00 00 A1
at = entrypoint
type = protector
version = 6.4.0
options = Automatic Protection
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DS.Sentinel_SuperPro.2.sg

[Sentinel SuperPro 6.4.1 [Automatic Protection]]
pattern = A1 ?? ?? ?? ?? 55 8B ?? ?? ?? 85 C0 74 ?? 85 ED 75 ?? A1 ?? ?? ?? ?? 50 55 FF 15 ?? ?? ?? ?? 8B 0D
at = entrypoint
type = protector
version = 6.4.1
options = Automatic Protection
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DS.Sentinel_SuperPro.2.sg

[Sentinel SuperPro 6.4.5.0 [Automatic Protection]]
pattern = A1 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 50 C7 04 85 ?? ?? ?? ?? ?? ?? ?? ?? E8
at = entrypoint
type = protector
version = 6.4.5.0
options = Automatic Protection
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DS.Sentinel_SuperPro.2.sg

; protector_DYAMAR.2.sg
[DYAMAR 1.3.5]
section = /^\.dyamar[CD]$/
type = protector
version = 1.3.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DYAMAR.2.sg

; protector_DZA_Patcher.2.sg
[DZA Patcher 1.3]
pattern = EB 08 '5H40L1N' 00 60 E8 00 00 00 00 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 83 EA 10 89 95 ?? ?? ?? ?? 8B 44 24 20 25 00 00 FF FF
at = entrypoint
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DZA_Patcher.2.sg

[DZA Patcher 1.3]
pattern = BF ?? ?? ?? ?? 99 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35
at = entrypoint
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_DZA_Patcher.2.sg

; protector_Eazfuscator.2.sg
[EazFuscator]
pattern = 'fefef'
in = section(#0)[0-0x400]
pattern.2 = 00 E2 80 ** E2 80 ** E2 80 ** E2 80 ** E2 80 ** E2 80 ** E2 80 ** E2 80 ** E2 80 ** E2 80 **
in.2 = section(#0)
requires = dotnet
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Eazfuscator.2.sg

; protector_Elan_License_Manager.1.sg
[Elan License Manager 4.1.3 [1995 by Elan Computer Group, Inc.]]
pattern = 8B 44 24 ?? 83 F8 ?? 0F 85 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? A3 ?? ?? ?? ?? 85 C9 75 ?? 3C ?? 75 ?? A9
at = entrypoint
type = protector
version = 4.1.3
options = 1995 by Elan Computer Group, Inc.
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Elan_License_Manager.1.sg

; protector_ElecKey.2.sg
[ElecKey [AnyCPU]]
pattern = 83 C4 20 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? C7 44 24 08 00 00 00 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 A3
in = section(#0)
requires = dotnet
type = protector
options = AnyCPU
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ElecKey.2.sg

[ElecKey [x64]]
pattern = 48 8B 0D D2 BE 01 00 66 41 B8 32 00 48 8D 91 7B 07 00 00 FF 15 A0 40 01 00 33 C9 FF 15 B8 40 01 00 48 8B
in = section(#0)
requires = dotnet
type = protector
options = x64
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ElecKey.2.sg

[ElecKey 2.00.X]
pattern = 41 50 41 51 51 52 57 53 55 56 E8 00 00 00 00 5B 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 2B D8 48 8B EB
at = entrypoint
requires = dotnet, pe32+
type = protector
version = 2.00.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ElecKey.2.sg

[ElecKey 2.00.X]
pattern = 51 52 57 53 55 56 E8 00 00 00 00 5B B8 ?? ?? ?? ?? 2B D8
at = entrypoint
requires = dotnet, pe32
type = protector
version = 2.00.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ElecKey.2.sg

[ElecKey 2.00.X]
pattern = 41 50 41 51 51 52 57 53 55 56 E8 00 00 00 00 5B 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 2B D8 48 8B EB
at = entrypoint
requires = native, pe32+
type = protector
version = 2.00.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ElecKey.2.sg

[ElecKey 2.00.X]
pattern = 51 52 57 53 55 56 E8 00 00 00 00 5B B8 ?? ?? ?? ?? 2B D8
at = entrypoint
requires = native, pe32
type = protector
version = 2.00.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ElecKey.2.sg

; protector_ENIGMA.2.sg
[Enigma]
pattern = 00 00 00 'ENIGMA'
in = section(#0)
requires = dotnet
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg

[Enigma]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9A ?? ?? ?? ?? ?? ?? E9 $$$$$$$$ 60 E8 00 00 00 00 5D ?? ED
at = entrypoint
requires = native, pe32
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma 5.X]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 9A ?? ?? ?? ?? ?? ?? E9 $$$$$$$$ 60 E8 00 00 00 00 5D ?? ED
at = entrypoint
pattern.2 = 'Enigma Protector'
in.2 = section(#-1), section(#-2)
requires = native, pe32
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = second last section is searched even if the last section has raw data

[Enigma]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 81 ED ?? ?? ?? ?? E9
at = entrypoint
requires = native, pe32
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma 5.X]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 81 ED ?? ?? ?? ?? E9
at = entrypoint
pattern.2 = 'Enigma Protector'
in.2 = section(#-1), section(#-2)
requires = native, pe32
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = second last section is searched even if the last section has raw data

[Enigma]
pattern = 68 ?? ?? ?? ?? E8 $$$$$$$$ EB $$ 83 C4 ?? E9 $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED
at = entrypoint
requires = native, pe32
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma 5.X]
pattern = 68 ?? ?? ?? ?? E8 $$$$$$$$ EB $$ 83 C4 ?? E9 $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED
at = entrypoint
pattern.2 = 'Enigma Protector'
in.2 = section(#-1), section(#-2)
requires = native, pe32
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = second last section is searched even if the last section has raw data

[Enigma]
pattern = EB $$ E9 $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 81 ED ?? ?? ?? ?? E9
at = entrypoint
requires = native, pe32
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma 5.X]
pattern = EB $$ E9 $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 81 ED ?? ?? ?? ?? E9
at = entrypoint
pattern.2 = 'Enigma Protector'
in.2 = section(#-1), section(#-2)
requires = native, pe32
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = second last section is searched even if the last section has raw data

[Enigma]
pattern = E8 $$$$$$$$ 83 C4 ?? E9 $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 81 ED ?? ?? ?? ?? E9
at = entrypoint
requires = native, pe32
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma 5.X]
pattern = E8 $$$$$$$$ 83 C4 ?? E9 $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 81 ED ?? ?? ?? ?? E9
at = entrypoint
pattern.2 = 'Enigma Protector'
in.2 = section(#-1), section(#-2)
requires = native, pe32
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = second last section is searched even if the last section has raw data

[Enigma]
pattern = 60 E8 00 00 00 00 5D 83 ?? ?? 81 ED
at = entrypoint
requires = native, pe32
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma]
pattern = EB $$ E9 $$$$$$$$ 60 E8 00 00 00 00 5D 83 ?? ?? 81 ED
at = entrypoint
requires = native, pe32
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma v1.14]
pattern = EB $$ E9 $$$$$$$$ 60 E8 00 00 00 00 5D 83 ?? ?? 81 ED
at = entrypoint
pattern.2 = 'ENIGMA' 07 ' PROT'
in.2 = section(#-1)
requires = native, pe32
type = protector
version = v1.14
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg

[Enigma]
pattern = 50 51 52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 48 9C 48 81 EC 08 00 00 00 0F AE 1C 24 E8 00 00 00 00 5D
at = entrypoint
requires = native, pe32+
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma 5.X]
pattern = 50 51 52 53 55 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 48 9C 48 81 EC 08 00 00 00 0F AE 1C 24 E8 00 00 00 00 5D
at = entrypoint
pattern.2 = 'Enigma Protector'
in.2 = section(#-1), section(#-2)
requires = native, pe32+
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = second last section is searched even if the last section has raw data

[Enigma]
pattern = EB $$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 81 ED ?? ?? ?? ?? E9
at = entrypoint
requires = native, pe32+
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

[Enigma 5.X]
pattern = EB $$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 81 ED ?? ?? ?? ?? E9
at = entrypoint
pattern.2 = 'Enigma Protector'
in.2 = section(#-1), section(#-2)
requires = native, pe32+
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = second last section is searched even if the last section has raw data

[Enigma]
pattern = 00 00 00 'ENIGMA'
in = section(#-1), section(#-2)
import = /!MessageBoxA$/
requires = native
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = MessageBoxA as the only function of the second imported library, flags 0xE0000040 of the first section not checked, second last section is searched even if the last section has raw data; version read from file

[Enigma 5.X]
pattern = 'Enigma Protector'
in = section(#-1), section(#-2)
import = /!MessageBoxA$/
requires = native
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = MessageBoxA as the only function of the second imported library, flags 0xE0000040 of the first section not checked, second last section is searched even if the last section has raw data

[Enigma]
section = enigma1, enigma2
requires = native
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = getSectionNameCollision("1", "2") == "enigma" approximated by the section names enigma1 and enigma2

[Enigma]
pattern = 60 64 8B 2D ?? ?? ?? ?? 3E 8B 6D ?? 3E 8B 6D ?? E8 ?? ?? ?? ?? BB ?? ?? ?? ?? C3
at = entrypoint
requires = native
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ENIGMA.2.sg
x-die-loss = version read from file

; protector_Escargot.2.sg
[Escargot 0.1]
pattern = EB 08 '(esc0.1)' 60 68
at = entrypoint
type = protector
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Escargot.2.sg

[Escargot 0.1 final]
pattern = EB 04 '@0.1' 60 68
at = entrypoint
type = protector
version = 0.1 final
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Escargot.2.sg

; protector_EsProtect.2.sg
[EsProtect 1.3-3.9, custom UPX]
pattern = F9
at = entrypoint
section = Esp0, Esp1, /^\.Esp!?$/
type = protector
version = 1.3-3.9, custom UPX
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_EsProtect.2.sg
x-die-loss = more than 3 sections, entry point and relocations in the last section, resources and imports in section 2, and the positions of the Esp0, Esp1 and .Esp! sections not checked

; protector_Excalibur.2.sg
[Excalibur 1.03 [by forgot/uS/DFCG]]
pattern = E9 $$$$$$$$ 60 E8 $$$$$$$$ 58 61 EB $$ 60 9C 9C 6A ?? 73 ?? EB
at = entrypoint
type = protector
version = 1.03
options = by forgot/uS/DFCG
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Excalibur.2.sg

; protector_Exe_Guarder.2.sg
[Exe Guarder 1.8]
pattern = 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00
at = entrypoint
type = protector
version = 1.8
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Exe_Guarder.2.sg

; protector_EXE_Password_Protector.2.sg
[EXE Password Protector 1.1]
pattern = 6A 60 68 10 B5 40 00 E8 2E 02 00 00 BF 94 00 00 00 8B C7 E8 22 F4 FF FF 89 65 E8 8B F4 89 3E 56 FF 15 10 B0 40 00 8B 4E 10 89 0D 00 ED 40 00 8B 46 04
at = entrypoint
type = protector
version = 1.1
author = Eliseu Filipi
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_EXE_Password_Protector.2.sg

; protector_Exe_Shield.2.sg
[Exe Shield 1.7]
pattern = EB 06 68 ?? ?? 06 00 C3 9C 60 E8 02 00 00
at = entrypoint
pattern.2 = 90 1F
at.2 = entrypoint + 0x3
type = protector
version = 1.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Exe_Shield.2.sg

[Exe Shield 2.7]
pattern = EB 06 68 ?? ?? 06 00 C3 9C 60 E8 02 00 00
at = entrypoint
pattern.2 = F4 86
at.2 = entrypoint + 0x3
type = protector
version = 2.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Exe_Shield.2.sg

[Exe Shield 2.7b]
pattern = EB 06 68 ?? ?? 06 00 C3 9C 60 E8 02 00 00
at = entrypoint
pattern.2 = 40 85
at.2 = entrypoint + 0x3
type = protector
version = 2.7b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Exe_Shield.2.sg

[Exe Shield]
pattern = EB 06 68 ?? ?? 06 00 C3 9C 60 E8 02 00 00
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Exe_Shield.2.sg

[Exe Shield 2.9]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 EB 08 00 00 8D BD ?? ?? ?? ?? 8B F7 AC ?? ?? ?? F8
at = entrypoint
type = protector
version = 2.9
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Exe_Shield.2.sg

[Exe Shield 1.3RC]
pattern = 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? ?? ?? 81 E9 ?? ?? ?? ?? 8B D5 81 C2
at = entrypoint
type = protector
version = 1.3RC
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Exe_Shield.2.sg

; protector_EXEFog.2.sg
[ExeFog 1.1]
pattern = 56 E8 $$$$$$$$ 5E 5E E9 $$$$$$$$ E8 $$$$$$$$ 5D 83 C5 ?? 55 C3
at = entrypoint
type = protector
version = 1.1
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_EXEFog.2.sg

[ExeFog 1.1]
pattern = 52 E8 $$$$$$$$ 83 C4 ?? 5A 8B E4 51 0F B6 C9 81 E5
at = entrypoint
type = protector
version = 1.1
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_EXEFog.2.sg

[ExeFog 1.1]
pattern = 65 45 C2 FB 19 5B BD 00 40 40 EB EF 91 55 F0 40 18 97 DB 00 24 E8 E8 00 00 00 83 87 20 2E 87 D1 78 20 FB 1C B8 00 B0 EF 0B 00 00 00 84 8E
in = entrypoint[0-0x1000]
type = protector
version = 1.1
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_EXEFog.2.sg

; protector_ExeSafeguard.2.sg
[ExeSafeguard 1.0]
section = .sg
import = advapi32.dll!RegOpenKeyA
requires = native, pe32
type = protector
version = 1.0
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeSafeguard.2.sg
x-die-loss = .sg being the last section with flags 0xE0000020 that holds the entry point at its start and the imports, and RegOpenKeyA being the only import not checked

; protector_ExeShield.2.sg
[ExeShield]
pattern = E8 04 00 00 00 83 60 EB 0C 5D EB 05
at = entrypoint
pattern.2 = 85 C0
at.2 = overlay
requires = rich
section = .shield
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeShield.2.sg
x-die-loss = number of imports (none) not checked

[ExeShield [modified]]
pattern = E8 04 00 00 00 83 60 EB 0C 5D EB 05
at = entrypoint
pattern.2 = 85 C0
at.2 = overlay
requires = rich
section = !.shield
type = protector
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeShield.2.sg
x-die-loss = number of imports (none) not checked

; protector_ExeStealth.2.sg
[ExeStealth 1.1]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 7B 09 00 00 8B F7 AC
at = entrypoint
type = protector
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth 2.5]
pattern = 60 90 EB 22 'ExeStealth'
at = entrypoint
type = protector
version = 2.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth 2.70-2.71]
pattern = EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED
at = entrypoint
type = protector
version = 2.70-2.71
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth 2.72-2.73 [Shareware]]
pattern = EB 00 EB 2F 'Shareware - ExeStealth' 00
at = entrypoint
type = protector
version = 2.72-2.73
options = Shareware
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth 2.74 [Shareware]]
pattern = EB 00 EB 17 'Shareware - ExeStealth' 00
at = entrypoint
type = protector
version = 2.74
options = Shareware
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth 2.75]
pattern = 90 60 90 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 15 00 00 00
at = entrypoint
type = protector
version = 2.75
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth 2.75a [Shareware]]
pattern = EB 58 'Shareware-Version ExeStealth'
at = entrypoint
type = protector
version = 2.75a
options = Shareware
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth 2.76 [Shareware]]
pattern = EB ?? 'ExeStealth V2 Shareware '
at = entrypoint
type = protector
version = 2.76
options = Shareware
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth 2.76]
pattern = EB 65 'ExeStealth V2 - www'
at = entrypoint
type = protector
version = 2.76
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth]
pattern = 'MZ'
at = resource(*/TN)
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

[ExeStealth]
resource = */TN
section = ExeS
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ExeStealth.2.sg

; protector_eXPressor.2.sg
[eXPressor 1.0]
pattern = E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.1]
pattern = E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02
at = entrypoint
type = protector
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.2]
pattern = 55 8B EC 81 EC ?? ?? 00 00 53 56 57 EB 0C 'ExPr-v.1.2.'
at = entrypoint
type = protector
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.3]
pattern = 55 8B EC 83 EC ?? 53 56 57 EB 0C 'ExPr-v.1.3.'
at = entrypoint
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.4]
pattern = 55 8B EC 83 EC ?? 53 56 57 EB 0C 'ExPr-v.1.4.'
at = entrypoint
type = protector
version = 1.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.4]
pattern = 8B EC 83 EC ?? 53 56 57 83 65 ?? ?? F3 EB 0C 'eXPr-v.1.4.'
at = entrypoint
type = protector
version = 1.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.4.5.X]
pattern = 55 8B EC 83 EC ?? 53 56 57 83 65 ?? 00 F3 EB 0C 'eXPr-v.1.4.' 00
at = entrypoint
type = protector
version = 1.4.5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.5.0.X]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 'eXPr-v.1.5.' 00
at = entrypoint
type = protector
version = 1.5.0.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.6]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 'eXPr-v.1.6.'
at = entrypoint
type = protector
version = 1.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.6]
pattern = ?? 68 ?? ?? ?? ?? E8 $$$$$$$$ ?? ?? 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 'eXPr-v.1.6.'
at = entrypoint
type = protector
version = 1.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.6]
pattern = 6A ?? 68 ?? ?? ?? ?? E8 $$$$$$$$ ?? ?? 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 'eXPr-v.1.6.'
at = entrypoint
type = protector
version = 1.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.6]
pattern = 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? E8 $$$$$$$$ ?? ?? 81 EC ?? ?? ?? ?? 53 56 57 83 A5 ?? ?? ?? ?? ?? F3 EB 0C 'eXPr-v.1.6.'
at = entrypoint
type = protector
version = 1.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor]
pattern = EB 01 68 EB 01 ?? ?? ?? ?? 83 EC 0C 53 56 57 EB 01 ?? 83 3D ?? ?? ?? ?? 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

[eXPressor 1.6.1]
pattern = 68 ######## EB $$ EB $$ 55 8B EC 83 EC ?? 53 56 57 EB $$ 83 3D ?? ?? ?? ?? ?? 74
at = entrypoint
type = protector
version = 1.6.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_eXPressor.2.sg

; protector_FISH_.NET.2.sg
[FISH .NET 1.X]
pattern = 08 00 'FISH_NET'
in = section(#0)
requires = dotnet
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_FISH_.NET.2.sg

[FISH .NET 1.X]
pattern = 'FISH.NET'
in = section(#0)
requires = dotnet
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_FISH_.NET.2.sg

; protector_Fish_PE.2.sg
[Fish PE 1.2]
pattern = 60 E8 07 00 00 00 61 68 ?? ?? ?? ?? C3 5E 56
at = entrypoint
type = protector
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Fish_PE.2.sg
x-die-loss = number of sections (2) and raw size 0 of the first section not checked

[Fish PE 1.3]
pattern = 60 E8 21 00 00 00 EB $$ 61 68 ?? ?? ?? ?? C3 5E 56
at = entrypoint
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Fish_PE.2.sg
x-die-loss = number of sections (2) and raw size 0 of the first section not checked

; protector_FishPE_Shield.2.sg
[FishPE Shield 1.12/1.16]
pattern = 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC
at = entrypoint
type = protector
version = 1.12/1.16
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_FishPE_Shield.2.sg

[FishPE Shield 1.12/1.16]
pattern = 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00
at = entrypoint
type = protector
version = 1.12/1.16
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_FishPE_Shield.2.sg

[FishPE Shield 1.0X]
pattern = 60 E8 ?? ?? ?? ?? C3 90 09 00 00 00 2C 00 00 00 ?? ?? ?? ?? C4 03 00 00 BC A0 00 00 00 40 01 00
at = entrypoint
type = protector
version = 1.0X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_FishPE_Shield.2.sg

[FishPE Shield 2.0.1]
pattern = 60 E8 ?? ?? ?? ?? 61 C3
at = entrypoint
pattern.2 = 60 E8 $$$$$$$$ 55 8B EC 81 C4 70 FF FF FF 53 56 57
at.2 = entrypoint
type = protector
version = 2.0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_FishPE_Shield.2.sg

; protector_FlashBack_Protector.2.sg
[FlashBack 1.0]
pattern = 60 60 9C 8C C9 32 C9 E3 $$ 9D 61 90 60 90 61 EB $$ 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8
at = entrypoint
type = protector
version = 1.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_FlashBack_Protector.2.sg

; protector_G!X_Protector.2.sg
[G!X Protector 1.2]
pattern = 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00
at = entrypoint
type = protector
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_G!X_Protector.2.sg

; protector_GameGuard.2.sg
[GameGuard 2006.5.X.X]
pattern = 31 FF 74 06 61 E9 'JMP0'
at = entrypoint
type = protector
version = 2006.5.X.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_GameGuard.2.sg

; protector_Goats_PE_Mutilator.2.sg
[Goat's PE Mutilator 1.6]
pattern = E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D
at = entrypoint
type = protector
version = 1.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Goats_PE_Mutilator.2.sg

; protector_Goliath.2.sg
[Goliath [demo]]
pattern = 20 00 65 00 76 00 61 00 6C 00 75 00 61 00 74 00 65 00
in = section(#0)
section = .GOLIATH
dotnet_string = ObfuscatedByGoliath
type = protector
options = demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Goliath.2.sg

[Goliath]
section = .GOLIATH
dotnet_string = ObfuscatedByGoliath
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Goliath.2.sg

[Goliath [demo]]
pattern = '.Goliath.NET.CodeShield.'
in = section(#0)
pattern.2 = 20 00 65 00 76 00 61 00 6C 00 75 00 61 00 74 00 65 00
in.2 = section(#0)
section = .GOLIATH
dotnet_string = !ObfuscatedByGoliath
type = protector
options = demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Goliath.2.sg

[Goliath]
pattern = '.Goliath.NET.CodeShield.'
in = section(#0)
section = .GOLIATH
dotnet_string = !ObfuscatedByGoliath
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Goliath.2.sg

; protector_GuardantStealth.2.sg
[Guardant Stealth]
import = novex32.dll
type = protector
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_GuardantStealth.2.sg
x-die-loss = DIE requires NOVEX32.dll to be the only imported library

; protector_HackShield.2.sg
[HackShield]
pattern = 'TerminateHackShield'
in = section[0-0x2048]
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HackShield.2.sg
x-die-loss = DIE searches only the first 0x2048 bytes of the section that holds the import directory

; protector_HASP.2.sg
[HASP Protection [1997 by Aladdin Knowledge Systems Ltd.]]
pattern = 6A ?? 60 2E FF 35 ?? ?? ?? ?? 2E FF 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 83 C4 ?? 2E FF 35 ?? ?? ?? ?? 2E FF 35 ?? ?? ?? ?? B8 ?? ?? ?? ?? 83 C0 ?? 50
at = entrypoint
type = protector
options = 1997 by Aladdin Knowledge Systems Ltd.
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HASP.2.sg

; protector_Hide&Protect.2.sg
[Hide&Protect 1.016]
pattern = 90 90 90 E9 D8 ?? 05 00 95 ?? 53 00 95 4A 50 00
at = entrypoint
type = protector
version = 1.016
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Hide&Protect.2.sg

[Hide&Protect 1.016]
pattern = 90 90 90 E9 ?? ?? ?? ?? 00 00 00 00 00 00 00 00
at = entrypoint
type = protector
version = 1.016
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Hide&Protect.2.sg

; protector_HidePE.2.sg
[HidePE by BGCorp 0.1 [32Lite 0.03]]
pattern = 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68
at = entrypoint
type = protector
version = 0.1
options = 32Lite 0.03
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [ACProtect 1.09]]
pattern = 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
at = entrypoint
type = protector
version = 0.1
options = ACProtect 1.09
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Armadillo 3.00]]
pattern = 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85
at = entrypoint
type = protector
version = 0.1
options = Armadillo 3.00
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [ASPack 2.XX]]
pattern = 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95
at = entrypoint
type = protector
version = 0.1
options = ASPack 2.XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [ASProtect]]
pattern = 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD
at = entrypoint
type = protector
version = 0.1
options = ASProtect
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 1.2 [ASProtect]]
pattern = 68 ######## 6F 40 67 48 5E 68 ?? ?? ?? ?? 67 49 4E 68 ?? ?? ?? ?? 50 46 6F
at = entrypoint
type = protector
version = 1.2
options = ASProtect
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Borland Delphi 3.0]]
pattern = 55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
at = entrypoint
type = protector
version = 0.1
options = Borland Delphi 3.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Borland Delphi 5.0 KOL/MCK]]
pattern = 55 8B EC 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90
at = entrypoint
type = protector
version = 0.1
options = Borland Delphi 5.0 KOL/MCK
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Borland Delphi 6.0-7.0]]
pattern = 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8
at = entrypoint
type = protector
version = 0.1
options = Borland Delphi 6.0-7.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [CD-Cops II]]
pattern = 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01
at = entrypoint
type = protector
version = 0.1
options = CD-Cops II
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [CodeSafe 2.0]]
pattern = 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85
at = entrypoint
type = protector
version = 0.1
options = CodeSafe 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Crunch]]
pattern = 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00
at = entrypoint
type = protector
version = 0.1
options = Crunch
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [DEF 1.0]]
pattern = BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01
at = entrypoint
type = protector
version = 0.1
options = DEF 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [DxPack 1.0]]
pattern = 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00
at = entrypoint
type = protector
version = 0.1
options = DxPack 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [ExeSmasher]]
pattern = 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B
at = entrypoint
type = protector
version = 0.1
options = ExeSmasher
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [FSG 1.0]]
pattern = 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B
at = entrypoint
type = protector
version = 0.1
options = FSG 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [FSG 1.31]]
pattern = BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80
at = entrypoint
type = protector
version = 0.1
options = FSG 1.31
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Gleam 1.00]]
pattern = 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF
at = entrypoint
type = protector
version = 0.1
options = Gleam 1.00
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [JDPack 1.X/JDProtect 0.9]]
pattern = 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01
at = entrypoint
type = protector
version = 0.1
options = JDPack 1.X/JDProtect 0.9
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [LCC Win32 1.X]]
pattern = 64 A1 01 00 00 00 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 90 50
at = entrypoint
type = protector
version = 0.1
options = LCC Win32 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [LCC Win32 DLL]]
pattern = 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1
at = entrypoint
type = protector
version = 0.1
options = LCC Win32 DLL
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Lockless Intro Pack]]
pattern = 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD
at = entrypoint
type = protector
version = 0.1
options = Lockless Intro Pack
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [LTC 1.3]]
pattern = 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06
at = entrypoint
type = protector
version = 0.1
options = LTC 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Macromedia Flash Projector 6.0]]
pattern = 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C
at = entrypoint
type = protector
version = 0.1
options = Macromedia Flash Projector 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [MEW 11 SE 1.0]]
pattern = E9 09 00 00 00 00 00 00 02 00 00 00 0C 90
at = entrypoint
type = protector
version = 0.1
options = MEW 11 SE 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Microsoft Visual Basic 5.0-6.0]]
pattern = 68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00
at = entrypoint
type = protector
version = 0.1
options = Microsoft Visual Basic 5.0-6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Microsoft Visual Basic 6.0 DLL]]
pattern = 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF
at = entrypoint
type = protector
version = 0.1
options = Microsoft Visual Basic 6.0 DLL
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Microsoft Visual C++ 5.0+/MFC]]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9
at = entrypoint
type = protector
version = 0.1
options = Microsoft Visual C++ 5.0+/MFC
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Microsoft Visual C++ 6.0/Debug Version]]
pattern = 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90
at = entrypoint
type = protector
version = 0.1
options = Microsoft Visual C++ 6.0/Debug Version
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Microsoft Visual C++ 6.20]]
pattern = 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 55 8B EC 83 EC 50 53 56 57 BE 90 90 90 90 8D 7D F4 A5 A5 66 A5 8B
at = entrypoint
type = protector
version = 0.1
options = Microsoft Visual C++ 6.20
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Microsoft Visual C++ 7.0 DLL]]
pattern = 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84
at = entrypoint
type = protector
version = 0.1
options = Microsoft Visual C++ 7.0 DLL
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [MinGW GCC 2.X]]
pattern = 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45
at = entrypoint
type = protector
version = 0.1
options = MinGW GCC 2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Neolite 2.0]]
pattern = E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
at = entrypoint
type = protector
version = 0.1
options = Neolite 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [NorthStar PE Shrinker 1.3]]
pattern = 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00
at = entrypoint
type = protector
version = 0.1
options = NorthStar PE Shrinker 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Pack Master 1.0/PEX Clone]]
pattern = 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
at = entrypoint
type = protector
version = 0.1
options = Pack Master 1.0/PEX Clone
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [PE Intro 1.0]]
pattern = 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A
at = entrypoint
type = protector
version = 0.1
options = PE Intro 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [PE Pack 0.99]]
pattern = 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A
at = entrypoint
type = protector
version = 0.1
options = PE Pack 0.99
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [PE Protect 0.9]]
pattern = 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3
at = entrypoint
type = protector
version = 0.1
options = PE Protect 0.9
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [PECompact 1.4+]]
pattern = 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81
at = entrypoint
type = protector
version = 0.1
options = PECompact 1.4+
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [PENightMare 2 Beta]]
pattern = 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A
at = entrypoint
type = protector
version = 0.1
options = PENightMare 2 Beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [PESHiELD 0.25]]
pattern = 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC
at = entrypoint
type = protector
version = 0.1
options = PESHiELD 0.25
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [PEtite 2.X/level 0]]
pattern = 90 90 90 90 68 ?? ?? ?? ?? 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 B8 00 90 90 00 6A 00 68 90 90 90 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68
at = entrypoint
type = protector
version = 0.1
options = PEtite 2.X/level 0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [PEX 0.99]]
pattern = 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01
at = entrypoint
type = protector
version = 0.1
options = PEX 0.99
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [REALBasic]]
pattern = 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01
at = entrypoint
type = protector
version = 0.1
options = REALBasic
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Ste@lth PE 1.01]]
pattern = 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA ?? ?? ?? ?? FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00
at = entrypoint
type = protector
version = 0.1
options = Ste@lth PE 1.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [UPX 0.6]]
pattern = 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00
at = entrypoint
type = protector
version = 0.1
options = UPX 0.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [VBOX 4.3 MTE]]
pattern = 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0
at = entrypoint
type = protector
version = 0.1
options = VBOX 4.3 MTE
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Video-Lan-Client]]
pattern = 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01
at = entrypoint
type = protector
version = 0.1
options = Video-Lan-Client
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [VOB ProtectCD 5]]
pattern = 36 3E 26 8A C0 60 E8 00 00 00 00
at = entrypoint
type = protector
version = 0.1
options = VOB ProtectCD 5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [WATCOM C/C++ EXE]]
pattern = E9 00 00 00 00 90 90 90 90 57 41
at = entrypoint
type = protector
version = 0.1
options = WATCOM C/C++ EXE
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [XCR 0.11]]
pattern = 60 8B F0 33 DB 83 C3 01 83 C0 01
at = entrypoint
type = protector
version = 0.1
options = XCR 0.11
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Yoda's Protector 1.02]]
pattern = E8 03 00 00 00 EB 01 90 90
at = entrypoint
type = protector
version = 0.1
options = Yoda's Protector 1.02
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.1 [Morphine 1.2]]
pattern = 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 E2 90 90 90 EB 08 82 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 01
at = entrypoint
type = protector
version = 0.1
options = Morphine 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.2 [BJFNT 1.1b]]
pattern = EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90
at = entrypoint
type = protector
version = 0.2
options = BJFNT 1.1b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.2 [BJFNT 1.2]]
pattern = EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00
at = entrypoint
type = protector
version = 0.2
options = BJFNT 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.2 [Borland C++]]
pattern = EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90
at = entrypoint
type = protector
version = 0.2
options = Borland C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.2 [Borland Delphi DLL]]
pattern = 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00
at = entrypoint
type = protector
version = 0.2
options = Borland Delphi DLL
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.2 [Borland Delphi Setup Module]]
pattern = 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00
at = entrypoint
type = protector
version = 0.2
options = Borland Delphi Setup Module
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 0.2 [ZCode 1.01]]
pattern = E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00
at = entrypoint
type = protector
version = 0.2
options = ZCode 1.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

[HidePE by BGCorp 1.01]
pattern = ?? BA ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 04 B8 ?? ?? ?? ?? 89 02 83 C2 F8 FF E2 '\x0D\x0A-=[ HidePE by BHCorp ]=-'
at = entrypoint
type = protector
version = 1.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HidePE.2.sg

; protector_HyperTech_Crackproof.2.sg
[HyperTech Crackproof]
pattern = 'KeRnEl32.dLl'
in = image
import = kernel32.dll
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_HyperTech_Crackproof.2.sg
x-die-loss = DIE requires the first imported library to be named exactly KeRnEl32.dLl, the entry searches the name anywhere in the image

; protector_ILProtector.2.sg
[ILProtector]
requires = dotnet
dotnet_string = Protect32.dll, Protect64.dll
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ILProtector.2.sg
x-die-loss = global .cctor not checked

; protector_ILUCRYPT.2.sg
[ILUCRYPT 4.015]
pattern = 8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7
at = entrypoint
type = protector
version = 4.015
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ILUCRYPT.2.sg

[ILUCRYPT 4.018]
pattern = 8B EC FA C7 ?? ?? ?? ?? 4C 4C C3 FB BF ?? ?? B8 ?? ?? 2E ?? ?? D1 C8 4F 81
at = entrypoint
type = protector
version = 4.018
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ILUCRYPT.2.sg

; protector_Inquartos_Obfuscator.2.sg
[Inquartos Obfuscator]
pattern = E8 $$$$$$$$ BB ?? ?? ?? ?? E8 $$$$$$$$ E8 $$$$$$$$ 33 C0 64 FF 30 64 89 20 4B CC C3
at = entrypoint
section = .inq
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Inquartos_Obfuscator.2.sg

; protector_IntelliProtector.2.sg
[IntelliProtector]
pattern = E9 ?? ?? ?? ?? CC
at = section(#-1)
pattern.2 = 'Protected by IntelliProtector'
in.2 = section(#-1)
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_IntelliProtector.2.sg
x-die-loss = version read from file

; protector_InxObfuscator.2.sg
[Inx Obfuscator]
pattern = 00 13 'Inx .NET Obfuscator' 00 00
in = image
requires = dotnet
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_InxObfuscator.2.sg

; protector_iPB_Protect.2.sg
[iPB Protect 0.1.3-0.1.7]
pattern = 55 8B EC 6A FF 68 'KCUF' 68 'TIHS' 64 A1 00 00 00 00
at = entrypoint
type = protector
version = 0.1.3-0.1.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_iPB_Protect.2.sg

; protector_IProtect.2.sg
[IProtect 1.0 [FxLib.dll mode]]
pattern = EB 33 '.FUXLoadLibraryA' 00
at = entrypoint
pattern.2 = 'FxLib.dll' 00
at.2 = entrypoint + 0x13
type = protector
version = 1.0
options = FxLib.dll mode
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_IProtect.2.sg

[IProtect 1.0 [FxSub.dll mode]]
pattern = EB 33 '.FUXLoadLibraryA' 00
at = entrypoint
pattern.2 = 'FxSub.dll' 00
at.2 = entrypoint + 0x13
type = protector
version = 1.0
options = FxSub.dll mode
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_IProtect.2.sg

[IProtect 1.0]
pattern = EB 33 '.FUXLoadLibraryA' 00
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_IProtect.2.sg

; protector_Jar2exe.1.sg
[Jar2Exe [x86]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15 ?? ?? ?? ?? 33 D2 8A D4 89 15 ?? ?? ?? ?? 8B C8 81 E1 ?? ?? ?? ?? 89 0D
at = entrypoint
pattern.2 = EF BB BF
at.2 = overlay
pattern.3 = 50 4B 03 04
in.3 = overlay[0-0xFF]
type = protector
options = x86
lang = Java
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Jar2exe.1.sg

[Jar2Exe [x64]]
pattern = 48 83 EC ?? 48 89 5C 24 ?? 48 89 7C 24 ?? FF 15 ?? ?? ?? ?? 48 8B C8 33 D2 41 B8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 ?? B8 ?? ?? ?? ?? E9
at = entrypoint
pattern.2 = EF BB BF
at.2 = overlay
pattern.3 = 50 4B 03 04
in.3 = overlay[0-0xFF]
type = protector
options = x64
lang = Java
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Jar2exe.1.sg

[Jar2Exe]
pattern = EB $$ A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 52 6A ?? E8 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? 5A E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A
at = entrypoint
pattern.2 = EF BB BF
at.2 = overlay
pattern.3 = 50 4B 03 04
in.3 = overlay[0-0xFF]
type = protector
lang = Java
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Jar2exe.1.sg

[Jar2Exe]
pattern = EB $$ A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 52 6A ?? E8 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? 5A E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A
at = entrypoint
pattern.2 = 50 4B 03 04
at.2 = overlay
type = protector
lang = Java
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Jar2exe.1.sg

; protector_kkryptor.2.sg
[k.kryptor 3]
pattern = EB $$ 60 E8 ?? ?? ?? ?? 5E 8D ?? ?? B9 ?? ?? ?? ?? 49 33 C0 51 02 ?? ?? D3 C0 49 79 ?? 33 ?? ?? 59 00
at = entrypoint
type = protector
version = 3
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_kkryptor.2.sg

; protector_KoiVM.2.sg
[KoiVM 2.0+]
pattern = 'KoiVM'
in = section(#0)
requires = dotnet
type = protector
version = 2.0+
author = r0da, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_KoiVM.2.sg
x-die-loss = DIE reports it only if at most one other protector was detected

[KoiVM 2.0+]
pattern = 'VMEntryRun'
in = section(#0)
requires = dotnet
type = protector
version = 2.0+
author = r0da, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_KoiVM.2.sg
x-die-loss = DIE reports it only if at most one other protector was detected

; protector_Konekt_Protector.2.sg
[Konekt Protector]
pattern = FC 55 50 E8 $$$$$$$$ 5D 50 E8 $$$$$$$$ EB $$ 58 EB $$ 40 EB $$ FF E0
at = entrypoint
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Konekt_Protector.2.sg

; protector_Krypton.2.sg
[Krypton 0.2]
pattern = 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04
at = entrypoint
type = protector
version = 0.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Krypton.2.sg

[Krypton 0.3]
pattern = 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA
at = entrypoint
type = protector
version = 0.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Krypton.2.sg

[Krypton 0.4]
pattern = 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85
at = entrypoint
pattern.2 = 83 E8 06
at.2 = entrypoint + 0x15
type = protector
version = 0.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Krypton.2.sg

[Krypton 0.5]
pattern = 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85
at = entrypoint
pattern.2 = EB 43 DF
at.2 = entrypoint + 0x15
type = protector
version = 0.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Krypton.2.sg

[Krypton]
pattern = 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Krypton.2.sg

; protector_LameCrypt.2.sg
[LameCrypt 1.0]
pattern = 60 66 9C BB ?? ?? ?? ?? 80 B3 ?? ?? ?? ?? 90 4B 83 FB FF 75 F3 66 9D 61
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_LameCrypt.2.sg

; protector_LARP.2.sg
[LARP 2.0]
pattern = E8 $$$$$$$$ E8 $$$$$$$$ E8 $$$$$$$$ E8 $$$$$$$$ 5D 81 ED ?? ?? ?? ?? 83 04 24 ?? 83 C4 ?? FF 64 24
at = entrypoint
type = protector
version = 2.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_LARP.2.sg

; protector_LaserLock.2.sg
[LaserLock]
pattern = EB $$ EB $$ 50 55 E8 $$$$$$$$ 5D 50 8B C5 81 ED ?? ?? ?? ?? 2D ?? ?? ?? ?? 3E 2B 85 ?? ?? ?? ?? 3E 89 85 ?? ?? ?? ?? 60 8D 85 ?? ?? ?? ?? 50 8D 9D ?? ?? ?? ?? 2B D8 53
at = entrypoint
type = protector
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_LaserLock.2.sg

; protector_LDK.2.sg
[SafeNet Sentinel LDK]
section = .AKS1, .AKS2, .AKS3, .rsrc
type = protector
author = sendersu
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_LDK.2.sg
x-die-loss = number of sections (4) not checked

; protector_LDK_.NET.2.sg
[SafeNet Sentinel LDK .NET]
requires = dotnet
dotnet_string = .protect, haspdnert.dll
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_LDK_.NET.2.sg

; protector_MaskPE.2.sg
[MaskPE 2.0]
pattern = 60
at = entrypoint
pattern.2 = 61 60 E8 ?? ?? ?? ?? 8B C3 3E 8B ?? 40 E8
in.2 = entrypoint[0-0x100]
section = .MaskPE
type = protector
version = 2.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MaskPE.2.sg

; protector_Maxtocode.2.sg
[Maxtocode 1.X [Runtime]]
requires = dotnet
dotnet_string = Attick.dll, CheckRuntime
type = protector
version = 1.X
options = Runtime
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Maxtocode.2.sg

[Maxtocode 1.X]
pattern = 00 'InfaceMax ' FF FF FF 00 5F 17 59 20 FF FF 00 'toCode_interface' 00
in = section(#0)
requires = dotnet
dotnet_string = !Attick.dll
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Maxtocode.2.sg

[Maxtocode 3.X]
requires = dotnet
dotnet_string = !Attick.dll, MRuntime3.dll
type = protector
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Maxtocode.2.sg

[Maxtocode 1.X]
pattern = 00 'InfaceMax ' FF FF FF 00 5F 17 59 20 FF FF 00 'toCode_interface' 00
in = section(#0)
requires = dotnet
dotnet_string = !CheckRuntime
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Maxtocode.2.sg

[Maxtocode 3.X]
requires = dotnet
dotnet_string = !CheckRuntime, MRuntime3.dll
type = protector
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Maxtocode.2.sg

; protector_Metrowerks_CodeWarrior.2.sg
[Metrowerks CodeWarrior 2.0]
pattern = 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8
at = entrypoint
type = protector
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Metrowerks_CodeWarrior.2.sg

[Metrowerks CodeWarrior 2.0]
pattern = 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68
at = entrypoint
type = protector
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Metrowerks_CodeWarrior.2.sg

; protector_Morphnah.2.sg
[Morphnah 1.0.7]
pattern = 55 8B EC 87 E5 5D E9 $$$$$$$$ 55 8B EC 83 EC ?? 53 56 57 60 64 A1 ?? ?? ?? ?? 8B 40 ?? 89 45 ?? 64 A1 ?? ?? ?? ?? C7 40
at = entrypoint
type = protector
version = 1.0.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Morphnah.2.sg

[Morphnah 1.0.2]
pattern = 60 E8 $$$$$$$$ 5D 81 ED ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? B8 ?? ?? ?? ?? 01 E8 80 30 ?? 83 F9 ?? 74 ?? 81 7F ?? ?? ?? ?? ?? 75 ?? 8B 57
at = entrypoint
section = .nah
type = protector
version = 1.0.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Morphnah.2.sg

[Morphnah 1.0.3]
pattern = 60 E8 $$$$$$$$ 5D 81 ED ?? ?? ?? ?? 31 C0 40 83 F0 ?? 40 3D ?? ?? ?? ?? 75 ?? BE ?? ?? ?? ?? EB ?? EB ?? 8B 85 ?? ?? ?? ?? 83 F8 ?? 75 ?? 31 C0 01 EE 3D
at = entrypoint
section = .nah
type = protector
version = 1.0.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Morphnah.2.sg

[Morphnah beta 2]
pattern = EB $$ 60 8B 4C ?? ?? 87 D1 87 D1 8B 09 3B ED
at = entrypoint
section = .nah
type = protector
version = beta 2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Morphnah.2.sg

; protector_MSLRH.2.sg
[MSLRH 0.32a [fake .BJFNT 1.3]]
pattern = EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50
at = entrypoint
type = protector
version = 0.32a
options = fake .BJFNT 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake ASPack 2.11d]]
pattern = 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75
at = entrypoint
type = protector
version = 0.32a
options = fake ASPack 2.11d
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake ASPack 2.12]]
pattern = 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03
at = entrypoint
type = protector
version = 0.32a
options = fake ASPack 2.12
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake ASPack 2.12]]
pattern = 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 73 00 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B
at = entrypoint
type = protector
version = 0.32a
options = fake ASPack 2.12
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake EXE32Pack 1.3X]]
pattern = 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 90 83 C4 14 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00
at = entrypoint
type = protector
version = 0.32a
options = fake EXE32Pack 1.3X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake Microsoft Visual C++]]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00
at = entrypoint
type = protector
version = 0.32a
options = fake Microsoft Visual C++
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake MSVC++ 6.0 DLL]]
pattern = 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58
at = entrypoint
type = protector
version = 0.32a
options = fake MSVC++ 6.0 DLL
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake MSVC++ 7.0 DLL Method 3]]
pattern = 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB
at = entrypoint
type = protector
version = 0.32a
options = fake MSVC++ 7.0 DLL Method 3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake MSVC++ DLL Method 4]]
pattern = 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75
at = entrypoint
type = protector
version = 0.32a
options = fake MSVC++ DLL Method 4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake Neolite 2.0]]
pattern = E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 'NeoLite Executable File Compressor\x0D\x0ACopyright (c) 1998' 2C 31
at = entrypoint
type = protector
version = 0.32a
options = fake Neolite 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake nSPack 1.3]]
pattern = 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74
at = entrypoint
type = protector
version = 0.32a
options = fake nSPack 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PC-Guard 4.XX]]
pattern = FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58
at = entrypoint
type = protector
version = 0.32a
options = fake PC-Guard 4.XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PE Crypt 1.02]]
pattern = E8 00 00 00 00 5B 83 EB 05 EB 04 'RND!' 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB
at = entrypoint
type = protector
version = 0.32a
options = fake PE Crypt 1.02
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PE Lock NT 2.04]]
pattern = EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 EB EB 03 CD 20 03 61 9D 83 C4 04 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83
at = entrypoint
type = protector
version = 0.32a
options = fake PE Lock NT 2.04
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PEBundle 0.2-3.X]]
pattern = 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02
at = entrypoint
type = protector
version = 0.32a
options = fake PEBundle 0.2-3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PEBundle 2.0X-2.4X]]
pattern = 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 83 BD 9C 38 40 00 01 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29
at = entrypoint
type = protector
version = 0.32a
options = fake PEBundle 2.0X-2.4X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PECompact 1.4X]]
pattern = EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A
at = entrypoint
type = protector
version = 0.32a
options = fake PECompact 1.4X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PESHiELD 0.25]]
pattern = 60 E8 2B 00 00 00 '\x0D\x0A\x0D\x0A\x0D\x0ARegistAred to: NON-COMMERCIAL!!\x0D\x0A\x0D\x0A\x0D' 00 58 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04
at = entrypoint
type = protector
version = 0.32a
options = fake PESHiELD 0.25
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PEtite 2.1]]
pattern = B8 ?? ?? ?? ?? 6A 00 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB
at = entrypoint
type = protector
version = 0.32a
options = fake PEtite 2.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake PEX 0.99]]
pattern = 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83
at = entrypoint
type = protector
version = 0.32a
options = fake PEX 0.99
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake SVKP 1.11]]
pattern = 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4
at = entrypoint
type = protector
version = 0.32a
options = fake SVKP 1.11
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake UPX 0.89.6-1.02/1.05-1.24]]
pattern = 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40
at = entrypoint
type = protector
version = 0.32a
options = fake UPX 0.89.6-1.02/1.05-1.24
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake WWPack32 1.X]]
pattern = 53 55 8B E8 33 DB EB $$ E8 00 00 00 00 58 2D ?? ?? ?? ?? 50 60 33 C9 50 58 50 50 8B E8 51 FD 2E 2B 84 ?? ?? ?? ?? ?? 8B F0 2E 03 B4 ?? ?? ?? ?? ?? 8B F8
at = entrypoint
type = protector
version = 0.32a
options = fake WWPack32 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a [fake Yoda's Cryptor 1.2]]
pattern = 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC 90 2C 8A C0 C0 78 90 04 62 EB 01 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00
at = entrypoint
type = protector
version = 0.32a
options = fake Yoda's Cryptor 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.1-0.2]
pattern = 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8
at = entrypoint
type = protector
version = 0.1-0.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.31]
pattern = 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1
at = entrypoint
type = protector
version = 0.31
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.32a]
pattern = EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03
at = entrypoint
type = protector
version = 0.32a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

[MSLRH 0.31a]
pattern = 55 8B EC 56 57 BF ?? ?? ?? ?? 8B 75 ?? 85 F6 5F 5E 5D EB $$ EB $$ EB $$ E8 $$$$$$$$ E8 $$$$$$$$ EB $$ 83 C4
at = entrypoint
type = protector
version = 0.31a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MSLRH.2.sg

; protector_MZ0oPE.2.sg
[MZ0oPE 1.0.6b]
pattern = EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68
at = entrypoint
type = protector
version = 1.0.6b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_MZ0oPE.2.sg

; protector_N-Code.2.sg
[N-Code 0.2]
pattern = 90 66 BE ?? ?? 66 83 FE ?? 74 ?? 66 B8 ?? ?? 66 BE ?? ?? 66 83 FE ?? 74 ?? 66 83 E8 ?? 66 BB ?? ?? 66 83 C3 ?? 66 43 66 81 FB ?? ?? 74 ?? 66 83 F8
at = entrypoint
type = protector
version = 0.2
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_N-Code.2.sg

; protector_N-Joy.2.sg
[N-Joy 1.0]
pattern = 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FF FF 6A 00 68 ?? ?? ?? ?? 6A 0A 6A 00 E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00
at = entrypoint
pattern.2 = EF F5
at.2 = entrypoint + 0x21
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_N-Joy.2.sg

[N-Joy 1.1]
pattern = 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FF FF 6A 00 68 ?? ?? ?? ?? 6A 0A 6A 00 E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00
at = entrypoint
pattern.2 = 7F F5
at.2 = entrypoint + 0x21
type = protector
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_N-Joy.2.sg

[N-Joy 1.2]
pattern = 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FF FF 6A 00 68 ?? ?? ?? ?? 6A 0A 6A 00 E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00
at = entrypoint
pattern.2 = C7 EA
at.2 = entrypoint + 0x21
type = protector
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_N-Joy.2.sg

[N-Joy 1.3]
pattern = 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FF FF 6A 00 68 ?? ?? ?? ?? 6A 0A 6A 00 E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00
at = entrypoint
pattern.2 = 23 E7
at.2 = entrypoint + 0x21
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_N-Joy.2.sg

[N-Joy]
pattern = 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FF FF 6A 00 68 ?? ?? ?? ?? 6A 0A 6A 00 E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_N-Joy.2.sg

; protector_NET_Spider.2.sg
[.NET Spider 0.5-1.3]
pattern = 'Protected_By_Attribute' 00 'NETSpider.Attribute'
in = section(#0)
requires = dotnet
type = protector
version = 0.5-1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NET_Spider.2.sg

; protector_NetReactor.2.sg
[.NET Reactor 2.X-3.X]
pattern = 55 8B EC B9 0F 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? ?? E8
at = entrypoint
section = !.reacto
type = protector
version = 2.X-3.X
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg

[.NET Reactor 4.2]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC 10
at = entrypoint
pattern.2 = E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 0C 68
at.2 = entrypoint
resource = */__
section = !.reacto
type = protector
version = 4.2
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg

[.NET Reactor 4.5-4.7]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC 10
at = entrypoint
pattern.2 = E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B FF 55 8B EC 83 EC 20 8B 45 08 56 57
at.2 = entrypoint
resource = */__
section = !.reacto
type = protector
version = 4.5-4.7
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg

[.NET Reactor 3.X]
pattern = 55 8B EC B9 0F 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? ?? ?? ?? E8
in = section(#0)
requires = dotnet
section = !.reacto
dotnet_string = !NecroVM.Runtime
type = protector
version = 3.X
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg

[.NET Reactor 4.8-4.9]
pattern = 52 66 68 6E 20 4D 18 22 76 B5 33 11 12 33 0C 6D 0A 20 4D 18 22 9E A1 29 61 1C 76 B5 05 19 01 58
in = section(#1)
requires = dotnet
section = !.reacto
dotnet_string = !NecroVM.Runtime
type = protector
version = 4.8-4.9
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg
x-die-loss = characteristics of section 1 (0xC0000040) not checked

[.NET Reactor 6.X [Control Flow]]
pattern = 'm_' %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% 00 'm_' %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% 00 'm_' %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% 00 'm_' %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% 00 'm_' %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% %% 00
in = section(#0)
requires = dotnet
section = !.reacto
dotnet_string = !NecroVM.Runtime
type = protector
version = 6.X
options = Control Flow
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg

[.NET Reactor 6.5]
pattern = '$$method0x' 36 30 30 30 33 31 37 2D 31 00 24 24 6D 65 74 68 6F 64 30 78 36 30 30 30 33 33 32 2D 31 00 24 24 6D 65 74 68 6F 64 30 78 36 30 30 30 33 33 32 2D 32 00 24 24 6D 65 74 68 6F 64 30 78 36 30 30 30 33 34 30 2D 31 00 24 24 6D 65 74 68 6F 64 30 78 36 30 30 30 33 34 30 2D 32 00 24 24 6D 65 74 68 6F 64 30 78 36 30 30 30 33 35 33 2D 31 00 24 24 6D 65 74 68 6F 64
in = section(#0)
requires = dotnet
section = !.reacto
dotnet_string = !NecroVM.Runtime
type = protector
version = 6.5
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg

[.NET Reactor [Anti-tamper]]
pattern = 20 00 69 00 73 00 20 00 74 00 61 00 6D 00 70 00 65 00 72 00 65 00 64 00 2E 00
in = section(#0)
requires = dotnet
section = !.reacto
dotnet_string = !NecroVM.Runtime, BinaryReader, RSACryptoServiceProvider
type = protector
options = Anti-tamper
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg
x-die-loss = global .cctor not checked; version set by the other .NET Reactor checks (3.X, 4.8-4.9, 6.X, 6.5) not reported

[.NET Reactor [Demo]]
pattern = 45 00 7A 00 69 00 72 00 69 00 7A 00 27 00 73 00 20 00 22 00 2E 00 4E 00 45 00 54 00 20 00 52 00 65 00 61 00 63 00 74 00 6F 00 72 00 22 00 21 00 20 00 54 00 68 00 69 00 73 00 20 00 61
in = section(#0)
requires = dotnet
section = !.reacto
dotnet_string = !NecroVM.Runtime, DateTime
type = protector
options = Demo
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetReactor.2.sg
x-die-loss = version set by the other .NET Reactor checks (3.X, 4.8-4.9, 6.X, 6.5) not reported

; protector_NetShield.2.sg
[NetShield]
requires = dotnet
section = "!Sugar"
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NetShield.2.sg
x-die-loss = global .cctor not checked; options (Fake signs, Anti-ILDASM, Anti-de4dot) not reported

; protector_Ningishzida.2.sg
[Ningishzida 1.0]
pattern = 9C 60 96 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 04 1B 00 00 8D BD ?? ?? ?? ?? 8B F7 AC
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Ningishzida.2.sg

; protector_North_Star_PE_Shrinker.2.sg
[North Star PE Shrinker 1.3]
pattern = 9C 60 E8 00 00 00 00 5D B8 ?? ?? ?? ?? 2D ?? ?? ?? ?? 2B E8 8D B5
at = entrypoint
section = !nsp0
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_North_Star_PE_Shrinker.2.sg

; protector_notcpuid.2.sg
[notcpuid 1.0.5]
pattern = 55 48 89 E5 51 53 52 56 57
at = entrypoint
section = .ptext
requires = pe32+
type = protector
version = 1.0.5
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_notcpuid.2.sg
x-die-loss = flags 0xE0000020 and position of .ptext (last section holding the entry point) not checked

[notcpuid 1.0.5]
pattern = 55 89 E5 51 53 52 56 57
at = entrypoint
section = .ptext
requires = pe32
type = protector
version = 1.0.5
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_notcpuid.2.sg
x-die-loss = flags 0xE0000020 and position of .ptext (last section holding the entry point) not checked

; protector_NTkrnl_Protector.2.sg
[NTkrnl Protector 0.1]
pattern = 68 ?? ?? ?? ?? E8
at = entrypoint
pattern.2 = 'http://www.ntcore.com  '
in.2 = section(#1)
import = /!LoadLibraryA$/, /!GetProcAddress$/
type = protector
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NTkrnl_Protector.2.sg
x-die-loss = DIE requires exactly one imported library with exactly the functions LoadLibraryA and GetProcAddress

[NTkrnl Protector 0.15]
pattern = 68 ?? ?? ?? ?? E8
at = entrypoint
pattern.2 = 'http://www.ntkrnl.com'
in.2 = section(#1)
import = /!LoadLibraryA$/, /!GetProcAddress$/
type = protector
version = 0.15
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NTkrnl_Protector.2.sg
x-die-loss = DIE requires exactly one imported library with exactly the functions LoadLibraryA and GetProcAddress

[NTkrnl Protector]
pattern = 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? C3
at = entrypoint
pattern.2 = 68 ######## 60 E8 $$$$$$$$ 5D 45 55 C3
at.2 = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_NTkrnl_Protector.2.sg

; protector_Obfuscar.2.sg
[Obfuscar 1.0]
pattern = 06 91 06 61 20 AA 00 00 00 61 D2 9C 06 17 58 0A
in = section(#0)
requires = dotnet
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obfuscar.2.sg

; protector_Obfuscator_NET_2009.2.sg
[Obfuscator.NET 2009]
requires = dotnet
dotnet_us = Macrobject.Obfuscator
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obfuscator_NET_2009.2.sg

[Obfuscator.NET 2009 [Unregistered]]
requires = dotnet
dotnet_us = !Macrobject.Obfuscator, Obfuscated by Macrobject Obfuscator.NET UNREGISTRED
type = protector
options = Unregistered
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obfuscator_NET_2009.2.sg

; protector_Obsidium.2.sg
[Obsidium 1.0.0.61]
pattern = E8 AF 1C 00 00
at = entrypoint
requires = native
type = protector
version = 1.0.0.61
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.1.1.1]
pattern = EB 02 ?? ?? E8 E7 1C 00 00
at = entrypoint
requires = native
type = protector
version = 1.1.1.1
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.2]
pattern = EB 02 ?? ?? E8 77 1E 00 00
at = entrypoint
requires = native
type = protector
version = 1.2
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.2.0.0]
pattern = EB 02 ?? ?? E8 3F 1E 00 00
at = entrypoint
requires = native
type = protector
version = 1.2.0.0
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.2.5.0]
pattern = E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00
at = entrypoint
requires = native
type = protector
version = 1.2.5.0
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.2.5.8]
pattern = EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 04
at = entrypoint
requires = native
type = protector
version = 1.2.5.8
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.2.X]
pattern = E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36
at = entrypoint
requires = native
type = protector
version = 1.2.X
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.0.0]
pattern = EB 04 ?? ?? ?? ?? E8 29 00 00 00 EB 02 ?? ?? EB 01 ?? 8B 54 24 0C EB 02
at = entrypoint
requires = native
type = protector
version = 1.3.0.0
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.0.4]
pattern = EB 02 ?? ?? E8 25 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 01
at = entrypoint
requires = native
type = protector
version = 1.3.0.4
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.0.13]
pattern = EB 01 ?? E8 26 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 01
at = entrypoint
requires = native
type = protector
version = 1.3.0.13
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.0.17]
pattern = EB 02 ?? ?? E8 28 00 00 00 EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C EB
at = entrypoint
requires = native
type = protector
version = 1.3.0.17
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.0.21]
pattern = EB 03 ?? ?? ?? E8 2E 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B
at = entrypoint
requires = native
type = protector
version = 1.3.0.21
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.0.37]
pattern = EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04
at = entrypoint
requires = native
type = protector
version = 1.3.0.37
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.1.1]
pattern = EB 02 ?? ?? E8 27 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 01
at = entrypoint
requires = native
type = protector
version = 1.3.1.1
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.2.2]
pattern = EB 04 ?? ?? ?? ?? E8 2A 00 00 00 EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54
at = entrypoint
requires = native
type = protector
version = 1.3.2.2
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.1]
pattern = EB 01 ?? E8 29 00 00 00 EB 02 ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C EB 02
at = entrypoint
requires = native
type = protector
version = 1.3.3.1
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.2]
pattern = EB 01 ?? E8 2B 00 00 00 EB 02 ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03
at = entrypoint
requires = native
type = protector
version = 1.3.3.2
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.3]
pattern = EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 03 ?? ?? ?? 8B ?? 24 0C EB
at = entrypoint
requires = native
type = protector
version = 1.3.3.3
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.4]
pattern = EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03
at = entrypoint
requires = native
type = protector
version = 1.3.3.4
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.6]
pattern = EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? ?? ?? ?? ?? ?? ?? 8B 54 24 0C
at = entrypoint
requires = native
type = protector
version = 1.3.3.6
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.7]
pattern = EB 02 ?? ?? E8 27 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 03
at = entrypoint
requires = native
type = protector
version = 1.3.3.7
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.7]
pattern = EB 02 ?? ?? E8 2C 00 00 00 EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24
at = entrypoint
requires = native
type = protector
version = 1.3.3.7
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.8]
pattern = EB 04 ?? ?? ?? ?? E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04
at = entrypoint
requires = native
type = protector
version = 1.3.3.8
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.3.9]
pattern = EB 02 ?? ?? E8 29 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04
at = entrypoint
requires = native
type = protector
version = 1.3.3.9
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.4.1]
pattern = EB 01 ?? E8 2A 00 00 00 EB 04 ?? ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C EB 03
at = entrypoint
requires = native
type = protector
version = 1.3.4.1
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.4.2]
pattern = EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 02
at = entrypoint
requires = native
type = protector
version = 1.3.4.2
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.3.5.0]
pattern = EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 8B 54 24 0C
at = entrypoint
requires = native
type = protector
version = 1.3.5.0
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.4.2.0]
pattern = EB 04 ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
version = 1.4.2.0
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 02 ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? EB 01 ?? 8B 54 24 0C
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 01 ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 05 ?? ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 05 ?? ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 05 ?? ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 05 ?? ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 8B 54 24 0C
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 02 ?? ?? 8B 54 24 0C
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? EB 01 ?? 8B 54 24 0C
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 8B 54 24 0C
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 01 ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 04 ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 02 ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 05 ?? ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 02 ?? ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 05 ?? ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 05 ?? ?? ?? ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 04 ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 02 ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 05 ?? ?? ?? ?? ?? EB 01 ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 01 ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 05 ?? ?? ?? ?? ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 03 ?? ?? ?? 50 EB 02 ?? ?? E8 ?? ?? ?? ?? EB 03 ?? ?? ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? EB 05 ?? ?? ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 05 ?? ?? ?? ?? ?? 50 EB 01 ?? E8 ?? ?? ?? ?? EB 01 ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 05 ?? ?? ?? ?? ?? 50 EB 04 ?? ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? EB 02 ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 04 ?? ?? ?? ?? 50 EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 04 ?? ?? ?? ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 05 ?? ?? ?? ?? ?? 50 EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 01 ?? EB 01 ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB 01 ?? 50 EB 03 ?? ?? ?? E8 ?? ?? ?? ?? EB 05 ?? ?? ?? ?? ?? EB 03 ?? ?? ?? 33 C0
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB $$ EB $$ 50 EB $$ E8 $$$$$$$$ EB $$ B8 ?? ?? ?? ?? EB $$ EB $$ 05 ?? ?? ?? ?? EB $$ 75 ?? EB $$ 64 FF 30
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium 1.6b43]
pattern = EB 08 ?? ?? ?? ?? ?? ?? ?? ?? EB 03 ?? ?? ?? 50 EB 02
at = entrypoint
requires = native
type = protector
version = 1.6b43
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

[Obsidium]
pattern = EB $$ E8 ?? ?? 00 00 EB $$ EB $$ 8B 54 24 0C EB
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Obsidium.2.sg

; protector_OneVM.2.sg
[OneVM 2.0, beta]
requires = dotnet
dotnet_string = Koi, OneVM.Runtime
dotnet_us = OneVM V2 BETA
type = protector
version = 2.0, beta
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_OneVM.2.sg
x-die-loss = the IL patterns in section 0 are not checked, they have no literal to search for

[OneVM]
requires = dotnet
dotnet_string = Koi, OneVM.Runtime
dotnet_us = !OneVM V2 BETA
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_OneVM.2.sg
x-die-loss = the IL patterns in section 0 are not checked, they have no literal to search for

; protector_Oreans_CodeVirtualizer.2.sg
[Oreans CodeVirtualizer]
pattern = EB $$ E9 $$$$$$$$ E9 $$$$$$$$ 56 50 53 E8 $$$$$$$$ 58 48 89 C3 48 FF C0 48 2D ?? ?? ?? ?? 48 2D ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 80 3B ?? 75 ?? C6 03 ?? BB ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50 E8
at = entrypoint
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Oreans_CodeVirtualizer.2.sg

[Oreans CodeVirtualizer]
section = .vlizer
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Oreans_CodeVirtualizer.2.sg

; protector_ORiEN.2.sg
[ORiEN 2.11]
pattern = E9 5D 01 00 00 CE D1 CE ?? '\x0D\x0A--------------------------------------------\x0D\x0A- ORiEN executable files protection system -\x0D\x0A------ Created by A. Fisun, 1994-2003 ------\x0D\x0A------- WWW: http://zalexf.narod.ru/ -------\x0D\x0A-------- e-mail: zalexf@hotmail.ru ---------\x0D\x0A--------------'
at = entrypoint
pattern.2 = CE
at.2 = entrypoint + 0x8
type = protector
version = 2.11
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ORiEN.2.sg

[ORiEN 2.12]
pattern = E9 5D 01 00 00 CE D1 CE ?? '\x0D\x0A--------------------------------------------\x0D\x0A- ORiEN executable files protection system -\x0D\x0A------ Created by A. Fisun, 1994-2003 ------\x0D\x0A------- WWW: http://zalexf.narod.ru/ -------\x0D\x0A-------- e-mail: zalexf@hotmail.ru ---------\x0D\x0A--------------'
at = entrypoint
pattern.2 = CD
at.2 = entrypoint + 0x8
type = protector
version = 2.12
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ORiEN.2.sg

[ORiEN]
pattern = E9 5D 01 00 00 CE D1 CE ?? '\x0D\x0A--------------------------------------------\x0D\x0A- ORiEN executable files protection system -\x0D\x0A------ Created by A. Fisun, 1994-2003 ------\x0D\x0A------- WWW: http://zalexf.narod.ru/ -------\x0D\x0A-------- e-mail: zalexf@hotmail.ru ---------\x0D\x0A--------------'
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ORiEN.2.sg

; protector_PACE.2.sg
[PACE Eden wrapper]
pattern = 83 3D ?? ?? ?? ?? ?? 75 ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 $$$$$$$$ 56 57 8B 3D ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 8B F0 85 F6 74 ?? 56 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15
at = entrypoint
type = protector
version = Eden wrapper
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PACE.2.sg

[PACE InterLok]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 8D 45 ?? 6A ?? 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 45 ?? EB ?? 8B 75 ?? 6A ?? 56 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 66 81 3E
at = entrypoint
type = protector
version = InterLok
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PACE.2.sg

; protector_PC_Guard.2.sg
[PC Guard 5.X]
pattern = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83
in = section(#0)
requires = dotnet
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PC_Guard.2.sg

[PC Guard 5.04-5.05]
pattern = FC 55 50 E8 00 00 00 00 5D 60 E8 $$$$$$$$ EB $$ 58 EB $$ 40 EB $$ FF E0
at = entrypoint
requires = native
type = protector
version = 5.04-5.05
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PC_Guard.2.sg

[PC Guard 4.06]
pattern = FC 55 50 E8 $$$$$$$$ 5D EB $$ 60 E8
at = entrypoint
requires = native
type = protector
version = 4.06
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PC_Guard.2.sg

; protector_PCShrink.2.sg
[PCShrink 0.71 beta]
pattern = 01 AD ?? ?? ?? ?? FF B5 ?? ?? ?? ?? 6A 40 FF 95
at = entrypoint
type = protector
version = 0.71 beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PCShrink.2.sg

[PCShrink 0.71]
pattern = 9C 60 BD ?? ?? ?? ?? 01 AD ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 6A ?? FF ?? ?? ?? ?? ?? 50 50 2D ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 5F 8D
at = entrypoint
type = protector
version = 0.71
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PCShrink.2.sg

; protector_PE-Armor.2.sg
[PE-Armor 0.46]
pattern = E8 $$$$$$$$ 5D 81 ED 05 00 00 00 8D 75 3D 56 FF 55 31 8D B5 86 00 00 00 56 50 FF 55 2D 89 85 93 00 00 00
at = entrypoint
type = protector
version = 0.46
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Armor.2.sg

[PE-Armor 0.49]
pattern = 56 52 51 53 55 E8 15 01 00 00 32 ?? ?? 00 00 00 00 00
at = entrypoint
type = protector
version = 0.49
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Armor.2.sg

[PE-Armor 0.7X]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 81 C5 ?? ?? ?? ?? 55 C3
at = entrypoint
type = protector
version = 0.7X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Armor.2.sg

[PE-Armor 0.X]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 58 83 EC ?? 5D E9 $$$$$$$$ 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56
at = entrypoint
type = protector
version = 0.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Armor.2.sg

; protector_PE-Shield.2.sg
[PE-SHiELD 0.25]
pattern = E9 $$$$$$$$ 60 E8 $$$$$$$$ 5D 83 ED ?? EB $$ 8D B5 ?? ?? ?? ?? BA ?? ?? ?? ?? 8A 3C 16 32 FA 80 ?? ?? 80 ?? ?? 88 ?? ?? 4A EB
at = entrypoint
type = protector
version = 0.25
author = hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Shield.2.sg

[PE-SHiELD 0.25-0.26]
pattern = 60 E8 $$$$$$$$ 5D 83 ED ?? EB $$ 8D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A ?? ?? 32 ?? 80 ?? ?? 80 ?? ?? 88 ?? ?? ?? EB
at = entrypoint
type = protector
version = 0.25-0.26
author = hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Shield.2.sg

[PE-SHiELD 0.2]
pattern = 60 E8 $$$$$$$$ 41 4E 41 4B 49 4E 5D 83 ED ?? EB $$ 8D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8A ?? ?? 32
at = entrypoint
type = protector
version = 0.2
author = hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Shield.2.sg

[PE-SHiELD 0.1d]
pattern = E8 $$$$$$$$ 4E 86 ED 38 CA 47 47 5A 52 43 33 F6 81 C2
at = entrypoint
type = protector
version = 0.1d
author = hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Shield.2.sg

[PE-SHiELD 0.1d]
pattern = E8 $$$$$$$$ 4F 46 59 51 F5 2B F9 D1 E6 38 C2 81 C1
at = entrypoint
type = protector
version = 0.1d
author = hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Shield.2.sg

[PE-SHiELD 0.1d]
pattern = E8 $$$$$$$$ 4E 86 C9 4F 59 51 42 47 84 F6 86 E4 D1 CA 81 C1
at = entrypoint
type = protector
version = 0.1d
author = hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE-Shield.2.sg

; protector_PE_Diminisher.2.sg
[PE Diminisher 0.1]
pattern = 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 0B 00 00 00 89 95 ?? ?? ?? ?? 80 BD
at = entrypoint
type = protector
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Diminisher.2.sg

[PE Diminisher 0.1 [Alt]]
pattern = 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 81 EA 0B ?? ?? ?? 89 95 ?? ?? ?? ?? 80 BD
at = entrypoint
type = protector
version = 0.1
options = Alt
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Diminisher.2.sg

; protector_PE_Encrypt.2.sg
[PE Encrypt 1.0]
pattern = 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 'MZ' 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Encrypt.2.sg

; protector_PE_Intro.2.sg
[PE Intro 1.0]
pattern = 8B 04 24 9C 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 80 BD ?? ?? ?? ?? ?? 0F 85 48
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Intro.2.sg

; protector_PE_Lock_NT.2.sg
[PELOCKnt 2.01]
pattern = EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD
at = entrypoint
type = protector
version = 2.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Lock_NT.2.sg

[PELOCKnt 2.02c]
pattern = EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD
at = entrypoint
type = protector
version = 2.02c
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Lock_NT.2.sg

[PELOCKnt 2.03]
pattern = EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01
at = entrypoint
type = protector
version = 2.03
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Lock_NT.2.sg

[PELOCKnt 2.04]
pattern = EB $$ 1E EB $$ 9C EB $$ EB $$ 60 EB $$ EB $$ E8 $$$$$$$$ 58 40 50 C3
at = entrypoint
type = protector
version = 2.04
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Lock_NT.2.sg

; protector_PE_Lock_Phantasm_by_Ding_Boy.2.sg
[PE Lock Phantasm by Ding Boy 0.07/0.8]
pattern = 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED
at = entrypoint
type = protector
version = 0.07/0.8
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Lock_Phantasm_by_Ding_Boy.2.sg

[PE Lock Phantasm by Ding Boy 1.0/1.1]
pattern = 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC
at = entrypoint
type = protector
version = 1.0/1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Lock_Phantasm_by_Ding_Boy.2.sg

[PE Lock Phantasm by Ding Boy 1.5b3]
pattern = 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED
at = entrypoint
type = protector
version = 1.5b3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Lock_Phantasm_by_Ding_Boy.2.sg

; protector_PE_Password.2.sg
[PE Password by SMT 0.2]
pattern = E8 04 ?? ?? ?? 8B EC 5D C3 33 C0 5D 8B FD 81 ED ?? ?? ?? ?? 81 EF ?? ?? ?? ?? 83 EF 05 89 AD ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 46 80
at = entrypoint
type = protector
version = 0.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Password.2.sg

; protector_PE_Protect.2.sg
[PE Protect 0.9]
pattern = '\x0D\x0APE-PROTECT 0.9 (C)o'
at = entrypoint + 0x40
type = protector
version = 0.9
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Protect.2.sg

[PE Protect 0.9]
pattern = 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 ?? ?? ?? ?? 58 83 C0 07 C6 ?? C3
at = entrypoint
type = protector
version = 0.9
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PE_Protect.2.sg

; protector_PEBundle.2.sg
[PEBundle 0.2-2.0X [modified]]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
pattern.2 = 6A 04
at.2 = entrypoint + 0x1C
section = !/^(peb|PEB)undle$/
type = protector
version = 0.2-2.0X
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle 0.2-2.0X]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
pattern.2 = 6A 04
at.2 = entrypoint + 0x1C
section = /^(peb|PEB)undle$/
type = protector
version = 0.2-2.0X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle 2.0b5-2.3 [modified]]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
pattern.2 = 01 AD
at.2 = entrypoint + 0x1C
section = !/^(peb|PEB)undle$/
type = protector
version = 2.0b5-2.3
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle 2.0b5-2.3]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
pattern.2 = 01 AD
at.2 = entrypoint + 0x1C
section = /^(peb|PEB)undle$/
type = protector
version = 2.0b5-2.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle 2.44 [modified]]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
pattern.2 = 83 BD
at.2 = entrypoint + 0x1C
section = !/^(peb|PEB)undle$/
type = protector
version = 2.44
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle 2.44]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
pattern.2 = 83 BD
at.2 = entrypoint + 0x1C
section = /^(peb|PEB)undle$/
type = protector
version = 2.44
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle 3.XX [modified]]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
pattern.2 = 80 BD
at.2 = entrypoint + 0x1C
section = !/^(peb|PEB)undle$/
type = protector
version = 3.XX
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle 3.XX]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
pattern.2 = 80 BD
at.2 = entrypoint + 0x1C
section = /^(peb|PEB)undle$/
type = protector
version = 3.XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle [modified]]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
section = !/^(peb|PEB)undle$/
type = protector
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

[PEBundle]
pattern = 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? ?? ?? 87 DD
at = entrypoint
section = /^(peb|PEB)undle$/
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEBundle.2.sg

; protector_PECRYPT32.2.sg
[PECRYPT32 1.02 [by random & killa]]
pattern = E8 00 00 00 00 5B 83 EB ?? EB $$ 85 C0 73 ?? F7 05 ?? ?? ?? ?? ?? ?? ?? ?? 58 EB $$ 56 57 55 50 E8
at = entrypoint
type = protector
version = 1.02
options = by random & killa
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PECRYPT32.2.sg

[PECRYPT32 1.02 [by random & acpizer]]
pattern = E8 00 00 00 00 5B 83 EB ?? EB $$ EB $$ EB $$ EB $$ EB $$ EB $$ EB $$ EB $$ 80 BB ?? ?? ?? ?? ?? 74 ?? 83 BB ?? ?? ?? ?? ?? 74 ?? BE ?? ?? ?? ?? 03 F3 8B BB ?? ?? ?? ?? EB
at = entrypoint
type = protector
version = 1.02
options = by random & acpizer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PECRYPT32.2.sg

[PECRYPT32 0.0193c [by random & acp]]
pattern = E8 00 00 00 00 5B 83 EB ?? 8B 83 ?? ?? ?? ?? 53 8B EB 2B D8 2B 9D ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 5B BE ?? ?? ?? ?? 03 F3 8B 93 ?? ?? ?? ?? 52 AD 0B C0 0F 84 ?? ?? ?? ?? 89 83
at = entrypoint
type = protector
version = 0.0193c
options = by random & acp
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PECRYPT32.2.sg

; protector_PEncrypt.2.sg
[PEncrypt 1.0]
pattern = 60 9C BE ?? ?? ?? ?? 8B FE B9 ?? ?? ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 ?? ?? ?? FF
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEncrypt.2.sg

[PEncrypt 2.0]
pattern = EB $$ E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? E8 33 00 00 00 89 85
at = entrypoint
type = protector
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEncrypt.2.sg

[PEncrypt 3.0]
pattern = E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 8B FE B9 0F 00 00 00 BB
at = entrypoint
type = protector
version = 3.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEncrypt.2.sg

[PEncrypt 3.1]
pattern = E9 ?? ?? ?? 00 F0 0F C6
at = entrypoint
type = protector
version = 3.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEncrypt.2.sg

; protector_PEnguinCrypt.2.sg
[PEnguinCrypt 1.0]
pattern = B8 ?? ?? ?? ?? 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PEnguinCrypt.2.sg

; protector_PENinja.2.sg
[PE Ninja [modified]]
pattern = 5D 8B C5 81 ED ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 2D 71 02 00 00 89 85 ?? ?? ?? ?? 0F B6 B5 ?? ?? ?? ?? 8B FD
at = entrypoint
type = protector
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PENinja.2.sg

; protector_PESpin.2.sg
[PESpin 0.1]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = 5C
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 0.3]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = B7
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 0.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 0.4]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = 73
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 0.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 0.7]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = 83
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 0.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.0]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = C8
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.1]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = 7D
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.3, beta]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = 71
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 1.3, beta
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.3]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = AC
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.3X]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = 88
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 1.3X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.32]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = 17
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 1.32
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.33]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
pattern.2 = 77
at.2 = entrypoint + 0x1B
requires = pe32
type = protector
version = 1.33
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin]
pattern = EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24
at = entrypoint
requires = pe32
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.2X]
pattern = 55 48 81 EC 90 00 00 00 8D 6C 24 28 48 89 75 ?? 48 89 7D ?? 48 89 5D ?? 4C 89 45 ?? 4C 89 4D ?? 4C 89 55 ?? 4C 89 5D ?? 4C 89 65 ?? 4C 89 6D ?? 4C 89 75 ?? 4C 89 7D ?? 48 89 4D ?? 48 89 55
at = entrypoint
requires = pe32+
type = protector
version = 1.2X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

[PESpin 1.23]
pattern = 55 48 81 EC 90 00 00 00 48 8D 6C 24 28 48 89 75 18 48 89 7D 20 48 89 5D 00 4C 89 45 28 4C 89 4D 30 4C 89 55 38 4C 89 5D 40 4C 89 65 48 4C 89 6D 50 4C 89 75 58 4C 89 7D 60 48 89 4D 08 48 89 55 10 48 2B C9 4C 8D 05
at = entrypoint
requires = pe32+
type = protector
version = 1.23
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PESpin.2.sg

; protector_PETetris.2.sg
[PETetris]
section = PETETRIS
type = protector
author = KDSS-Research
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PETetris.2.sg

; protector_Phoenix.2.sg
[Phoenix 1.7-1.8]
pattern = 00 00 01 0B 16 0C ?? ?? ?? ?? ?? 02 08 ?? ?? ?? ?? ?? 0D 09 06 08 59 61 D2 13 04 09 1E 63 08 61 D2 13 05 07 08 11 05 1E 62 11 04 60 D1 9D 08 17 58
in = section(#0)
requires = dotnet
dotnet_string = ?0?
type = protector
version = 1.7-1.8
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Phoenix.2.sg

[Phoenix 1.X]
pattern = '?.resources'
in = section(#0)
requires = dotnet
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Phoenix.2.sg

; protector_Photo_Compiler.2.sg
[Photo Compiler]
pattern = 55 8B EC 83 C4 F0 B8
at = entrypoint
pattern.2 = 'PK'
at.2 = overlay
pattern.3 = 'PhotoCompiler.Runtime'
in.3 = section(#0)
type = protector
author = A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Photo_Compiler.2.sg

; protector_PolyCrypt_PE.2.sg
[JLabSoftware PolyCrypt PE 2004-2005]
pattern = 60 E8 $$$$$$$$ 91 8B F4 AD FE C9 80 34 08 ?? E2 ?? C3
at = entrypoint
type = protector
version = 2004-2005
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PolyCrypt_PE.2.sg

; protector_Private_EXE_Protector.2.sg
[Private EXE Protector 1.9.7]
pattern = 55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB
at = entrypoint
type = protector
version = 1.9.7
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 1.X]
pattern = B8 ?? ?? ?? ?? B9 ?? 90 01 ?? BE ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 01 ?? ?? ?? C3
at = entrypoint
type = protector
version = 1.X
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 2.0]
pattern = 89 ?? ?? 38 00 00 00 8B ?? 00 00 00 00 81 ?? ?? ?? ?? ?? 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF
at = entrypoint
type = protector
version = 2.0
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 3.04]
pattern = 52 BA ?? ?? ?? ?? C7 02 ######## ?? ?? 50 ?? ?? 53 ?? ?? 51 ?? ?? 52 ?? ?? 56 ?? 57 ?? ?? 55 ?? ?? 81 EE
at = entrypoint
type = protector
version = 3.04
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 4.0-4.12]
pattern = EB 08 ?? ?? 00 00 00 00 00 00 ?? 00 9C
at = entrypoint
type = protector
version = 4.0-4.12
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 4.0-4.12]
pattern = EB 08 ?? ?? 00 00 00 00 00 00 ?? 00 68
at = entrypoint
type = protector
version = 4.0-4.12
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 4.X]
pattern = 60 64 FF 35 ?? ?? ?? ?? B9 ?? ?? ?? ?? 89 CE 81 C6 ?? ?? ?? ?? BA ?? ?? ?? ?? BD ?? ?? ?? ?? 8B 06 83 C6 ?? 8B 1E 89 DF FC F8 29 C3 33 DD 31 C3 89 1E
at = entrypoint
type = protector
version = 4.X
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 3.4.0]
pattern = 51 B9 ?? ?? ?? ?? C7 01 ?? ?? ?? ?? 59 FF 35 ?? ?? ?? ?? C3
at = entrypoint
type = protector
version = 3.4.0
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 3.4.0]
pattern = 53 BB ?? ?? ?? ?? C7 03 ?? ?? ?? ?? 5B FF 35 ?? ?? ?? ?? C3
at = entrypoint
type = protector
version = 3.4.0
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 3.0.0-3.3.5]
pattern = B9 00 00 00 00 F3 AE
in = entrypoint[0-0xB00]
type = protector
version = 3.0.0-3.3.5
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

[Private EXE Protector 3.0.0-3.3.5]
pattern = B9 00 00 00 00 F3 66
in = entrypoint[0-0xB00]
type = protector
version = 3.0.0-3.3.5
author = horsicq, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Private_EXE_Protector.2.sg

; protector_Protect_Disc.2.sg
[Protect Disc 9.11.0]
pattern = 36 3E 26 8A C0 60 E8 $$$$$$$$ 55 8B EC 83 EC ?? B8 ?? ?? ?? ?? 8B 7D ?? 2B F8 E8
at = entrypoint
type = protector
version = 9.11.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Protect_Disc.2.sg
x-die-loss = build number (options) read from file

[Protect Disc 7.5.3]
pattern = 36 3E 26 8A C0 60 E8 $$$$$$$$ 5F 81 EF ?? ?? ?? ?? BE ?? ?? ?? ?? 8B 87 ?? ?? ?? ?? 03 C6 57 56 8C A7
at = entrypoint
type = protector
version = 7.5.3
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Protect_Disc.2.sg
x-die-loss = build number (options) read from file

; protector_Protection_Plus.2.sg
[Protection Plus 4.X]
pattern = 50 60 29 C0 64 FF 30 E8 ?? ?? ?? ?? 5D 83 ED ?? 89 E8 89 A5 ?? ?? ?? ?? 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 8B 00 85 C0 0F 85
at = entrypoint
type = protector
version = 4.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Protection_Plus.2.sg

[Protection Plus Wrapper 4.6+]
pattern = '{4A6E2EB8-0392-4258-9C91-65BB5FF8F1F9}'
in = section(entrypoint)
type = protector
version = 4.6+
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Protection_Plus.2.sg
x-die-loss = import hash not checked; DIE expects the GUID 0x27 bytes before the entry point

; protector_PUNiSHER.2.sg
[PUNiSHER 1.5 demo]
pattern = EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00
at = entrypoint
type = protector
version = 1.5 demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_PUNiSHER.2.sg

; protector_QrYPt0r.2.sg
[QrYPt0r 1.0]
pattern = EB $$ E8 $$$$$$$$ 64 FF 35 00 00 00 00
at = entrypoint
type = protector
version = 1.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_QrYPt0r.2.sg

; protector_QuickBFC.2.sg
[Quick Batch File Compiler]
pattern = 'batfilerecord'
in = section(.text)
section = .didata
resource = */SRC
type = protector
lang = Batch
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_QuickBFC.2.sg

; protector_QuickPack_NT.2.sg
[QuickPack NT 0.1a]
pattern = 4D 5A 90 EB $$ 52 E9 $$$$$$$$ E8 $$$$$$$$ 5D 8D AD ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 8D ?? ?? ?? 50 6A ?? 68 ?? ?? ?? ?? 55 FF 53
at = entrypoint
type = protector
version = 0.1a
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_QuickPack_NT.2.sg

; protector_ReNET-pack.2.sg
[ReNET-pack]
pattern = 'Protected/Packed with ReNET-Pack by stx'
in = section(#0)
requires = dotnet
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ReNET-pack.2.sg

; protector_REVProt.2.sg
[REVProt 0.1a]
pattern = E8 $$$$$$$$ 31 C0 64 FF 30 64 89 20 64 8F 05 ?? ?? ?? ?? 83 C4 ?? 60 E8 $$$$$$$$ 83 C4 ?? E8 $$$$$$$$ 5D 81 ED ?? ?? ?? ?? 60 B9
at = entrypoint
type = protector
version = 0.1a
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_REVProt.2.sg

; protector_ReWolf_Virtualizer.2.sg
[ReWolf Virtualizer]
pattern = E8 00 00 00 00 5B
at = entrypoint
requires = pe32
section = .VM
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_ReWolf_Virtualizer.2.sg
x-die-loss = the .VM section is not checked to be the last section

; protector_RLP.2.sg
[RLP 0.7.3b]
pattern = 68 00 ?? ?? 00 E8 01 00 00 00 C3 C3
at = entrypoint
requires = pe32
section = .rlp
type = protector
version = 0.7.3b
author = horsicq, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_RLP.2.sg

; protector_RobustObfuscator.2.sg
[Robust Obfuscator]
pattern = 00 20 ?? ?? ?? ?? FE 0E ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 5F 20 ?? ?? ?? ??
in = section(#0)
requires = dotnet
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_RobustObfuscator.2.sg
x-die-loss = global .NET cctor (isNetGlobalCctorPresent) not checked

; protector_SafeDisc.2.sg
[SafeDisc]
pattern = 55 8B EC 60 BB ?? ?? ?? ?? 33 C9 8A 0D ?? ?? ?? ?? 85 C9 74 ?? B8 ?? ?? ?? ?? 2B C3 83 E8 ?? EB
at = entrypoint
requires = native
type = protector
author = hypn0, BJNFNE, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SafeDisc.2.sg

[SafeDisc]
section = stxt774, stxt371
requires = native
type = protector
author = hypn0, BJNFNE, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SafeDisc.2.sg
x-die-loss = positions of stxt774/stxt371 (last two sections), section count and import/entry point in the last section not checked

; protector_Safenet_RMS.2.sg
[Safenet RMS (Sentinel)]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 85 ?? ?? ?? ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 74 ?? E9
at = entrypoint
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Safenet_RMS.2.sg

; protector_Safengine_Shielden.2.sg
[Safengine Shielden 2.X]
pattern = EB $$ E9 $$$$$$$$ E8 ?? ?? ?? ?? 'Safengine Shielden'
at = entrypoint
type = protector
version = 2.X
author = hors, sendersu
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Safengine_Shielden.2.sg
x-die-loss = version read from file ("Safengine Shielden v"/"Safengine NetLicensor v" string) replaces 2.X

[Shielden]
pattern = E8 ?? ?? ?? ?? 'Shielden'
at = entrypoint
pattern.2 = 'Shielden v'
in.2 = entrypoint[0-0x50]
type = protector
author = hors, sendersu
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Safengine_Shielden.2.sg
x-die-loss = version read from file

; protector_SC_Obfuscator.2.sg
[SC Obfuscator]
pattern = 60 33 C9 8B 1D ?? ?? ?? ?? 03 1D ?? ?? ?? ?? 8A 04 19 84 C0 74 ?? 3C ?? 74 ?? 34 ?? 88 04 19 41 3B 0D ?? ?? ?? ?? 75 ?? A1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 61 FF 25
at = entrypoint
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SC_Obfuscator.2.sg

; protector_SDProtector.2.sg
[SDProtector 1.10]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1
at = entrypoint
pattern.2 = 50 83 EC 08
at.2 = entrypoint + 0x2A
type = protector
version = 1.10
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SDProtector.2.sg

[SDProtector 1.16]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1
at = entrypoint
pattern.2 = 18 33 C0
at.2 = entrypoint + 0x4D
type = protector
version = 1.16
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SDProtector.2.sg

[SDProtector 1.1X]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 88 88 88 08 64 A1
at = entrypoint
type = protector
version = 1.1X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SDProtector.2.sg

; protector_Secure_Shade.2.sg
[Secure Shade 1.8]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 BE ?? ?? ?? ?? 8D 7D ?? 8D 45 ?? A5 A5 A5 A5 6A ?? 50 A4 E8 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 59 59 68 ?? ?? ?? ?? FF D3
at = entrypoint
type = protector
version = 1.8
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Secure_Shade.2.sg

; protector_SecuROM.2.sg
[SecuROM pre-8.03.03]
section = .securom
type = protector
version = pre-8.03.03
author = ELF_7719116, DosX, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SecuROM.2.sg
x-die-loss = the .securom section is not checked to be the last section

[SecuROM 8.03.03+]
section = .dsstext
type = protector
version = 8.03.03+
author = ELF_7719116, DosX, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SecuROM.2.sg

[SecuROM]
pattern = 'AddD' 03
at = overlay
section = !.dsstext
type = protector
author = ELF_7719116, DosX, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SecuROM.2.sg
x-die-loss = version read from file

[SecuROM 1.X-4.6]
section = .cms_t, !.dsstext
type = protector
version = 1.X-4.6
author = ELF_7719116, DosX, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SecuROM.2.sg

[SecuROM 1.X-4.6]
section = .cms_d, !.dsstext
type = protector
version = 1.X-4.6
author = ELF_7719116, DosX, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SecuROM.2.sg

; protector_Shrink_Wrap.2.sg
[Shrink Wrap 1.4]
pattern = 58 60 8B E8 55 33 F6 68 48 01 ?? ?? E8 49 01 ?? ?? EB
at = entrypoint
type = protector
version = 1.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Shrink_Wrap.2.sg

; protector_Shrinker.2.sg
[Shrinker 3.2]
pattern = 55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04
at = entrypoint
type = protector
version = 3.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Shrinker.2.sg

[Shrinker 3.3]
pattern = 55 8B EC 56 57 75 65 68 00 01 00 00 E8
at = entrypoint
type = protector
version = 3.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Shrinker.2.sg

[Shrinker 3.4]
pattern = 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04
at = entrypoint
type = protector
version = 3.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Shrinker.2.sg

[Shrinker 3.2]
pattern = 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 8B ?? ?? A3 ?? ?? ?? ?? 85 F6 74 ?? 68
at = entrypoint
type = protector
version = 3.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Shrinker.2.sg

[Shrinker 3.5]
pattern = 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 ?? ?? 8B ?? ?? A3 ?? ?? ?? ?? 85 F6 74 ?? 83
at = entrypoint
type = protector
version = 3.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Shrinker.2.sg

[Shrinker 3.4]
pattern = 83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF
at = entrypoint
type = protector
version = 3.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Shrinker.2.sg

[Shrinker]
pattern = 80 3D ?? ?? ?? ?? ?? 53 56 8B 74 24 ?? 57 55 75 ?? 85 F6 74 ?? 68 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 FF D7
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Shrinker.2.sg

; protector_SimbiOZ.2.sg
[SimbiOZ]
pattern = 50 60 E8 00 00 00 00 5D 81 ED 07 10 40 00 68 80 0B 00 00 8D 85 1F 10 40 00 50 E8 84 0B 00 00
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SimbiOZ.2.sg

[SimbiOZ 1.3]
pattern = 57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3
at = entrypoint
type = protector
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SimbiOZ.2.sg

[SimbiOZ 2.1]
pattern = 55 50 8B C4 83 C0 04 C7 00 ?? ?? ?? ?? 58 C3 90
at = entrypoint
type = protector
version = 2.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SimbiOZ.2.sg

[SimbiOZ]
pattern = 55 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SimbiOZ.2.sg

; protector_Skater.2.sg
[Skater 2.X]
pattern = 42 28 07 00 00 06 6F 09 00 00 06 28 38 00 00 0A 2A 1B 30 04 00 6F 00 00 00 0D 00 00 11 02 72 B9
in = section(#0)
requires = dotnet
type = protector
version = 2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Skater.2.sg
x-die-loss = IL of the .NET entry point method (compareEP_NET) searched in the first section

[Skater 2.X [demo]]
pattern = 42 28 07 00 00 06 6F 09 00 00 06 28 38 00 00 0A 2A 1B 30 04 00 6F 00 00 00 0D 00 00 11 02 72 B9
in = section(#0)
pattern.2 = 4F 00 62 00 66 00 75 00 73 00 63 00 61 00 74 00 6F 00 72 00 20 00 44 00 65 00 6D 00 6F 00
in.2 = section(#0)
requires = dotnet
type = protector
version = 2.X
options = demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Skater.2.sg
x-die-loss = IL of the .NET entry point method (compareEP_NET) searched in the first section

[Skater]
dotnet_string = RustemSoft.Skater
requires = dotnet
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Skater.2.sg

[Skater [demo]]
pattern = 4F 00 62 00 66 00 75 00 73 00 63 00 61 00 74 00 6F 00 72 00 20 00 44 00 65 00 6D 00 6F 00
in = section(#0)
dotnet_string = RustemSoft.Skater
requires = dotnet
type = protector
options = demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Skater.2.sg

[Skater]
dotnet_string = RustemSoft.Skater.Skater_NET_Obfuscator
requires = dotnet
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Skater.2.sg

[Skater [demo]]
pattern = 4F 00 62 00 66 00 75 00 73 00 63 00 61 00 74 00 6F 00 72 00 20 00 44 00 65 00 6D 00 6F 00
in = section(#0)
dotnet_string = RustemSoft.Skater.Skater_NET_Obfuscator
requires = dotnet
type = protector
options = demo
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Skater.2.sg

; protector_SLVc0deProtector.2.sg
[SLVc0deProtector 1.12]
pattern = E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 52
at = entrypoint
type = protector
version = 1.12
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SLVc0deProtector.2.sg

; protector_Smart_Assembly.2.sg
[Smart Assembly 3.X]
pattern = 20 FF FF FF 00 5F 17 59 20 FF FF 00 00
in = section(#0)
requires = dotnet
type = protector
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Smart_Assembly.2.sg

[Smart Assembly 1.X-4.X]
dotnet_string = "Powered by {smartassembly}"
requires = dotnet
type = protector
version = 1.X-4.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Smart_Assembly.2.sg

[Smart Assembly 5.X]
dotnet_string = "Powered by SmartAssembly", !"Powered by {smartassembly}"
requires = dotnet
type = protector
version = 5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Smart_Assembly.2.sg

[Smart Assembly]
dotnet_string = SmartAssembly.Attributes, !"Powered by {smartassembly}", !"Powered by SmartAssembly"
requires = dotnet
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Smart_Assembly.2.sg

[Smart Assembly]
pattern = 'Powered by SmartAssembly '
in = section(#0)
dotnet_string = !"Powered by {smartassembly}", !"Powered by SmartAssembly", !SmartAssembly.Attributes
requires = dotnet
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Smart_Assembly.2.sg
x-die-loss = version read from file

[Smart Assembly]
pattern = 'Powered by {smartassembly}'
in = section(entrypoint)
dotnet_string = !"Powered by {smartassembly}", !"Powered by SmartAssembly", !SmartAssembly.Attributes
requires = dotnet
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Smart_Assembly.2.sg

; protector_SmokesCrypt.2.sg
[SmokesCrypt 1.2]
pattern = 60 B8 ?? ?? ?? ?? B8 ?? ?? ?? ?? 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1
at = entrypoint
type = protector
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SmokesCrypt.2.sg

; protector_SoftProtect.2.sg
[SoftProtect]
pattern = E8 ?? ?? 00 00 8D 85 ?? ?? 00 00 C7 00 00 00 00 00 E8 ?? ?? 00 00 E8 ?? ?? 00 00 8D 85 ?? ?? 00 00 50 E8 ?? ?? 00 00 83
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SoftProtect.2.sg

[SoftProtect]
pattern = EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SoftProtect.2.sg

; protector_SoftSentry.2.sg
[SoftSentry 2.11]
pattern = 55 8B EC 83 EC ?? 53 56 57 E9
at = entrypoint
pattern.2 = 50
at.2 = entrypoint + 0xA
type = protector
version = 2.11
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SoftSentry.2.sg

[SoftSentry 3.0]
pattern = 55 8B EC 83 EC ?? 53 56 57 E9
at = entrypoint
pattern.2 = B0 06
at.2 = entrypoint + 0xA
type = protector
version = 3.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SoftSentry.2.sg

[SoftSentry]
pattern = 55 8B EC 83 EC ?? 53 56 57 E9
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SoftSentry.2.sg

; protector_Special_EXE_Password_Protector.2.sg
[Special EXE Password Protector 1.0X]
pattern = 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E
at = entrypoint
type = protector
version = 1.0X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Special_EXE_Password_Protector.2.sg

; protector_SpicesNet.2.sg
[Spices.Net]
dotnet_string = NineRays.Obfuscator
requires = dotnet
type = protector
author = horsicq, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SpicesNet.2.sg

[Spices.Net [demo]]
pattern = 'Built using an evaluation version of 9Rays.Net Spices.Obfuscator.'
in = section(#0)
dotnet_string = NineRays.Obfuscator
requires = dotnet
type = protector
options = demo
author = horsicq, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SpicesNet.2.sg
x-die-loss = demo string searched in the whole first section instead of the 512 bytes before the second section

[Spices.Net 5.X]
pattern = '9Rays.Net Spices.Net Obfuscator'
in = section(#0)
dotnet_string = NineRays.Obfuscator
requires = dotnet
type = protector
version = 5.X
author = horsicq, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SpicesNet.2.sg

[Spices.Net 5.X [demo]]
pattern = '9Rays.Net Spices.Net Obfuscator'
in = section(#0)
pattern.2 = 'Built using an evaluation version of 9Rays.Net Spices.Obfuscator.'
in.2 = section(#0)
dotnet_string = NineRays.Obfuscator
requires = dotnet
type = protector
version = 5.X
options = demo
author = horsicq, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SpicesNet.2.sg
x-die-loss = demo string searched in the whole first section instead of the 512 bytes before the second section

[Spices.Net 5.X [DLL]]
pattern = '9Rays.Net Spices.Net Obfuscator'
in = section(#0), section(#1)
dotnet_string = !NineRays.Obfuscator
requires = dotnet, dll
type = protector
version = 5.X
options = DLL
author = horsicq, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SpicesNet.2.sg

; protector_Standalone_EXE_Locker.2.sg
[Standalone EXE Locker 1.0]
pattern = E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Standalone_EXE_Locker.2.sg

; protector_StarForce.2.sg
[StarForce 3.0]
pattern = 68 ?? ?? ?? ?? FF 25 ?? ?? 63
at = entrypoint
type = protector
version = 3.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_StarForce.2.sg

[StarForce 1.1 [ProActive]]
pattern = 68 ?? ?? ?? ?? FF 25 ?? ?? 57
at = entrypoint
type = protector
version = 1.1
options = ProActive
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_StarForce.2.sg

[StarForce [Protection Driver]]
pattern = 57 68 ?? 0D 01 00 68 00 ?? ?? 00 E8 50 ?? FF FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00 68 ?? ?? ?? 00
at = entrypoint
type = protector
options = Protection Driver
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_StarForce.2.sg

[StarForce 3.X]
pattern = E8 ?? ?? ?? ?? 00 00 00 00 00 00
at = entrypoint
type = protector
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_StarForce.2.sg

[StarForce 3.4]
pattern = 60 E8 00 00 00 00 58 83 C0 08
at = entrypoint
section = .brick
type = protector
version = 3.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_StarForce.2.sg

[StarForce 3.X]
pattern = 68 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? 00 00 00 00 00
at = entrypoint
type = protector
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_StarForce.2.sg

[StarForce 4.X-5.X]
import = protect.dll
section = .ps4
type = protector
version = 4.X-5.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_StarForce.2.sg

[StarForce 3.X]
import = protect.dll
section = .sforce3, !.ps4
type = protector
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_StarForce.2.sg

; protector_Ste@lth_PE.2.sg
[Ste@lth PE 2.X]
pattern = BA ?? ?? ?? ?? B8 ?? ?? ?? ?? 89 02 42 42 42 B8 ?? ?? ?? ?? 89 02 4A 4A 4A FF D2
in = eof[0x40]
type = protector
version = 2.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Ste@lth_PE.2.sg

[Ste@lth PE 2.X]
pattern = B8 ?? ?? ?? ?? BA ?? ?? ?? ?? 89 10 40 40 40 BA ?? ?? ?? ?? 89 10 48 48 48 50 C3
in = eof[0x40]
type = protector
version = 2.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Ste@lth_PE.2.sg

; protector_Strongbit_EXECryptor.2.sg
[Strongbit EXECryptor 2.0/2.1 [protected IAT]]
pattern = A4 ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? 94 ?? ?? ?? D8 ?? ?? ?? 00 00 00 00 FF FF FF FF B8
at = entrypoint
requires = native
type = protector
version = 2.0/2.1
options = protected IAT
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.0/2.1]
pattern = 55 8B EC 83 C4 F4 56 57 53 BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84
at = entrypoint
requires = native
type = protector
version = 2.0/2.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.1.17]
pattern = BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15
at = entrypoint
requires = native
type = protector
version = 2.1.17
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.2.4]
pattern = E8 $$$$$$$$ E8 00 00 00 00 ?? ?? ?? ?? ?? ?? 8B 1C 24 81 EB ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 6A ?? 68
at = entrypoint
requires = native
type = protector
version = 2.2.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.2.6 [minimum protection]]
pattern = 50 68 ?? ?? ?? ?? 58 81 E0 ?? ?? ?? ?? E9 ?? ?? ?? 00 87 0C 24 59 E8 ?? ?? ?? 00 89 45 F8 E9
at = entrypoint
requires = native
type = protector
version = 2.2.6
options = minimum protection
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.2.6 [DLL/minimum protection]]
pattern = 50 8B C6 87 04 24 68 ?? ?? ?? ?? 5E E9 ?? ?? ?? ?? 85 C8 E9 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 0F 81
at = entrypoint
requires = native
type = protector
version = 2.2.6
options = DLL/minimum protection
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.2/2.3 [compressed code]]
pattern = E8 00 00 00 00 58 ?? ?? ?? ?? ?? 8B 1C 24 81 EB ?? ?? ?? ?? B8 ?? ?? ?? ?? 50 6A 04 68 00 10 00 00 50 6A 00 B8
at = entrypoint
requires = native
type = protector
version = 2.2/2.3
options = compressed code
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.2/2.3 [protected IAT]]
pattern = CC ?? ?? ?? 00 00 00 00 FF FF FF FF 3C ?? ?? ?? B4 ?? ?? ?? 08 ?? ?? ?? 00 00 00 00 FF FF FF FF E8
at = entrypoint
requires = native
type = protector
version = 2.2/2.3
options = protected IAT
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.3.9 [compressed resources]]
pattern = 51 68 ?? ?? ?? ?? 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00
at = entrypoint
requires = native
type = protector
version = 2.3.9
options = compressed resources
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.3.9 [minimum protection]]
pattern = 68 ?? ?? ?? ?? E9 ?? ?? ?? FF 50 C1 C8 18 89 05 ?? ?? ?? ?? C3 C1 C0 18 51 E9 ?? ?? ?? FF 84 C0 0F 84
at = entrypoint
requires = native
type = protector
version = 2.3.9
options = minimum protection
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.3.9 [DLL/compressed resources]]
pattern = 50 68 ?? ?? ?? ?? 58 C1 C0 0F E9 ?? ?? ?? 00 87 04 24 58 89 45 FC E9 ?? ?? ?? FF FF 05 ?? ?? ?? ?? E9
at = entrypoint
requires = native
type = protector
version = 2.3.9
options = DLL/compressed resources
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.3.9 [DLL/minimum protection]]
pattern = 51 68 ?? ?? ?? ?? 87 2C 24 8B CD 5D 81 E1 ?? ?? ?? ?? E9 ?? ?? ?? 00 89 45 F8 51 68 ?? ?? ?? ?? 59 81 F1
at = entrypoint
requires = native
type = protector
version = 2.3.9
options = DLL/minimum protection
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.XX [compressed resources]]
pattern = 56 57 53 31 DB 89 C6 89 D7 0F B6 06 89 C2 83 E0 1F C1 EA 05 74 2D 4A 74 15 8D 5C 13 02 46 C1 E0 08 89
at = entrypoint
requires = native
type = protector
version = 2.XX
options = compressed resources
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.XX [max. compressed resources]]
pattern = 55 8B EC 83 C4 EC FC 53 57 56 89 45 FC 89 55 F8 89 C6 89 D7 66 81 3E 4A 43 0F 85 23 01 00 00 83 C6 0A
at = entrypoint
requires = native
type = protector
version = 2.XX
options = max. compressed resources
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 1.3.0.45]
pattern = E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1
at = entrypoint
requires = native
type = protector
version = 1.3.0.45
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 1.4X-1.5X]
pattern = E8 $$$$$$$$ 31 C0 64 FF 30 64 89 20 64 8F 05 ?? ?? ?? ?? 83 C4 ?? E9 $$$$$$$$ 60 E8 $$$$$$$$ 83 C4
at = entrypoint
requires = native
type = protector
version = 1.4X-1.5X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 1.5X]
pattern = E8 $$$$$$$$ 31 C0 64 FF 30 64 89 20 CC C3
at = entrypoint
requires = native
type = protector
version = 1.5X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.1X]
pattern = 83 C6 14 8B 55 FC E9 ?? FF FF FF
at = entrypoint
requires = native
type = protector
version = 2.1X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.1X]
pattern = E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1
at = entrypoint
requires = native
type = protector
version = 2.1X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor 2.2X]
pattern = FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00
at = entrypoint
requires = native
type = protector
version = 2.2X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

[Strongbit EXECryptor SDK]
export = /EXECryptor_(?:AntiDebug|DecodeSerialNumber|DecryptStr|GetDate|GetEXEC|GetEXECryptorVersion|ProtectImport|IsRegistered|VerifySerialNumber)/
requires = native
type = protector
version = SDK
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Strongbit_EXECryptor.2.sg

; protector_SVK_Protector.2.sg
[SVK Protector 1.051]
pattern = 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB
at = entrypoint
type = protector
version = 1.051
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SVK_Protector.2.sg

[SVK Protector 1.11]
pattern = 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23
at = entrypoint
type = protector
version = 1.11
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SVK_Protector.2.sg

[SVK Protector 1.3X-1.4X]
pattern = 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? ?? ?? 64 A0 23
at = entrypoint
type = protector
version = 1.3X-1.4X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SVK_Protector.2.sg

[SVK Protector]
pattern = E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? ?? ?? 64 A0 23
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SVK_Protector.2.sg

[SVK Protector]
pattern = 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 74 ?? 75 ?? ?? ?? ?? 64 A0 23
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_SVK_Protector.2.sg

; protector_Tages.2.sg
[TAGES]
pattern = 89 25 ?? ?? ?? ?? E8 $$$$$$$$ 6A ?? 6A ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? E8 $$$$$$$$ 8B 44 24 ?? 0F AF 44 24 ?? 50 6A ?? FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? C3
at = entrypoint
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Tages.2.sg

; protector_tElock.2.sg
[tElock 0.41X]
pattern = 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68
at = entrypoint
type = protector
version = 0.41X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.4X]
pattern = C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6
at = entrypoint
pattern.2 = 52
at.2 = entrypoint + 0x16
type = protector
version = 0.4X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.5X]
pattern = C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6
at = entrypoint
pattern.2 = 5E
at.2 = entrypoint + 0x16
type = protector
version = 0.5X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock]
pattern = C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.60]
pattern = E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08
at = entrypoint
type = protector
version = 0.60
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.70]
pattern = 60 E8 ?? ?? 00 00 C3 83
at = entrypoint
pattern.2 = BD 10
at.2 = entrypoint + 0x2
type = protector
version = 0.70
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.71]
pattern = 60 E8 ?? ?? 00 00 C3 83
at = entrypoint
pattern.2 = ED 10
at.2 = entrypoint + 0x2
type = protector
version = 0.71
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.71b2]
pattern = 60 E8 ?? ?? 00 00 C3 83
at = entrypoint
pattern.2 = 44 11
at.2 = entrypoint + 0x2
type = protector
version = 0.71b2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.71b7]
pattern = 60 E8 ?? ?? 00 00 C3 83
at = entrypoint
pattern.2 = 48 11
at.2 = entrypoint + 0x2
type = protector
version = 0.71b7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.80]
pattern = 60 E8 ?? ?? 00 00 C3 83
at = entrypoint
pattern.2 = F9 11
at.2 = entrypoint + 0x2
type = protector
version = 0.80
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.7X-0.84]
pattern = 60 E8 ?? ?? 00 00 C3 83
at = entrypoint
type = protector
version = 0.7X-0.84
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.85f]
pattern = 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02
at = entrypoint
type = protector
version = 0.85f
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.90]
pattern = ?? ?? E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B
at = entrypoint
type = protector
version = 0.90
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.92a]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 7E E9
at.2 = entrypoint
type = protector
version = 0.92a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.95]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 D5 E4
at.2 = entrypoint
type = protector
version = 0.95
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.96]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 59 E4
at.2 = entrypoint
type = protector
version = 0.96
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.98b1]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 25 E4
at.2 = entrypoint
type = protector
version = 0.98b1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.98b2]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 1B E4
at.2 = entrypoint
type = protector
version = 0.98b2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.98 Special Build]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 99 D7
at.2 = entrypoint
type = protector
version = 0.98 Special Build
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.99]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 5E DF
at.2 = entrypoint
type = protector
version = 0.99
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.99c]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 3F DF
at.2 = entrypoint
type = protector
version = 0.99c
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 1.00]
pattern = E9 ?? ?? FF FF
at = entrypoint
pattern.2 = E9 E5 E2
at.2 = entrypoint
type = protector
version = 1.00
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

[tElock 0.35]
pattern = 66 8B C0 8D 24 24 60 9C E8 00 00 00 00 5D D1 4D
at = entrypoint
type = protector
version = 0.35
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_tElock.2.sg

; protector_Themida.2.sg
[Themida/Winlicense 2.X]
pattern = 48 83 EC 08 50 53 E8 01 00 00 00 CC 58 48 89 C3 48 FF C0 48 2D ?? ?? ?? ?? 48 2D ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 80 3B CC 75 ?? C6 03 00
at = entrypoint
requires = pe32+
type = protector
version = 2.X
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.X [DotNET]]
pattern = 48 83 EC 08 50 53 E8 01 00 00 00 CC 58 48 89 C3 48 FF C0 48 2D ?? ?? ?? ?? 48 2D ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 80 3B CC 75 ?? C6 03 00
at = entrypoint
requires = pe32+
import = /!_CorExeMain$/
type = protector
version = 2.X
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.9]
pattern = B8 00 00 00 00 60 11 C0
in = section(#0)
requires = dotnet
type = protector
version = 1.9
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.9 [DotNET]]
pattern = B8 00 00 00 00 60 11 C0
in = section(#0)
requires = dotnet
import = /!_CorExeMain$/
type = protector
version = 1.9
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.X]
pattern = 83 EC 04 80 53 E8 01 00
in = section(#0)
requires = dotnet
type = protector
version = 2.X
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.X [DotNET]]
pattern = 83 EC 04 80 53 E8 01 00
in = section(#0)
requires = dotnet
import = /!_CorExeMain$/
type = protector
version = 2.X
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.0.X.X-1.8.0.0 [Compressed]]
pattern = B8 ?? ?? ?? ?? 60 0B C0 74 ?? E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75
at = entrypoint
pattern.2 = 58
at.2 = entrypoint + 0x9
requires = native
type = protector
version = 1.0.X.X-1.8.0.0
options = Compressed
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.0.X.X-1.8.0.0 [DotNET]]
pattern = B8 ?? ?? ?? ?? 60 0B C0 74 ?? E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75
at = entrypoint
pattern.2 = 58
at.2 = entrypoint + 0x9
requires = native
import = /!_CorExeMain$/
type = protector
version = 1.0.X.X-1.8.0.0
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.8.X-1.9.X [Compressed]]
pattern = B8 ?? ?? ?? ?? 60 0B C0 74 ?? E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75
at = entrypoint
pattern.2 = 68
at.2 = entrypoint + 0x9
requires = native
type = protector
version = 1.8.X-1.9.X
options = Compressed
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.8.X-1.9.X [DotNET]]
pattern = B8 ?? ?? ?? ?? 60 0B C0 74 ?? E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75
at = entrypoint
pattern.2 = 68
at.2 = entrypoint + 0x9
requires = native
import = /!_CorExeMain$/
type = protector
version = 1.8.X-1.9.X
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense [Compressed]]
pattern = B8 ?? ?? ?? ?? 60 0B C0 74 ?? E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75
at = entrypoint
requires = native
type = protector
options = Compressed
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense [DotNET]]
pattern = B8 ?? ?? ?? ?? 60 0B C0 74 ?? E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75
at = entrypoint
requires = native
import = /!_CorExeMain$/
type = protector
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.0.X.X-1.8.X.X [NoCompression]]
pattern = 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00
at = entrypoint
requires = native
type = protector
version = 1.0.X.X-1.8.X.X
options = NoCompression
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.0.X.X-1.8.X.X [DotNET]]
pattern = 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00
at = entrypoint
requires = native
import = /!_CorExeMain$/
type = protector
version = 1.0.X.X-1.8.X.X
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.X [NoCompression SecureEngine]]
pattern = 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD
at = entrypoint
requires = native
type = protector
version = 1.X
options = NoCompression SecureEngine
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.X [DotNET]]
pattern = 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 B5 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD
at = entrypoint
requires = native
import = /!_CorExeMain$/
type = protector
version = 1.X
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.0.1.0-2.1.8.0]
pattern = 83 EC 04 50 53 E8 01 00 00 00 CC 58 8B D8 40
at = entrypoint
requires = native
type = protector
version = 2.0.1.0-2.1.8.0
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.0.1.0-2.1.8.0 [DotNET]]
pattern = 83 EC 04 50 53 E8 01 00 00 00 CC 58 8B D8 40
at = entrypoint
requires = native
import = /!_CorExeMain$/
type = protector
version = 2.0.1.0-2.1.8.0
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.0.1.0-2.1.8.0]
pattern = 51 B9 ?? ?? ?? ?? 85 C9 74 $$ 59 E9 $$$$$$$$ 83 EC ?? 50 53 ?? ?? ?? ?? ?? ?? 58 89 C3 40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3B ?? 75 ?? C6 03 ?? BB ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50
at = entrypoint
requires = native
type = protector
version = 2.0.1.0-2.1.8.0
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.0.1.0-2.1.8.0 [DotNET]]
pattern = 51 B9 ?? ?? ?? ?? 85 C9 74 $$ 59 E9 $$$$$$$$ 83 EC ?? 50 53 ?? ?? ?? ?? ?? ?? 58 89 C3 40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3B ?? 75 ?? C6 03 ?? BB ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 50
at = entrypoint
requires = native
import = /!_CorExeMain$/
type = protector
version = 2.0.1.0-2.1.8.0
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.X]
pattern = 83 EC 04 50 53 E8 01 00 00 00 CC 58 89 C3 40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3B CC 75 ?? C6 03 00
at = entrypoint
requires = native
type = protector
version = 2.X
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 2.X [DotNET]]
pattern = 83 EC 04 50 53 E8 01 00 00 00 CC 58 89 C3 40 2D ?? ?? ?? ?? 2D ?? ?? ?? ?? 05 ?? ?? ?? ?? 80 3B CC 75 ?? C6 03 00
at = entrypoint
requires = native
import = /!_CorExeMain$/
type = protector
version = 2.X
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.1.X-1.2.X]
pattern = E9 $$$$$$$$ 8B C5 8B D4 60 E8
at = entrypoint
requires = native
type = protector
version = 1.1.X-1.2.X
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 1.1.X-1.2.X [DotNET]]
pattern = E9 $$$$$$$$ 8B C5 8B D4 60 E8
at = entrypoint
requires = native
import = /!_CorExeMain$/
type = protector
version = 1.1.X-1.2.X
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense]
pattern = EB $$ E9 $$$$$$$$ E9 $$$$$$$$ 56 50 53 E8 $$$$$$$$ 58 89 C3 40 2D
at = entrypoint
requires = native
type = protector
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense [DotNET]]
pattern = EB $$ E9 $$$$$$$$ E9 $$$$$$$$ 56 50 53 E8 $$$$$$$$ 58 89 C3 40 2D
at = entrypoint
requires = native
import = /!_CorExeMain$/
type = protector
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 3.XX]
section = .themida
requires = native
type = protector
version = 3.XX
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 3.XX [DotNET]]
section = .themida
requires = native
import = /!_CorExeMain$/
type = protector
version = 3.XX
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 3.XX, Winlicense]
section = .winlice, !.themida
requires = native
type = protector
version = 3.XX, Winlicense
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

[Themida/Winlicense 3.XX, Winlicense [DotNET]]
section = .winlice, !.themida
requires = native
import = /!_CorExeMain$/
type = protector
version = 3.XX, Winlicense
options = DotNET
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Themida.2.sg

; protector_Thinstall.2.sg
[Thinstall (VMware ThinApp) 2.403]
pattern = 6A 00 FF 15 20 50 40 00 E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41
at = entrypoint
type = protector
version = 2.403
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.5XX]
pattern = 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? ?? 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10
at = entrypoint
type = protector
version = 2.5XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 1.9X]
pattern = 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00
at = entrypoint
type = protector
version = 1.9X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.0X]
pattern = B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 ?? FF FF FF
at = entrypoint
pattern.2 = AD
at.2 = entrypoint + 0xF
type = protector
version = 2.0X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.2X-2.308]
pattern = B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 ?? FF FF FF
at = entrypoint
pattern.2 = B9
at.2 = entrypoint + 0xF
type = protector
version = 2.2X-2.308
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp)]
pattern = B8 EF BE AD DE 50 6A 00 FF 15 ?? ?? ?? ?? E9 ?? FF FF FF
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.545]
pattern = E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00
at = entrypoint
type = protector
version = 2.545
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.547-2.600]
pattern = E8 00 00 00 00 58 BB ?? ?? 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68
at = entrypoint
pattern.2 = C1 80
at.2 = entrypoint + 0x7
type = protector
version = 2.547-2.600
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.609]
pattern = E8 00 00 00 00 58 BB ?? ?? 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68
at = entrypoint
pattern.2 = AD 19
at.2 = entrypoint + 0x7
type = protector
version = 2.609
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.620-2.623]
pattern = E8 00 00 00 00 58 BB ?? ?? 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68
at = entrypoint
pattern.2 = AC 1E
at.2 = entrypoint + 0x7
type = protector
version = 2.620-2.623
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.628]
pattern = E8 00 00 00 00 58 BB ?? ?? 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68
at = entrypoint
pattern.2 = 34 1D
at.2 = entrypoint + 0x7
type = protector
version = 2.628
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.6XX]
pattern = E8 00 00 00 00 58 BB ?? ?? 00 00 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? 00 00 68
at = entrypoint
type = protector
version = 2.6XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 2.7XX]
pattern = 9C 60 E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? E9
at = entrypoint
type = protector
version = 2.7XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 3.035-3.043]
pattern = 9C 60 68 'StAl' 68 'ThIn' E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68
at = entrypoint
pattern.2 = 00 28
at.2 = entrypoint + 0x20
type = protector
version = 3.035-3.043
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 3.049-3.080]
pattern = 9C 60 68 'StAl' 68 'ThIn' E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68
at = entrypoint
pattern.2 = 00 2C
at.2 = entrypoint + 0x20
type = protector
version = 3.049-3.080
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 3.0XX]
pattern = 9C 60 68 'StAl' 68 'ThIn' E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68
at = entrypoint
pattern.2 = BA FE
at.2 = entrypoint + 0x2A
type = protector
version = 3.0XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 3.10X]
pattern = 9C 60 68 'StAl' 68 'ThIn' E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68
at = entrypoint
pattern.2 = 2C FF
at.2 = entrypoint + 0x2A
type = protector
version = 3.10X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp)]
pattern = 9C 60 68 'StAl' 68 'ThIn' E8 00 00 00 00 58 BB ?? ?? ?? ?? 2B C3 50 68
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 5.0]
pattern = B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 2B E0 8D 50 ?? 45 33 C0 33 C9 E8 ?? ?? ?? ?? 85 C0 75 ?? B9 ?? ?? ?? ?? FF 15
at = entrypoint
type = protector
version = 5.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 5.2.2]
pattern = 6A ?? 6A ?? 6A ?? E8 $$$$$$$$ 8B FF 55 8B EC 83 7D ?? ?? 75 ?? E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65
at = entrypoint
pattern.2 = 09 05 00 00
at.2 = overlay
type = protector
version = 5.2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

[Thinstall (VMware ThinApp) 5.2.4]
pattern = 6A ?? 6A ?? 6A ?? E8 $$$$$$$$ 55 8B EC 83 7D ?? ?? 75 ?? E8 $$$$$$$$ 55 8B EC 83 EC ?? 83 65 ?? ?? 83 65 ?? ?? A1
at = entrypoint
pattern.2 = 09 05 00 00
at.2 = overlay
type = protector
version = 5.2.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Thinstall.2.sg
x-die-loss = version replaced by the ThinAppVersion version info value if present

; protector_UG2002_Cruncher.2.sg
[UG2002 Cruncher 0.3b3]
pattern = 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? E8 0D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 58
at = entrypoint
type = protector
version = 0.3b3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UG2002_Cruncher.2.sg

; protector_UltraPro.2.sg
[UltraPro 1.0]
pattern = A1 ?? ?? ?? ?? 85 C0 0F 85 3B 06 00 00 55 56 C7 05 ?? ?? ?? ?? 01 00 00 00 FF 15
at = entrypoint
type = protector
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UltraPro.2.sg

[UltraPro 0.75]
pattern = 60 E8 07 00 00 00 61 68 ?? ?? 40 00 C3 83 04 24 18 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 61
at = entrypoint
type = protector
version = 0.75
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UltraPro.2.sg

[UltraPro 1.03-1.10]
pattern = 83 EC 04 C7 04 24 00 ?? ?? ?? C3 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? 00 10 00 00 00 02 00 00 01
at = entrypoint
type = protector
version = 1.03-1.10
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UltraPro.2.sg

; protector_UPolyX.2.sg
[UPolyX 0.X]
pattern = 81 FD 00 FB FF FF 83 D1 ?? 8D 14 2F 83 FD FC 76 ?? 8A 02 42 88 07 47 49 75
at = entrypoint
type = protector
version = 0.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UPolyX.2.sg

[UPolyX 0.1]
pattern = E2 ?? FF ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00
at = entrypoint
type = protector
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UPolyX.2.sg

[UPolyX 0.5]
pattern = 55 8B EC ?? 00 BD 46 00 8B ?? B9 ?? 00 00 00 80 ?? ?? 51
at = entrypoint
type = protector
version = 0.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UPolyX.2.sg

[UPolyX 0.5]
pattern = BB ?? ?? ?? ?? 83 EC 04 89 1C 24 ?? B9 ?? 00 00 00 80 33
at = entrypoint
type = protector
version = 0.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UPolyX.2.sg

[UPolyX 0.5]
pattern = E8 00 00 00 00 59 83 C1 07 51 C3 C3
at = entrypoint
type = protector
version = 0.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UPolyX.2.sg

[UPolyX 0.5]
pattern = 83 EC 04 89 ?? 24 59 ?? ?? 00 00 00
at = entrypoint
type = protector
version = 0.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UPolyX.2.sg

; protector_UPX_Protector.2.sg
[UPX Protector 1.0X]
pattern = EB ?? ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB
at = entrypoint
type = protector
version = 1.0X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_UPX_Protector.2.sg

; protector_VaySoft_PDF2EXE.2.sg
[VaySoft PDF to EXE Converter 6.82 [PDF Adv.Xor Ovl.]]
pattern = 55 8B EC B9
at = entrypoint
pattern.2 = 25 5B 48 42 20 32 2A
at.2 = overlay
type = protector
version = 6.82
options = PDF Adv.Xor Ovl.
author = A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VaySoft_PDF2EXE.2.sg

; protector_VBox.2.sg
[VBox 4.10]
pattern = FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15
at = entrypoint
import = vboxp410.dll
type = protector
version = 4.10
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VBox.2.sg

[VBox 4.03]
pattern = FF 74 24 ?? FF 74 24 ?? FF 74 24 ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15
at = entrypoint
import = vboxp403.dll, !vboxp410.dll
type = protector
version = 4.03
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VBox.2.sg

[VBox 4.20]
pattern = 55 8B EC 83 C4 ?? 56 57 BE ?? ?? ?? ?? 8B 45 ?? 89 46 ?? FF 75 ?? 8F 46 ?? 8B 45 ?? 89 46 ?? 56
in = entrypoint[0-0x1000]
type = protector
version = 4.20
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VBox.2.sg

; protector_VbsToExe.1.sg
[Vbs To Exe 2.0.2.0]
pattern = '2edecompile'
at = resource(*/D) + 0x2
type = protector
version = 2.0.2.0
lang = VBScript
author = horsicq, A.S.L, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VbsToExe.1.sg

[Vbs To Exe 2.0.2.0 [Protected]]
pattern = '2edecompile'
at = resource(*/D) + 0x2
resource = */P
type = protector
version = 2.0.2.0
options = Protected
lang = VBScript
author = horsicq, A.S.L, adoxa
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VbsToExe.1.sg

; protector_VCasm-Protector.2.sg
[VCasm-Protector 1.0X]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00
at = entrypoint
type = protector
version = 1.0X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VCasm-Protector.2.sg

[VCasm-Protector 1.0e]
pattern = EB ?? '[VProtect]'
at = entrypoint
pattern.2 = ?? 0A
at.2 = entrypoint
type = protector
version = 1.0e
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VCasm-Protector.2.sg

[VCasm-Protector 1.1-1.2]
pattern = EB ?? '[VProtect]'
at = entrypoint
pattern.2 = ?? 0B
at.2 = entrypoint
type = protector
version = 1.1-1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VCasm-Protector.2.sg

[VCasm-Protector 1.X]
pattern = EB ?? '[VProtect]'
at = entrypoint
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VCasm-Protector.2.sg

; protector_Virbox.2.sg
[Virbox]
pattern = 'SENS'
at = image + 0x28
type = protector
author = Vito
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Virbox.2.sg

; protector_VMProtect.2.sg
[VMProtect]
section = .vmp0, .vmp1
requires = native, pe32
type = protector
author = ajax, hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VMProtect.2.sg
x-die-loss = position of the .vmp sections (last section apart from relocations and resources) not checked; version from import hashes not determined

[VMProtect [min protection]]
section = .vmp0, !.vmp1
requires = native, pe32
type = protector
options = min protection
author = ajax, hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VMProtect.2.sg
x-die-loss = position of the .vmp sections (last section apart from relocations and resources) not checked; version from import hashes not determined

[VMProtect 2.XX-3.XX]
section = .vmp0, .vmp1
requires = native, pe32+
type = protector
version = 2.XX-3.XX
author = ajax, hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VMProtect.2.sg
x-die-loss = position of the .vmp sections (last section apart from relocations and resources) not checked; version from import hashes not determined

[VMProtect 2.XX-3.XX [min protection]]
section = .vmp0, !.vmp1
requires = native, pe32+
type = protector
version = 2.XX-3.XX
options = min protection
author = ajax, hypn0, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VMProtect.2.sg
x-die-loss = position of the .vmp sections (last section apart from relocations and resources) not checked; version from import hashes not determined

; protector_VMProtect_NET.2.sg
[VMProtect 3.X]
pattern = '<Module>' 00 %% %% %% %% %% %% %% %% 00
in = dotnet_stream(#Strings)
pattern.2 = 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00
in.2 = dotnet_stream(#Strings)[0-0x100000]
dotnet_string = SuppressIldasmAttribute, kernel32, get_IsAttached, OpCodes, !VMProtect
requires = dotnet
type = protector
version = 3.X
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VMProtect_NET.2.sg
x-die-loss = global .NET cctor and section count not checked; name patterns searched in the #Strings heap (the run of 12 names in its first 1 MiB) instead of the whole image

[VMProtect 3.X [Resources protection]]
pattern = '<Module>' 00 %% %% %% %% %% %% %% %% 00
in = dotnet_stream(#Strings)
pattern.2 = 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00
in.2 = dotnet_stream(#Strings)[0-0x100000]
pattern.3 = w'Program will be terminated.'
in.3 = image
dotnet_string = SuppressIldasmAttribute, kernel32, get_IsAttached, OpCodes, !VMProtect
requires = dotnet
type = protector
version = 3.X
options = Resources protection
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VMProtect_NET.2.sg
x-die-loss = global .NET cctor and section count not checked; name patterns searched in the #Strings heap (the run of 12 names in its first 1 MiB) instead of the whole image

[VMProtect 2.X-3.X]
pattern = '<Module>' 00 %% %% %% %% %% %% %% %% 00
in = dotnet_stream(#Strings)
pattern.2 = 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00
in.2 = dotnet_stream(#Strings)[0-0x100000]
section = .vmp0, .vmp1
dotnet_string = SuppressIldasmAttribute, kernel32, get_IsAttached, OpCodes, !VMProtect
requires = dotnet
type = protector
version = 2.X-3.X
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VMProtect_NET.2.sg
x-die-loss = global .NET cctor and section count not checked; name patterns searched in the #Strings heap (the run of 12 names in its first 1 MiB) instead of the whole image

[VMProtect 2.X-3.X [Resources protection]]
pattern = '<Module>' 00 %% %% %% %% %% %% %% %% 00
in = dotnet_stream(#Strings)
pattern.2 = 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00 %% %% %% %% %% %% %% %% 00
in.2 = dotnet_stream(#Strings)[0-0x100000]
pattern.3 = w'Program will be terminated.'
in.3 = image
section = .vmp0, .vmp1
dotnet_string = SuppressIldasmAttribute, kernel32, get_IsAttached, OpCodes, !VMProtect
requires = dotnet
type = protector
version = 2.X-3.X
options = Resources protection
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_VMProtect_NET.2.sg
x-die-loss = global .NET cctor and section count not checked; name patterns searched in the #Strings heap (the run of 12 names in its first 1 MiB) instead of the whole image

; protector_XCR.2.sg
[XCR 0.13]
pattern = 93 71 ?? EB $$ EB $$ 8B D8 78 $$ EB $$ 9C 33 C0 EB $$ 74 $$ EB $$ 60 79 ?? EB $$ E8 $$$$$$$$ 83 C4 ?? E8 $$$$$$$$ 8D 05 ?? ?? ?? ?? EB $$ 5D 85 ED 75
at = entrypoint
type = protector
version = 0.13
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_XCR.2.sg

; protector_Xenocode_Postbuild.2.sg
[Xenocode Postbuild 2.X-3.X]
dotnet_string = Xenocode.Client.Attributes.AssemblyAttributes
type = protector
version = 2.X-3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Xenocode_Postbuild.2.sg

[Xenocode Postbuild]
pattern = 'xvm' 00 01
at = overlay
dotnet_string = !Xenocode.Client.Attributes.AssemblyAttributes
section = .xcpad
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Xenocode_Postbuild.2.sg

; protector_XerinFuscator.2.sg
[XerinFuscator]
pattern = 'XerinFuscator v'
in = section
dotnet_string = XerinAtrribute
requires = dotnet
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_XerinFuscator.2.sg
x-die-loss = version read from file

[XerinFuscator [XVM]]
pattern = 'XerinFuscator v'
in = section
dotnet_string = XerinAtrribute, Xerin.Runtime
requires = dotnet
type = protector
options = XVM
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_XerinFuscator.2.sg
x-die-loss = version read from file

[XerinFuscator]
pattern = 'XerinFuscator v'
in = section
dotnet_string = XerinFuscator, !XerinAtrribute
requires = dotnet
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_XerinFuscator.2.sg
x-die-loss = version read from file

[XerinFuscator]
dotnet_us = "C# version only supports level 1 and 3"
section = !.text
dotnet_string = !XerinAtrribute, !XerinFuscator
requires = dotnet
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_XerinFuscator.2.sg
x-die-loss = first section not named .text approximated by no .text section; section count not checked

[XerinFuscator Legacy]
section = .Xerin
dotnet_string = !XerinAtrribute, !XerinFuscator
requires = dotnet
type = protector
version = Legacy
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_XerinFuscator.2.sg

; protector_Xtreamlok.2.sg
[Xtreamlok (SoftWrap) 1.X-3.X]
pattern = 90 90 EB $$ 52 53 51 56 57 55 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? E8 $$$$$$$$ 6A ?? E9
at = entrypoint
type = protector
version = 1.X-3.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Xtreamlok.2.sg

[Xtreamlok (SoftWrap) 1.X-3.X]
pattern = 90 EB $$ 52 53 51 56 57 55 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? E8 $$$$$$$$ 6A ?? E9
at = entrypoint
type = protector
version = 1.X-3.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Xtreamlok.2.sg

[Xtreamlok (SoftWrap) 1.X-3.X]
pattern = 90 90 90 EB $$ 52 53 51 56 57 55 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? E8 $$$$$$$$ 6A ?? E9
at = entrypoint
type = protector
version = 1.X-3.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Xtreamlok.2.sg

[Xtreamlok (SoftWrap) 1.X-3.X]
pattern = EB $$ 52 53 51 56 57 55 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? E8 $$$$$$$$ 6A ?? E9
at = entrypoint
type = protector
version = 1.X-3.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Xtreamlok.2.sg

; protector_Yano.2.sg
[Yano 1.X]
dotnet_string = YanoAttribute
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Yano.2.sg

; protector_Yodas_Protector.2.sg
[Yoda's Protector 1.01]
pattern = 55 8B EC 53 56 57 E8 $$$$$$$$ E8 $$$$$$$$ 33 C0 64 FF 30 64 89 20 CC C3
at = entrypoint
type = protector
version = 1.01
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Yodas_Protector.2.sg

[Yoda's Protector 1.02-1.03]
pattern = E8 $$$$$$$$ BB ?? ?? ?? ?? E8 $$$$$$$$ E8 $$$$$$$$ 33 C0 64 FF 30 64 89 20 4B CC C3
at = entrypoint
section = !.inq
type = protector
version = 1.02-1.03
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Yodas_Protector.2.sg
x-die-loss = absence of .inq checked for all sections instead of the last section

; protector_Yummy_Game_SoftwareShield.2.sg
[Yummy Game SoftwareShield 5.X]
pattern = 31 C0 E9 B9 FF FF FF C3
at = entrypoint
type = protector
version = 5.X
author = Levis
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Yummy_Game_SoftwareShield.2.sg

; protector_Zprotect.2.sg
[Zprotect 1.X]
pattern = 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00
at = section(#1)
type = protector
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Zprotect.2.sg
x-die-loss = more than 3 sections, first section without raw data and missing DOS stub not checked

[Zprotect]
pattern = E8 $$$$$$$$ 87 ?? 24 8D ?? ?? ?? ?? ?? 87 ?? 24 E9 $$$$$$$$ 60 E9 $$$$$$$$ 54 E9
at = entrypoint
type = protector
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protector_Zprotect.2.sg


; ======================================================================
; Protections (dongles, anti-cheat, obfuscation)
; ======================================================================

; protection_BattlEye.5.sg
[BattlEye]
section = .be0, .be1
import = /ntdll/
requires = signed
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_BattlEye.5.sg
x-die-loss = getSectionNameCollision("0", "1") == ".be" is approximated by the section names .be0 and .be1

[BattlEye]
section = .be0, .be1
import = /!CryptCATAdminAcquireContext$/
requires = signed
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_BattlEye.5.sg
x-die-loss = getSectionNameCollision("0", "1") == ".be" is approximated by the section names .be0 and .be1

[BattlEye Launcher]
pattern = 'https://cdn.battleye.com/%S/%s/%s'
in = image
section = .be0, .be1
import = /ntdll/
requires = signed
type = protector
version = Launcher
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_BattlEye.5.sg
x-die-loss = getSectionNameCollision("0", "1") == ".be" is approximated by the section names .be0 and .be1

[BattlEye Launcher]
pattern = 'https://cdn.battleye.com/%S/%s/%s'
in = image
section = .be0, .be1
import = /!CryptCATAdminAcquireContext$/
requires = signed
type = protector
version = Launcher
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_BattlEye.5.sg
x-die-loss = getSectionNameCollision("0", "1") == ".be" is approximated by the section names .be0 and .be1

; protection_Denuvo.5.sg
[Denuvo 1.0]
pattern = 51 52 41 50 41 51 4C 8D ?? ?? ?? ?? ?? 4C 8D ?? ?? ?? ?? ?? 4D 29 C1
at = entrypoint
requires = native, pe32+
type = protector
version = 1.0
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 2.0b]
pattern = 48 89 ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? 4C 89 ?? ?? ?? ?? ?? 4C 89 ?? ?? ?? ?? ?? 48 83 FA 01
at = entrypoint
requires = native, pe32+
type = protector
version = 2.0b
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 3.0a]
pattern = ?? ?? ?? ?? ?? ?? ?? ?? 4C 89 1C 24 49 89 E3
at = entrypoint
requires = native, pe32+
type = protector
version = 3.0a
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 12.0-17.0+]
pattern = 48 8D 64 24 ?? 50 51 52 80 3D ?? ?? ?? ?? ?? 75 ?? 48 8D 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??
at = entrypoint
requires = native, pe32+
type = protector
version = 12.0-17.0+
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 12.0-17.0+]
pattern = 48 8D A4 24 ?? ?? ?? ?? 50 51 52 80 3D ?? ?? ?? ?? ?? 75 ?? 48 8D 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??
at = entrypoint
requires = native, pe32+
type = protector
version = 12.0-17.0+
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 3.0b]
pattern = 4D 8D ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? 48 8D ?? ?? 48 89 ?? 48 89 ?? 48 89
at = entrypoint
requires = native, pe32+
type = protector
version = 3.0b
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo [Unity]]
pattern = 47 61 6D 65 41 73 73 65 6D 62 6C 79 44 65 6E 75 76 6F 44 72 6D 2E 64 6C 6C
at = entrypoint
requires = native, pe32+
type = protector
options = Unity
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 18.0-19.0]
pattern = 48 83 EC ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 F8 00 74 ?? 48 83 C4 58 48 89 25 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 31 C9
at = entrypoint
requires = native, pe32+
type = protector
version = 18.0-19.0
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 18.0-19.0]
pattern = 48 83 EC 28 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 83 F8 00 74 ?? 48 83 C4 28 48 89 25 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 31 C9
at = entrypoint
requires = native, pe32+
type = protector
version = 18.0-19.0
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo]
pattern = 64 65 6E 75 76 6F 5F 61 74 64 00 00 00 00 00 00
in = section
section = /^\.([ex](text|code)|([eu]|my|s[xr]|x[pd])data|arch|xtls)$/
requires = native, pe32+
type = protector
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo [x64]]
section = /^\.([ex](text|code)|([eu]|my|s[xr]|x[pd])data|arch|xtls)$/
import = denuvo64.dll
requires = native, pe32+
type = protector
options = x64
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 1.0]
pattern = 55 89 E5 8D ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ??
at = entrypoint
requires = native, pe32
type = protector
version = 1.0
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo 2.0]
pattern = 8D ?? ?? ?? ?? ?? ?? 89 7C 24 04 89 E7
at = entrypoint
requires = native, pe32
type = protector
version = 2.0
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of sections > 10 not checked

[Denuvo [FIFA23 series]]
section = /^\.([ex](text|code)|([eu]|my|s[xr]|x[pd])data|arch|xtls)$/
import = dbdata.dll
requires = native
type = protector
options = FIFA23 series
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg

[Denuvo [uPlay]]
section = /^\.([ex](text|code)|([eu]|my|s[xr]|x[pd])data|arch|xtls)$/
import = uplay_r1_loader64.dll
requires = native
type = protector
options = uPlay
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg

[Denuvo [Origin]]
import = /^core[\\\/]activation(64)?\.dll$/i
requires = native
type = protector
options = Origin
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg

[Denuvo]
export = /^GetDenuvo(TimeTicketRequest|TicketLocation)$/
import = /^d3d/
requires = native
type = protector
author = deadmau5, DosX, Nitr0-G, 0x80000003, BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Denuvo.5.sg
x-die-loss = number of imports > 10 not checked

; protection_DS.Eutron_SmartKey_dongle.5.sg
[Eutron SmartKey dongle reference]
pattern = 'skeydrv.dll'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Eutron_SmartKey_dongle.5.sg

[Eutron SmartKey dongle reference]
pattern = 5C 5C 2E 5C 'eusk2'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Eutron_SmartKey_dongle.5.sg

[Eutron SmartKey dongle reference]
pattern = 5C 5C 2E 5C 'Skey-'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Eutron_SmartKey_dongle.5.sg

[Eutron SmartKey dongle reference]
pattern = 5C 5C 2E 5C 'SkeyDev'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Eutron_SmartKey_dongle.5.sg

; protection_DS.Hardlock_dongle.5.sg
[Hardlock dongle reference]
pattern = 5C 5C 2E 5C 'HARDLOCK.VXD'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Hardlock_dongle.5.sg

[Hardlock dongle reference]
pattern = 5C 5C 2E 5C 'FEnteDev'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Hardlock_dongle.5.sg

; protection_DS.HASP_dongle.5.sg
[HASP dongle reference]
pattern = 'HASPDOSDRV'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.HASP_dongle.5.sg

[HASP dongle reference]
pattern = 'HASPUT16.DLL'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.HASP_dongle.5.sg

[HASP dongle reference Visual Basic]
pattern = 'haspvb32.dll'
in = image
import = msvbvm60.dll
type = protector
version = Visual Basic
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.HASP_dongle.5.sg

[HASP dongle reference Visual Basic]
pattern = 'haspvb32.dll'
in = image
import = msvbvm50.dll
type = protector
version = Visual Basic
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.HASP_dongle.5.sg

; protection_DS.MARX_Crypto-Box_dongle.5.sg
[MARX Crypto-Box dongle reference]
pattern = 'MARXDEV1.SYS'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.MARX_Crypto-Box_dongle.5.sg

[MARX Crypto-Box dongle reference]
pattern = 5C 5C 2E 5C 'MARXDEV'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.MARX_Crypto-Box_dongle.5.sg

[MARX Crypto-Box dongle reference]
pattern = 5C 5C 2E 5C 'Cb7Dev'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.MARX_Crypto-Box_dongle.5.sg

[MARX Crypto-Box dongle reference]
pattern = 5C 5C 2E 5C 'CB7'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.MARX_Crypto-Box_dongle.5.sg

[MARX Crypto-Box dongle reference]
pattern = 5C 5C 2E 5C 'CBUSB'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.MARX_Crypto-Box_dongle.5.sg

; protection_DS.Matrix_Hardware_Lock_dongle.5.sg
[Matrix Hardware Lock dongle reference]
pattern = 'MxLPT_Sem'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Matrix_Hardware_Lock_dongle.5.sg

[Matrix Hardware Lock dongle reference]
pattern = 'MxUSB_Sem'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Matrix_Hardware_Lock_dongle.5.sg

; protection_DS.NetHASP_dongle.5.sg
[NetHASP dongle reference]
pattern = 'NETHASP_00112233445566zz'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.NetHASP_dongle.5.sg

[NetHASP dongle reference]
pattern = 'nethasp.ini'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.NetHASP_dongle.5.sg

; protection_DS.SenseLock_dongle.5.sg
[SenseLock dongle reference]
pattern = 'sense4.dll'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.SenseLock_dongle.5.sg

[SenseLock dongle reference]
pattern = 'S4Open'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.SenseLock_dongle.5.sg

; protection_DS.Sentinel_dongle.5.sg
[Rainbow Sentinel dongle reference]
pattern = 'SNTNLUSB'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Sentinel_dongle.5.sg

[Rainbow Sentinel dongle reference]
pattern = 5C 5C 2E 5C 'SENTINEL.VXD'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Sentinel_dongle.5.sg

[Rainbow Sentinel dongle reference]
pattern = 5C 5C 2E 5C 'SntnlUsb'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Sentinel_dongle.5.sg

; protection_DS.Sentinel_SuperPro_dongle.5.sg
[Sentinel SuperPro dongle reference]
pattern = 'RNBOspro'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Sentinel_SuperPro_dongle.5.sg

; protection_DS.SoftLok_dongle.5.sg
[SoftLok dongle reference]
pattern = 5C 5C 2E 5C 'MNXX'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.SoftLok_dongle.5.sg

[SoftLok dongle reference]
pattern = 5C 5C 2E 5C 'SoftLok'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.SoftLok_dongle.5.sg

; protection_DS.Unikey_dongle.5.sg
[Unikey/Activator dongle reference]
pattern = 'SSIVDDP.DLL'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Unikey_dongle.5.sg

[Unikey/Activator dongle reference]
pattern = 5C 00 44 00 65 00 76 00 69 00 63 00 65 00 5C 00 53 00 53 00 49 00 50 00 44 00 44 00 50 00
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Unikey_dongle.5.sg

[Unikey/Activator dongle reference]
pattern = 5C 5C 2E 5C 'SSIPDDP'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Unikey_dongle.5.sg

[Unikey/Activator dongle reference]
pattern = 5C 5C 2E 5C 'PIPE\\SSINetPipe'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.Unikey_dongle.5.sg

; protection_DS.WIBU_Key_dongle.5.sg
[WIBU Key dongle reference]
pattern = 'WIBUKEY'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.WIBU_Key_dongle.5.sg

[WIBU Key dongle reference]
pattern = 'WkWin32.dll'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.WIBU_Key_dongle.5.sg

[WIBU Key dongle reference]
pattern = 'WKWIN32.DLL'
in = image
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_DS.WIBU_Key_dongle.5.sg

; protection_HASP_HL_Protection.5.sg
[HASP HL/SRM 4.X [HL]]
pattern = 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 74 ?? 8B 0D ?? ?? ?? ?? 51 FF 15
at = entrypoint
requires = pe32
type = protector
version = 4.X
options = HL
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_HASP_HL_Protection.5.sg

[HASP HL/SRM 1.X [SRM]]
pattern = 57 56 53 51 E8 01 00 00 00 ?? 58 05 ?? ?? ?? ?? 50 8B 30 03 F0 2B C0 8B FE 66 AD
at = entrypoint
requires = pe32
type = protector
version = 1.X
options = SRM
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_HASP_HL_Protection.5.sg

[HASP HL/SRM 1.X [HL]]
pattern = 55 8B EC 53 56 57 60 8B C4 A3 ?? ?? ?? ?? B8 ?? ?? ?? ?? 2B 05 ?? ?? ?? ?? A3 ?? ?? ?? ?? 83 3D ?? ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? A1 ?? ?? ?? ?? 50 FF 15
at = entrypoint
requires = pe32
type = protector
version = 1.X
options = HL
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_HASP_HL_Protection.5.sg

[HASP HL/SRM 1.X [SRM]]
pattern = 57 50 56 9C 53 51 52 41 50 41 51 48 8D 05 ?? ?? ?? ?? 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD
at = entrypoint
requires = pe32+
type = protector
version = 1.X
options = SRM
author = ajax
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_HASP_HL_Protection.5.sg

; protection_Microsoft_Warbird.2.sg
[Microsoft Warbird]
section = ?g_Encry
import = /!NtQuerySystemInformation$/
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Microsoft_Warbird.2.sg

[Microsoft Warbird [VM]]
pattern = '?g_EncryptedSegmentSystemCall_'
in = image
section = ?g_Encry
import = /!NtQuerySystemInformation$/
type = protector
options = VM
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Microsoft_Warbird.2.sg

[Microsoft Warbird]
section = /^PAGE(?:VRFY|wx[1-6])$/
import = /\.sys$/i
type = protector
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Microsoft_Warbird.2.sg

; protection_NetEase.5.sg
[NetEase [Protect II]]
import = nep2.dll
type = protector
options = Protect II
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_NetEase.5.sg

; protection_obfus_h.5.sg
[obfus.h]
export = WhatSoundDoesACowMake
type = protector
lang = C
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_obfus_h.5.sg
x-die-loss = linker version 6.0 (getCompilerVersion) not checked

; protection_obfusheader_h.5.sg
[obfusheader.h]
pattern = 'Stop reversing the binary'
in = section(.rdata)
pattern.2 = 'Reconsider your life choices'
in.2 = section(.rdata)
pattern.3 = 'And go touch some grass'
in.3 = section(.rdata)
type = protector
lang = C++
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_obfusheader_h.5.sg
x-die-loss = the two other messages are not required within 0x80 bytes before and 0x100 bytes after the first

[obfusheader.h [data consts]]
pattern = 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 53 4C 41 49 44 50
at = section(.data)
type = protector
options = data consts
lang = C++
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_obfusheader_h.5.sg

[obfusheader.h [fake signs]]
section = .enigma1, .vmp0, .xtls
type = protector
options = fake signs
lang = C++
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_obfusheader_h.5.sg
x-die-loss = the results Enigma, SecuROM, Denuvo and Themida/Winlicense are not removed

; protection_Softlocx.1.sg
[Softlocx 6.0]
pattern = EB $$ 55 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8B C5 55 60 9C 2B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? FF 74
at = entrypoint
type = protector
version = 6.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Softlocx.1.sg

; protection_SteamStub.5.sg
[SteamStub]
pattern = E8 00 00 00 00 50 53 51 52 56 57 55 8B 44 24 ?? 2D ?? ?? ?? ?? 8B CC 83 E4 ?? 51 51 51 50 E8 ?? ?? ?? ?? 83 C4 ?? 59 59 59 8B E1 89 44 24 ?? 5D 5F 5E 5A 59 5B 58 C3
at = entrypoint
type = protector
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_SteamStub.5.sg

[SteamStub [x64]]
pattern = E8 00 00 00 00 50 53 51 52 56 57 55 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 48 8B 4C 24 ?? 48 81 E9 ?? ?? ?? ?? 48 8B C4 48 83 E4 ?? 50 50 48 83 EC ?? E8 ?? ?? ?? ?? 48 83 C4 ?? 59 59
at = entrypoint
type = protector
options = x64
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_SteamStub.5.sg

; protection_Wibu_Codemeter.1.sg
[Wibu Codemeter]
section = __wibu00, __wibu01
type = protector
author = sendersu
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/protection_Wibu_Codemeter.1.sg


; ======================================================================
; Cryptors
; ======================================================================

; cryptor_Amber.2.sg
[Amber]
pattern = 83 EC 0C C7 05 94 53 40 00 01 00 00 00 E8 9E 02 00 00 83 C4 0C E9 A6 FC FF FF 8D B6 00 00 00 00 83 EC 0C C7 05 94 53 40 00 00 00 00 00 E8 7E 02 00 00 83 C4 0C E9 86 FC FF FF 8D B6 00 00 00 00 83 EC 1C 8B 44 24 20 89 04 24 E8 1D 12 00 00 85 C0 0F 94 C0 83 C4 1C 0F B6 C0 F7 D8 C3 90 90 90 55 89 E5 83
at = entrypoint
requires = pe32
type = cryptor
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Amber.2.sg
x-die-loss = import hash 0x97c72051 not checked

; cryptor_AverCryptor.2.sg
[AverCryptor 1.0]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? B8
at = entrypoint
pattern.2 = FA
at.2 = entrypoint + 0x41
section = .avc
type = cryptor
version = 1.0
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_AverCryptor.2.sg

[AverCryptor 1.0 [modified]]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? B8
at = entrypoint
pattern.2 = FA
at.2 = entrypoint + 0x41
section = !.avc
type = cryptor
version = 1.0
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_AverCryptor.2.sg

[AverCryptor 1.02]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? B8
at = entrypoint
pattern.2 = F7
at.2 = entrypoint + 0x41
section = .avc
type = cryptor
version = 1.02
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_AverCryptor.2.sg

[AverCryptor 1.02 [modified]]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? B8
at = entrypoint
pattern.2 = F7
at.2 = entrypoint + 0x41
section = !.avc
type = cryptor
version = 1.02
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_AverCryptor.2.sg

[AverCryptor]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? B8
at = entrypoint
section = .avc
type = cryptor
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_AverCryptor.2.sg

[AverCryptor [modified]]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8B BD ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? B8
at = entrypoint
section = !.avc
type = cryptor
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_AverCryptor.2.sg

; cryptor_BattleshipCrypter.2.sg
[Battleship Crypter 1.0]
pattern = 68 18 14 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00 7A 88 CD 65 9A 43 26 4D 8D F7 47 BE 86 15 23 7F
at = entrypoint
type = cryptor
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_BattleshipCrypter.2.sg

; cryptor_BorrCod.2.sg
[BorrCod]
dotnet_string = StubEch, Crypted.exe
requires = dotnet
type = cryptor
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_BorrCod.2.sg
x-die-loss = the module name Crypted.exe is only checked as an entry of the #Strings heap

; cryptor_CronosCrypter.1.sg
[CronosCrypter]
pattern = 43 72 6F 6E 6F 73 2D 43 72 79 70 74 65 72
in = section(#0)
requires = dotnet
type = cryptor
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_CronosCrypter.1.sg

; cryptor_CryptEngine_MalwareCryptor.2.sg
[CryptEngine NET-MalwareCryptor]
dotnet_string = Inject
dotnet_us = EntryPoint, Invoke, Load
type = cryptor
version = NET-MalwareCryptor
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_CryptEngine_MalwareCryptor.2.sg

; cryptor_Daemon_Crypt.2.sg
[Daemon Crypt 2.0 Public]
pattern = 'Daemon_Crypt1152'
at = overlay
import = msvbvm60.dll
type = cryptor
version = 2.0 Public
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Daemon_Crypt.2.sg
x-die-loss = MSVBVM60.DLL not checked to be the first library; the options AV killer and modified (import hashes) are not reported

; cryptor_DekkCrypt.2.sg
[DekkCrypt]
dotnet_us = encfile
dotnet_string = Encrypted.resources
type = cryptor
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_DekkCrypt.2.sg

; cryptor_Duals_eXe_Encryptor.2.sg
[Duals eXe Encryptor 1.0]
pattern = 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E
at = entrypoint
pattern.2 = 08 03
at.2 = entrypoint + 0x12
type = cryptor
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Duals_eXe_Encryptor.2.sg

[Duals eXe Encryptor 1.0b]
pattern = 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E
at = entrypoint
pattern.2 = 3A 04
at.2 = entrypoint + 0x12
type = cryptor
version = 1.0b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Duals_eXe_Encryptor.2.sg

[Duals eXe Encryptor]
pattern = 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E
at = entrypoint
type = cryptor
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Duals_eXe_Encryptor.2.sg

; cryptor_Encryptix.2.sg
[Encryptix]
dotnet_string = /^by-unknown/, WriteProcessMemory
requires = dotnet
type = cryptor
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Encryptix.2.sg
x-die-loss = the module name starting with by-unknown is only checked as an entry of the #Strings heap

; cryptor_Huan.2.sg
[Huan]
pattern = 48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 E9 ?? ?? ?? ?? CC CC 40 53 48 83 EC ?? 48 8B D9 33 C9 FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B C8 BA ?? ?? ?? ?? 48 83 C4 ?? 5B 48 FF 25 ?? ?? ?? ?? 48 89 4C 24 ??
at = entrypoint
requires = pe32+
import = /!VirtualAlloc$/, /!LoadLibraryA$/
section = .huan
type = cryptor
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Huan.2.sg
x-die-loss = number of imports (1), the positions of VirtualAlloc and LoadLibraryA in the first library and .huan being the last section not checked

[Huan [modified]]
pattern = 48 83 EC 28 E8 ?? ?? ?? ?? 48 83 C4 28 E9 ?? ?? ?? ?? CC CC 40 53 48 83 EC ?? 48 8B D9 33 C9 FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B C8 BA ?? ?? ?? ?? 48 83 C4 ?? 5B 48 FF 25 ?? ?? ?? ?? 48 89 4C 24 ??
at = entrypoint
requires = pe32+
import = /!VirtualAlloc$/, /!LoadLibraryA$/
section = !.huan
type = cryptor
options = modified
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Huan.2.sg
x-die-loss = number of imports (1), the positions of VirtualAlloc and LoadLibraryA in the first library and .huan being the last section not checked

; cryptor_Hyperion.2.sg
[Hyperion 1.1 [x86]]
pattern = E8 08 00 00 00 6A 00 FF 15 50 ?? ?? 00 55 89 E5 81 EC 2C 01 00 00 8D 45 D8 89 45 D4
at = entrypoint
type = cryptor
version = 1.1
options = x86
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Hyperion.2.sg

; cryptor_KCryptor.2.sg
[K!Cryptor 0.11]
pattern = 55 8B EC 83 EC ?? 53 56 57 33 DB 53 FF 15 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 89 45 ?? B8 ?? ?? ?? ?? FF 30 BE ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 68 ?? ?? ?? ?? 57 53 FF D0
at = entrypoint
type = cryptor
version = 0.11
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_KCryptor.2.sg

; cryptor_Kryptonit.2.sg
[Kryptonite 0.1-0.2]
pattern = 55 8B EC
at = entrypoint
pattern.2 = 'Krypton'
at.2 = image + 0x93
type = cryptor
version = 0.1-0.2
author = horsicq, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Kryptonit.2.sg

; cryptor_LimeCrypter.2.sg
[LimeCrypter]
pattern = 3C 50 72 69 76 61 74 65 49 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 44 65 74 61 69 6C 73 3E 7B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7D
in = section(#0)
pattern.2 = 00 'System.Security.Cryptography' 00
in.2 = section(#0)
pattern.3 = 00 'System.Collections.Generic' 00
in.3 = section(#0)
pattern.4 = 00 'System.Resources' 00
in.4 = section(#0)
pattern.5 = 00 'System.Reflection' 00
in.5 = section(#0)
requires = dotnet
dotnet_string = <Initialize>o__SiteContainer0, $$method0x6000005-1, Assembly, Rfc2898DeriveBytes, AES_Decrypt, <>p__Site1, !Chainski
type = cryptor
author = KDSS-Research
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_LimeCrypter.2.sg
x-die-loss = the pattern 24 followed by 36 bytes in section 0 is not checked

; cryptor_NativeCryptor_by_DosX.2.sg
[NativeCryptor by DosX]
pattern = '7stgc_hdr' 00
at = overlay
type = cryptor
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_NativeCryptor_by_DosX.2.sg
x-die-loss = number of sections >= 3 not checked

; cryptor_permafrost.2.sg
[permafrost x64 only]
pattern = E8 00 00 00 00 5D 48 8D 9D ?? ?? ?? ?? 48 BE ?? ?? ?? ?? ?? ?? ?? ?? 49 BA 25 23 22 84 E4 9C F2 CB 49 BB B3 01 00 00 00 01 00 00 48 8D BD FB FF FF FF B9 0F 00 00 00
at = entrypoint
requires = pe32+
type = cryptor
version = x64 only
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_permafrost.2.sg

; cryptor_PEUnion.2.sg
[PEUnion 4.0 [RunPE]]
pattern = E8 ?? ?? ?? 00 6A 00 FF 15 A4 ?? ?? 00 C3
at = entrypoint
pattern.2 = '</assembly>'
in.2 = section(.rsrc)
pattern.3 = 00 'Shlwapi.dll' 00
in.3 = section(#1)
requires = native, pe32
section = .rsrc, .idata, .text
import = kernel32.dll!GetProcAddress, kernel32.dll!ExitProcess, kernel32.dll!GetModuleFileNameA, kernel32.dll!GetComputerNameA, kernel32.dll!VirtualAllocExNuma, shlwapi.dll!PathFindFileNameA
type = cryptor
version = 4.0
options = RunPE
author = KDSS-Research, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_PEUnion.2.sg
x-die-loss = number of sections (3) and the virtual sizes of sections 0-2 not checked

[PEUnion 4.0]
pattern = 00 '<>c__DisplayClass1' 00
in = section(#0)
pattern.2 = 00 'LoadLibraryA' 00
in.2 = section(#0)
pattern.3 = 00 'GetProcAddress' 00
in.3 = section(#0)
pattern.4 = 00 'kernel32.dll' 00
in.4 = section(#0)
pattern.5 = 00 'IEnumerable`1' 00
in.5 = section(#0)
pattern.6 = 00 'Func`2' 00
in.6 = section(#0)
pattern.7 = 00 'System.Runtime.InteropServices' 00
in.7 = section(#0)
pattern.8 = 00 'System.Runtime.CompilerServices' 00
in.8 = section(#0)
pattern.9 = 00 'System.Collections.Generic' 00
in.9 = section(#0)
pattern.10 = 00 'System.Reflection' 00
in.10 = section(#0)
pattern.11 = 00 'System.Resources' 00
in.11 = section(#0)
pattern.12 = 00 'System.Core' 00
in.12 = section(#0)
pattern.13 = 00 'System.Linq' 00
in.13 = section(#0)
pattern.14 = 00 'System.IO' 00
in.14 = section(#0)
requires = dotnet
dotnet_string = !BeginInvoke, !EndInvoke
type = cryptor
version = 4.0
author = KDSS-Research, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_PEUnion.2.sg

[PEUnion 4.0 [Invoke]]
pattern = 00 '<>c__DisplayClass1' 00
in = section(#0)
pattern.2 = 00 'LoadLibraryA' 00
in.2 = section(#0)
pattern.3 = 00 'GetProcAddress' 00
in.3 = section(#0)
pattern.4 = 00 'kernel32.dll' 00
in.4 = section(#0)
pattern.5 = 00 'IEnumerable`1' 00
in.5 = section(#0)
pattern.6 = 00 'Func`2' 00
in.6 = section(#0)
pattern.7 = 00 'System.Runtime.InteropServices' 00
in.7 = section(#0)
pattern.8 = 00 'System.Runtime.CompilerServices' 00
in.8 = section(#0)
pattern.9 = 00 'System.Collections.Generic' 00
in.9 = section(#0)
pattern.10 = 00 'System.Reflection' 00
in.10 = section(#0)
pattern.11 = 00 'System.Resources' 00
in.11 = section(#0)
pattern.12 = 00 'System.Core' 00
in.12 = section(#0)
pattern.13 = 00 'System.Linq' 00
in.13 = section(#0)
pattern.14 = 00 'System.IO' 00
in.14 = section(#0)
requires = dotnet
dotnet_string = BeginInvoke
type = cryptor
version = 4.0
options = Invoke
author = KDSS-Research, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_PEUnion.2.sg

[PEUnion 4.0 [Invoke]]
pattern = 00 '<>c__DisplayClass1' 00
in = section(#0)
pattern.2 = 00 'LoadLibraryA' 00
in.2 = section(#0)
pattern.3 = 00 'GetProcAddress' 00
in.3 = section(#0)
pattern.4 = 00 'kernel32.dll' 00
in.4 = section(#0)
pattern.5 = 00 'IEnumerable`1' 00
in.5 = section(#0)
pattern.6 = 00 'Func`2' 00
in.6 = section(#0)
pattern.7 = 00 'System.Runtime.InteropServices' 00
in.7 = section(#0)
pattern.8 = 00 'System.Runtime.CompilerServices' 00
in.8 = section(#0)
pattern.9 = 00 'System.Collections.Generic' 00
in.9 = section(#0)
pattern.10 = 00 'System.Reflection' 00
in.10 = section(#0)
pattern.11 = 00 'System.Resources' 00
in.11 = section(#0)
pattern.12 = 00 'System.Core' 00
in.12 = section(#0)
pattern.13 = 00 'System.Linq' 00
in.13 = section(#0)
pattern.14 = 00 'System.IO' 00
in.14 = section(#0)
requires = dotnet
dotnet_string = EndInvoke, !BeginInvoke
type = cryptor
version = 4.0
options = Invoke
author = KDSS-Research, DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_PEUnion.2.sg

; cryptor_RDG_Tejon_Crypter.2.sg
[RDG Tejon Crypter 0.7]
pattern = 68 50 17 10 01 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 01 00 00 00 00 B3 65 D0 B8 91 9C E1 45 AA 1B EE E0 C8 04 67 EE
at = entrypoint
type = cryptor
version = 0.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RDG_Tejon_Crypter.2.sg

; cryptor_ReXCrypter.2.sg
[ReXCrypter]
dotnet_string = /^ReXStub /
requires = dotnet
type = cryptor
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_ReXCrypter.2.sg
x-die-loss = the assembly name prefix 'ReXStub ' is only checked as an entry of the #Strings heap; version read from file

[ReXCrypter custom stub]
dotnet_string = GetConsoleWindow, LoadInMem
requires = dotnet
type = cryptor
version = custom stub
author = DosX
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_ReXCrypter.2.sg

; cryptor_RPCrypt.2.sg
[RPCrypt 1.?? [modified]]
pattern = 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 1.??
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.??]
pattern = 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 1.??
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.1 [modified]]
pattern = 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 1.1
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.1]
pattern = 8B 04 24 83 E8 4F 68 ?? ?? ?? ?? FF D0
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.3/1.4 [modified]]
pattern = 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 1.3/1.4
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.3/1.4]
pattern = 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 1.3/1.4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.3b [modified]]
pattern = 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 1.3b
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.3b]
pattern = 61 83 EF 4F 60 68 ?? ?? ?? ?? FF D7
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 1.3b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.5 [modified]]
pattern = 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 1.5
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.5]
pattern = 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 1.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.6 [modified]]
pattern = 33 D0 68 ?? ?? ?? ?? FF D2
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 1.6
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.6]
pattern = 33 D0 68 ?? ?? ?? ?? FF D2
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 1.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.6b/1.6c [modified]]
pattern = 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 1.6b/1.6c
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.6b/1.6c]
pattern = 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 1.6b/1.6c
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.6d [modified]]
pattern = 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 1.6d
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 1.6d]
pattern = 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 1.6d
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 2.0 [Hide EP]]
pattern = F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF
at = entrypoint
pattern.2 = E8
at.2 = entrypoint + 0x18
section = /^(\.)?RCryptor$/
type = cryptor
version = 2.0
options = Hide EP
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 2.0 [modified]]
pattern = F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF
at = entrypoint
section = !/^(\.)?RCryptor$/
type = cryptor
version = 2.0
options = modified
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

[RPCrypt 2.0]
pattern = F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF
at = entrypoint
section = /^(\.)?RCryptor$/
type = cryptor
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_RPCrypt.2.sg

; cryptor_Shroud.2.sg
[Shroud 1.0]
pattern = 'SHROUD1.0' AD DE 00 00 EF BE
at = overlay
type = cryptor
version = 1.0
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Shroud.2.sg

; cryptor_Stones_PE_Encryptor.2.sg
[Stone's PE Encryptor 1.0]
pattern = 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 83 EA 0B 89 95
at = entrypoint
pattern.2 = 8D B5
at.2 = entrypoint + 0x23
type = cryptor
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Stones_PE_Encryptor.2.sg

[Stone's PE Encryptor 1.13]
pattern = 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 83 EA 0B 89 95
at = entrypoint
pattern.2 = 01 95
at.2 = entrypoint + 0x23
type = cryptor
version = 1.13
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Stones_PE_Encryptor.2.sg

[Stone's PE Encryptor]
pattern = 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? 83 EA 0B 89 95
at = entrypoint
type = cryptor
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Stones_PE_Encryptor.2.sg

[Stone's PE Encryptor 2.0]
pattern = 53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? FF 95 ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 2B 85
at = entrypoint
type = cryptor
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Stones_PE_Encryptor.2.sg

; cryptor_Virogen_Crypt.2.sg
[Virogen Crypt 0.75]
pattern = 9C 55 E8 $$$$$$$$ E8 00 00 00 00 8B 2C 24 81 ED ?? ?? ?? ?? 83 C4 ?? C3
at = entrypoint
type = cryptor
version = 0.75
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Virogen_Crypt.2.sg

; cryptor_Yodas_Crypter.2.sg
[Yoda's Crypter 1.0]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85
at = entrypoint
type = cryptor
version = 1.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Yodas_Crypter.2.sg

[Yoda's Crypter 1.1]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7
at = entrypoint
pattern.2 = 9E 00
at.2 = entrypoint + 0xE
type = cryptor
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Yodas_Crypter.2.sg

[Yoda's Crypter 1.2]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7
at = entrypoint
pattern.2 = 7B 09
at.2 = entrypoint + 0xE
type = cryptor
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Yodas_Crypter.2.sg

[Yoda's Crypter 1.X]
pattern = 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? 00 00 8D BD ?? ?? ?? ?? 8B F7
at = entrypoint
type = cryptor
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Yodas_Crypter.2.sg

[Yoda's Crypter 1.0b]
pattern = 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED
at = entrypoint
pattern.2 = E8 03 00 00 00 EB 01
at.2 = entrypoint + 0x13
type = cryptor
version = 1.0b
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Yodas_Crypter.2.sg

[Yoda's Crypter 1.3]
pattern = 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED
at = entrypoint
pattern.2 = B9
at.2 = entrypoint + 0x13
type = cryptor
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Yodas_Crypter.2.sg

[Yoda's Crypter 1.3]
pattern = 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60
at = entrypoint
type = cryptor
version = 1.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/cryptor_Yodas_Crypter.2.sg


; ======================================================================
; Joiners
; ======================================================================

; joiner_Celesty_File_Binder.1.sg
[Celesty File Binder 1.0 [static]]
pattern = E8 26 1F 00 00 E9 89 FE FF FF 8B FF 55 8B EC 83 EC 20 8B 45 08 56 57 6A 08 59 BE 0C 92 40 00 8D 7D E0 F3 A5 89 45 F8 8B 45 0C 5F 89 45 FC 5E 85 C0 74
at = entrypoint
type = joiner
version = 1.0
options = static
lang = C++
author = Eliseu Filipi
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_Celesty_File_Binder.1.sg

[Celesty File Binder 1.0 [dynamic]]
pattern = E8 96 04 00 00 E9 63 FD FF FF 8B FF 55 8B EC 81 EC 28 03 00 00 A3 E8 51 40 00 89 0D E4 51 40 00 89 15 E0 51 40 00 89 1D DC 51 40 00 89 35 D8 51 40 00 89 3D D4 51 40 00 66 8C 15 00
at = entrypoint
type = joiner
version = 1.0
options = dynamic
lang = C++
author = Eliseu Filipi
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_Celesty_File_Binder.1.sg

; joiner_ExeSplitter.1.sg
[ExeSplitter 1.2]
pattern = E9 95 02 00 00 64 A1 00 00 00 00 83 38 FF 74 04 8B 00 EB F7 8B 40 04 C3 55 8B EC B8 00 00 00 00 8B 75 08 81 E6 00 00 FF FF
at = entrypoint
type = joiner
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_ExeSplitter.1.sg

[ExeSplitter 1.3 [Split Method]]
pattern = E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? E8 66 FE FF FF 55 50 8D 9D ?? ?? ?? ?? 53 8D 9D
at = entrypoint
type = joiner
version = 1.3
options = Split Method
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_ExeSplitter.1.sg

[ExeSplitter 1.3 [Split Method]]
pattern = E9 FE 01 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 76 63 45 72 30 31 31 2E 74 6D 70 00
at = entrypoint
type = joiner
version = 1.3
options = Split Method
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_ExeSplitter.1.sg

[ExeSplitter 1.3 [Split+Crypt Method]]
pattern = E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 80 30 66 40 E2 FA 8F 98 67 66 66
at = entrypoint
type = joiner
version = 1.3
options = Split+Crypt Method
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_ExeSplitter.1.sg

; joiner_FreeJoiner.1.sg
[FreeJoiner 1.5.1]
pattern = 90 87 FF 90 90 B9 2B 00 00 00 BA ?? ?? ?? ?? 83 C2 03 90 87 FF 90 90 B9 04 00 00 00 90 87 FF 90 33 C9 C7 05
at = entrypoint
type = joiner
version = 1.5.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner 1.5.2 Stub engine 1.6]
pattern = E8 46 FD FF FF 50 E8 0C 00 00 00 FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = 1.5.2 Stub engine 1.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner 1.5.3 Stub engine 1.7]
pattern = E8 33 FD FF FF 50 E8 0D 00 00 00 CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = 1.5.3 Stub engine 1.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner 1.5.3 Stub engine 1.7.1]
pattern = 86 D6 90 86 F2 B9 93 60 08 FE 90 86 D6 90 86 F2 B9 9D 13 45 01 86 D6 90 86 F2 81 C2 93 60 08 FE 33 C9 B9 30 74 4D
at = entrypoint
type = joiner
version = 1.5.3 Stub engine 1.7.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner Small build 014/015]
pattern = 55 8B EC 83 C4 F0 86 FF 68 00 01 00 00 68 ?? ?? ?? ?? 6A 00 E8 F3 01 00 00 8A C0 6A 00 68 80 00 00 00 6A 03 6A 00
at = entrypoint
type = joiner
version = Small build 014/015
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner Small build 014-020]
pattern = E8 ?? ?? FF FF 6A 00 E8 0D 00 00 00 CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = Small build 014-020
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner Small build 017]
pattern = 55 8B EC 83 C4 F0 86 FF 86 DB 86 FF 68 00 01 00 00 68 ?? ?? ?? ?? 6A 00 E8 FF 01 00 00 8A E4 6A 00 68 80 00 00 00 6A 03
at = entrypoint
type = joiner
version = Small build 017
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner Small build 023]
pattern = E8 E1 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = Small build 023
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner Small build 029]
pattern = 50 32 C4 8A C3 58 E8 DE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = Small build 029
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner Small build 031/032]
pattern = 50 32 ?? 66 8B C3 58 E8 ?? FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = Small build 031/032
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner Small build 033]
pattern = 50 66 33 C3 66 8B C1 58 E8 AC FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = Small build 033
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

[FreeJoiner Small build 035]
pattern = 51 33 CB 86 C9 59 E8 9E FD FF FF 66 87 DB 6A 00 E8 0C 00 00 00 FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = Small build 035
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_FreeJoiner.1.sg

; joiner_inPEct.1.sg
[inPEct 1.1]
pattern = E8 00 00 00 00 5D 55 83 C5 20 8B F5 8B FE B9 ?? ?? ?? 00 BA ?? ?? ?? ?? AD 8B D8 33 C2 C1 C2 07 03 D3 AB E2 F3
at = entrypoint
type = joiner
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_inPEct.1.sg

; joiner_MicroJoiner.1.sg
[MicroJoiner 1.1]
pattern = BE ?? ?? ?? ?? BB ?? ?? ?? ?? 33 ED 83 EE 04 39 2E 74 11
at = entrypoint
type = joiner
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_MicroJoiner.1.sg

[MicroJoiner 1.5]
pattern = BF ?? ?? ?? ?? 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF
at = entrypoint
type = joiner
version = 1.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_MicroJoiner.1.sg

[MicroJoiner 1.6]
pattern = 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B
at = entrypoint
type = joiner
version = 1.6
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_MicroJoiner.1.sg

[MicroJoiner 1.7]
pattern = BF ?? ?? ?? ?? 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00
at = entrypoint
type = joiner
version = 1.7
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_MicroJoiner.1.sg

; joiner_N-Joiner.1.sg
[N-Joiner 0.1]
pattern = 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A 00 E8 14 00 00 00 6A 00 E8 13 00 00 00 CC FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
version = 0.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_N-Joiner.1.sg

; joiner_OxiJoiner.2.sg
[OxiJoiner]
pattern = E8 5C 00 00 00 A3 0B 30 40 00 6A 00 E8 68 00 00 00 A3 13 30 40 00 E8 6A 00 00 00 A3 70 3C 40 00 6A 0A FF 35 0B 30 40 00 6A 00 FF 35 13 30 40 00 E8 EA F4 FF FF 6A 00 E8 13 00 00 00 CC FF 25 7C 20 40 00 FF 25 08 20 40 00 FF 25 0C 20 40 00 FF
at = entrypoint
pattern.2 = 'PAPADDING'
in.2 = section(.rsrc)
type = joiner
author = KDSS-Research
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_OxiJoiner.2.sg

; joiner_RJoiner.1.sg
[RJoiner 1.2]
pattern = 55 8B EC 81 EC 0C 02 00 00 8D 85 F4 FD FF FF 56 50 68 04 01 00 00 FF 15
at = entrypoint
type = joiner
version = 1.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_RJoiner.1.sg

[RJoiner 1.2a]
pattern = 55 8B EC 81 EC 0C 01 00 00 8D 85 F4 FE FF FF 56 50 68 04 01 00 00 FF 15
at = entrypoint
type = joiner
version = 1.2a
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_RJoiner.1.sg

[RJoiner]
pattern = E8 03 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 ?? ?? ?? ?? FF 25 ?? ?? ?? ?? FF 25
at = entrypoint
type = joiner
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_RJoiner.1.sg

; joiner_SFXRun.1.sg
[SFXRun 1.1 [1999 by Sergey Sorokin]]
pattern = FF 15 ?? ?? ?? ?? 80 38 ?? 75 ?? 8A 48 ?? 40 80 F9 ?? 74 ?? 84 C9 75 ?? EB ?? 40 8A 08 80 F9 ?? 74 ?? 80 F9 ?? 74
at = entrypoint
type = joiner
version = 1.1
options = 1999 by Sergey Sorokin
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/joiner_SFXRun.1.sg


; ======================================================================
; Installers
; ======================================================================

; installer_ACCAStore.1.sg
[ACCAStore 1.9.4.0]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1
at = entrypoint
resource = */METRO_INFO
type = installer
version = 1.9.4.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_ACCAStore.1.sg

; installer_Acronis_installer.1.sg
[Acronis installer [ZIP]]
pattern = 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = installer
options = ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Acronis_installer.1.sg

[Acronis installer [ZIP]]
pattern = 6A ?? 68 ?? ?? ?? ?? E8 $$$$$$$$ 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 8B 44 24 ?? 89 6C 24 ?? 8D 6C 24 ?? 2B E0 53 56 57 8B 45 ?? 89 65 ?? 50 8B 45 ?? C7
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = installer
options = ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Acronis_installer.1.sg

[Acronis installer [ZIP]]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? 3B C7 BB ?? ?? ?? ?? 74
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = installer
options = ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Acronis_installer.1.sg

[Acronis installer [ZIP]]
pattern = 55 8B EC 8B 45 ?? 8B 4D ?? 8B 55 ?? 83 F8 ?? 75 ?? 89 15 ?? ?? ?? ?? 89 4D ?? 89 45 ?? 89 55 ?? 5D E9
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = installer
options = ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Acronis_installer.1.sg

[Acronis installer [ZIP]]
pattern = 8B 44 24 ?? 83 F8 ?? 8B 4C 24 ?? 8B 54 24 ?? 75 ?? 89 15 ?? ?? ?? ?? 89 4C 24 ?? 89 44 24 ?? 89 54 24 ?? E9
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = installer
options = ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Acronis_installer.1.sg

[Acronis installer [ZIP]]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? 83 65 ?? ?? 83 65 ?? ?? A1 ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = installer
options = ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Acronis_installer.1.sg

; installer_Actual_Installer.1.sg
[Actual Installer 1.0.0.0]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3
at = entrypoint
pattern.2 = ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 'MSCF' 00
at.2 = overlay
type = installer
version = 1.0.0.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Actual_Installer.1.sg

; installer_Adobe_FlashPlayer_downloader.1.sg
[Adobe FlashPlayer downloader 2.0 [PECompact]]
pattern = B8 ?? ?? ?? 00 50 64 FF 35 00
at = entrypoint
requires = overlay
version_info.InternalName = Adobe Download Manager
type = installer
version = 2.0
options = PECompact
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Adobe_FlashPlayer_downloader.1.sg

; installer_Adobe_installers.1.sg
[Adobe Reader Installer [7zip sfx]]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
pattern.2 = '7z' BC AF 27 1C
at.2 = resource(ARCHIVE_7Z)
type = installer
options = 7zip sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Adobe_installers.1.sg

[Adobe SVG Installer [gzip]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = '^OPT'
at.2 = overlay
pattern.3 = '^ARC' 1F 8B 08
in.3 = overlay[0-0x50]
type = installer
options = gzip
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Adobe_installers.1.sg

[Adobe WebInstaller [7zip sfx]]
pattern = E8 $$$$$$$$ 8B 0D ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B CF 74 ?? 85 CE 75 ?? E8 ?? ?? ?? ?? 8B C8
at = entrypoint
pattern.2 = '7z' BC AF 27 1C
at.2 = resource
type = installer
options = 7zip sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Adobe_installers.1.sg
x-die-loss = DIE checks only the first resource for the 7z signature

; installer_Advanced_installer.1.sg
[Advanced Installer]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
pattern.2 = 2F 30 EE 1F 5E 4E E5 1E
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer]
pattern = 55 8B EC 83 EC ?? 56 57 FF 15 ?? ?? ?? ?? 8B F0 85 F6 75 ?? 6A ?? EB ?? E8 ?? ?? ?? ?? 8A 06 3C ?? 8B 3D ?? ?? ?? ?? 75 ?? 56 FF D7
at = entrypoint
pattern.2 = 2F 30 EE 1F 5E 4E E5 1E
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer]
pattern = E8 $$$$$$$$ 8B 0D ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B CF 74 ?? 85 CE 75 ?? E8 ?? ?? ?? ?? 8B C8 3B CF 75 ?? B9 ?? ?? ?? ?? EB
at = entrypoint
pattern.2 = 2F 30 EE 1F 5E 4E E5 1E
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer]
pattern = 55 8B EC 83 EC ?? 56 57 FF 15 ?? ?? ?? ?? 8B F0 85 F6 75 ?? 6A ?? EB ?? E8 ?? ?? ?? ?? 8A 06 3C ?? 8B 3D ?? ?? ?? ?? 75 ?? 56 FF D7
at = entrypoint
pattern.2 = D0 CF 11 E0 A1 B1 1A E1
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
pattern.2 = D0 CF 11 E0 A1 B1 1A E1
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer]
pattern = 55 8B EC 83 7D ?? ?? 75 ?? E8 $$$$$$$$ 8B 0D ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B CF 74
at = entrypoint
pattern.2 = 'ADVINSTSFX'
in.2 = eof[0x50]
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? 83 65 ?? ?? 83 65 ?? ?? A1 ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7
at = entrypoint
pattern.2 = 'ADVINSTSFX'
in.2 = eof[0x50]
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer 12.6.1]
pattern = 55 8B EC 83 7D ?? ?? 75 ?? E8 ?? ?? ?? ?? FF 75 ?? FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 5D
at = entrypoint
pattern.2 = 'ADVINSTSFX'
in.2 = eof[0x50]
type = installer
version = 12.6.1
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer]
pattern = E8 $$$$$$$$ 8B 0D ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B CF 74 ?? 85 CE 75 ?? E8 ?? ?? ?? ?? 8B C8
at = entrypoint
pattern.2 = w'[GeneralOptions]'
at.2 = overlay + 0x2
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

[Advanced Installer 16.3.0.0]
pattern = 55 8B EC 83 7D ?? ?? 75 ?? E8 ?? ?? ?? ?? FF 75 ?? FF 75 ?? FF 75 ?? E8 ?? ?? ?? ?? 83 C4 ?? 5D
at = entrypoint
pattern.2 = C8 85 'CP' D8 E3
at.2 = overlay
type = installer
version = 16.3.0.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Advanced_installer.1.sg

; installer_Adveractive.1.sg
[Adveractive]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = '10JP'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Adveractive.1.sg

; installer_Aeco_installer.1.sg
[Aeco Systems installer 1.0]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 83 EC ?? 89 01
at = entrypoint
pattern.2 = 'EWETAR DATA FILE!! VER 1.00 <<<>>>'
at.2 = overlay
type = installer
version = 1.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Aeco_installer.1.sg

; installer_Alchemy_Mindworks_installer.1.sg
[Alchemy Mindworks installer]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF
at = entrypoint
pattern.2 = 50 4B 03 04
at.2 = resource
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Alchemy_Mindworks_installer.1.sg

; installer_AOLSetup.1.sg
[AOLSetup by America Online]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57
at = entrypoint
pattern.2 = 'RS'
at.2 = overlay
type = installer
version = by America Online
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_AOLSetup.1.sg

; installer_Astrum.1.sg
[Astrum]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'AstrumInstallWizard'
in.2 = resource[0-0x140]
requires = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Astrum.1.sg
x-die-loss = resource type (DIE Type 77) of the searched resource not checked

; installer_Autodesk_Self-Extract.1.sg
[Autodesk Self-Extract]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7 74 ?? 85 C6 74 ?? F7 D0
at = entrypoint
pattern.2 = '00000000000000BD00000000000000010000000000000001'
at.2 = overlay + 0x19A0
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Autodesk_Self-Extract.1.sg

; installer_AutoPlay_Media_Studio.1.sg
[AutoPlay Media Studio]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74 ?? 85 C3 74 ?? F7 D0 A3 ?? ?? ?? ?? EB
at = entrypoint
pattern.2 = 0B 0B AF AF 0B 0B A4
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_AutoPlay_Media_Studio.1.sg
x-die-loss = version read from file (file version, DIE falls back to 8.X)

[AutoPlay Media Studio]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15 ?? ?? ?? ?? 33 D2 8A D4 89 15 ?? ?? ?? ?? 8B C8
at = entrypoint
pattern.2 = 0B 0B AF AF 0B 0B A4
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_AutoPlay_Media_Studio.1.sg
x-die-loss = version read from file (file version, DIE falls back to 7.5.X)

; installer_AutorunProEnterprise.1.sg
[Autorun Pro Enterprise]
pattern = '9AutoRunObjects'
in = section(.rsrc)
section = CODE
type = installer
author = KDSS-Research
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_AutorunProEnterprise.1.sg

; installer_AutorunProEnterpriseII.1.sg
[Autorun Pro Enterprise II]
pattern = 'TAutoRunProjectX'
in = section(CODE)
pattern.2 = 'AutoRunObjects'
in.2 = section(.rsrc)
type = installer
author = KDSS-Research
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_AutorunProEnterpriseII.1.sg

; installer_BitRock_Installer.1.sg
[BitRock Installer]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 ?? 46 46 53 68
at = entrypoint
pattern.2 = ?? ?? ?? ?? '.eh_frame' 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_BitRock_Installer.1.sg

[BitRock Installer]
pattern = 83 EC ?? C7 04 24 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 74 26 ?? 8D BC 27 ?? ?? ?? ?? A1 ?? ?? ?? ?? FF E0
at = entrypoint
pattern.2 = ?? ?? ?? ?? '.eh_frame' 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_BitRock_Installer.1.sg

[BitRock Installer]
pattern = 'BitRock'
in = manifest
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_BitRock_Installer.1.sg

; installer_Bytessence_Install_Maker.1.sg
[Bytessence Install Maker 5.40]
pattern = 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68
at = entrypoint
pattern.2 = '$_BIM_CONFIG_START_$'
at.2 = overlay
type = installer
version = 5.40
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Bytessence_Install_Maker.1.sg

[Bytessence Install Maker 5.40 [x64]]
pattern = 48 83 EC ?? 49 C7 C0 ?? ?? ?? ?? 48 31 D2 48 B9 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 31 C9 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 4D 31 C0 48 C7 C2 ?? ?? ?? ?? 48 31 C9 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 B8
at = entrypoint
pattern.2 = '$_BIM_CONFIG_START_$'
at.2 = overlay
type = installer
version = 5.40
options = x64
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Bytessence_Install_Maker.1.sg

; installer_Calibre_installer.1.sg
[Calibre Portable Installer [.LZ Archive]]
resource = */EXTRA
version_info.ProductName = calibre
type = installer
options = .LZ Archive
author = horsicq, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Calibre_installer.1.sg
x-die-loss = .rsrc raw size > 0x6000000 not checked; version read from file

; installer_Chaos_Software_installer.1.sg
[Chaos Software installer]
pattern = 48 83 EC ?? E8 $$$$$$$$ 48 89 5C 24 ?? 57 48 83 EC ?? 48 8B ?? ?? ?? ?? ?? 48 83 64 24 ?? ?? 48 BF ?? ?? ?? ?? ?? ?? ?? ?? 48 3B C7 74
at = entrypoint
pattern.2 = 27 63 27 63 12 26 09 75 13 18 01 78
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Chaos_Software_installer.1.sg

; installer_ClickTeam.1.sg
[ClickTeam]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'wwgT)'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_ClickTeam.1.sg

[ClickTeam]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = ?? 12 01 00 ?? ?? 00 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_ClickTeam.1.sg

; installer_CNetX.1.sg
[CNetX [modified ZIP]]
pattern = 83 EC ?? 56 FF 15 ?? ?? ?? ?? 8B F0 8A 06 3C ?? 75 ?? 8A 46 ?? 46 84 C0 74 ?? 3C ?? 75
at = entrypoint
pattern.2 = 78 4B 03 04
at.2 = resource
type = installer
options = modified ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_CNetX.1.sg

; installer_Codegear_Installer.1.sg
[Codegear Installer]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD ?? EB $$ 8B 1E 83 EE ?? 11 DB 72 ?? B8 ?? ?? ?? ?? 01 DB 75 ?? 8B 1E
at = entrypoint
pattern.2 = ?? ?? ?? ?? 'GRCSETUPINFORMATION'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Codegear_Installer.1.sg

; installer_CreateInstall.1.sg
[CreateInstall]
pattern = 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 45 08 FF 15 ?? ?? ?? ?? 85 C0 74 27 6A 00 A1 ?? ?? ?? ?? 50 FF 15
at = entrypoint
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_CreateInstall.1.sg

[CreateInstall 2003.3.5]
pattern = 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 ?? ?? ?? ?? 8B F0 FF 15 ?? ?? ?? ?? 3D B7 00 00 00 75 0F 56 FF 15
at = entrypoint
pattern.2 = 02 06 0A 04 05 FD 59
at.2 = overlay
type = installer
version = 2003.3.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_CreateInstall.1.sg

[CreateInstall]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'aWAW'
at.2 = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_CreateInstall.1.sg

[CreateInstall]
pattern = 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 0B C0 74 ?? E8
at = entrypoint
pattern.2 = 'aWAW'
at.2 = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_CreateInstall.1.sg

; installer_CrypKey_Installer.1.sg
[CrypKey]
pattern = E8 $$$$$$$$ 56 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8
at = entrypoint
pattern.2 = 'CK16'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_CrypKey_Installer.1.sg

; installer_CSDD_installer.1.sg
[CSDD's 1.1]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 ?? 53 56 57
at = entrypoint
pattern.2 = EC 7C 7F 7C
at.2 = resource(*/1)
type = installer
version = 1.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_CSDD_installer.1.sg
x-die-loss = DIE checks only the first resource (named 1)

; installer_CZ_installer.1.sg
[CZ installer]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3
at = entrypoint
resource = */CZ_STORAGE
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_CZ_installer.1.sg

; installer_DeployMaster.1.sg
[DeployMaster 2.8.0]
pattern = 55 8B EC 81 C4 ?? ?? ?? ?? 53 33 C0 89 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30
at = entrypoint
pattern.2 = 'BZh91'
at.2 = overlay
type = installer
version = 2.8.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_DeployMaster.1.sg

; installer_distutils.1.sg
[distutils 2.6]
pattern = E8 ?? ?? ?? ?? E9 $$$$$$$$ 6A 58 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 F6 89 75 ?? 8D 45 ?? 50 FF 15 ?? ?? ?? ?? 6A ?? 5F 89 7D ?? B8 ?? ?? ?? ?? 66 39 05 ?? ?? ?? ?? 75
at = entrypoint
pattern.2 = '[metadata]'
at.2 = overlay
type = installer
version = 2.6
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_distutils.1.sg

[distutils 2.5]
pattern = 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 DB 89 5D ?? 53 8B 3D ?? ?? ?? ?? FF D7 66 ?? ?? ?? ?? 75 ?? 8B 48 ?? 03 C8 81 39 ?? ?? ?? ?? 75 ?? 0F B7
at = entrypoint
pattern.2 = '[metadata]'
at.2 = overlay
type = installer
version = 2.5
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_distutils.1.sg

; installer_Eschalon_installer.1.sg
[Eschalon Installer]
pattern = 55 8B EC 81 C4 ?? ?? ?? ?? 53 56 57 33 C0 89 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? E8 $$$$$$$$ E8 $$$$$$$$ 31 D2 8D
at = entrypoint
pattern.2 = 'EPSF'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Eschalon_installer.1.sg
x-die-loss = version read from file

; installer_Excelsior_Installer.1.sg
[Excelsior Installer]
pattern = 83 EC ?? 53 55 56 57 E8 ?? ?? ?? ?? 6A ?? 5B 39 1D ?? ?? ?? ?? 8B F3 7E ?? 8B 3D ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B ?? ?? 8A 08
at = entrypoint
pattern.2 = 'ExcelsiorII1'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Excelsior_Installer.1.sg

; installer_FDM_Installer.1.sg
[FDM Installer 1.0]
pattern = 55 8B EC 6A FF 68 20 71 40 00 68 2C 36 40 00
at = entrypoint
pattern.2 = '###FDMDATA###'
at.2 = overlay
type = installer
version = 1.0
author = A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_FDM_Installer.1.sg

[FDM Installer]
pattern = '###FDMDATA###'
at = overlay
type = installer
author = A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_FDM_Installer.1.sg

; installer_Gentee_Installer.1.sg
[Gentee Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 8D 85 ?? ?? ?? ?? 56 33 DB 57 8D 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 5D ?? 51 89 45 ?? 53 FF 15
at = entrypoint
pattern.2 = 'GEA'
in.2 = overlay[0-0x80]
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Gentee_Installer.1.sg

[Gentee Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 8D 85 ?? ?? ?? ?? 56 33 DB 57 8D 8D ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 5D ?? 51 89 45 ?? 53 FF 15
at = entrypoint
pattern.2 = 'GEA'
at.2 = resource(*/SETUP_TEMP)
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Gentee_Installer.1.sg

[Gentee Installer]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? 33 DB 89 5D ?? 6A ?? FF 15
at = entrypoint
pattern.2 = 'GEA'
in.2 = overlay[0-0x80]
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Gentee_Installer.1.sg

[Gentee Installer]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? 33 DB 89 5D ?? 6A ?? FF 15
at = entrypoint
pattern.2 = 'gentee'
in.2 = section(.data)[0-0x80]
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Gentee_Installer.1.sg

[Gentee Installer]
pattern = 81 EC ?? ?? ?? ?? 53 56 57 55 68 ?? ?? ?? ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 8B F0 FF 15 ?? ?? ?? ?? 3D ?? ?? ?? ?? 75 ?? 56
at = entrypoint
pattern.2 = 'OWS9G1'
at.2 = overlay + 0xB
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Gentee_Installer.1.sg

[Gentee Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 6A ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 6A ?? A1 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F0 6A ?? 56 FF 15
at = entrypoint
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Gentee_Installer.1.sg

; installer_Ghost_Installer.1.sg
[Ghost Installer 1.0.0.0 [xored MSCF, mask: 8D]]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 ?? ?? ?? ?? ?? ?? ?? ?? 57 83 CD ?? EB
at = entrypoint
pattern.2 = C0 DE CE CB 8D 8D 8D 8D
at.2 = overlay
type = installer
version = 1.0.0.0
options = xored MSCF, mask: 8D
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Ghost_Installer.1.sg

; installer_GPInstall.1.sg
[GPInstall [SPIS LH5]]
pattern = 55 8B EC 83 C4 ?? 53 33 C0 89 45 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 BA ?? ?? ?? ?? 33 C0 E8
at = entrypoint
pattern.2 = ?? ?? ?? ?? 'SPIS' 1A 'LH5'
at.2 = overlay
type = installer
options = SPIS LH5
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_GPInstall.1.sg

[GPInstall [SPIS LH5]]
pattern = 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 BA ?? ?? ?? ?? 33 C0 E8
at = entrypoint
pattern.2 = ?? ?? ?? ?? 'SPIS' 1A 'LH5'
at.2 = overlay
type = installer
options = SPIS LH5
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_GPInstall.1.sg

[GPInstall [SPIS LH5]]
pattern = 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 BA ?? ?? ?? ?? 33 C0
at = entrypoint
pattern.2 = ?? ?? ?? ?? 'SPIS' 1A 'LH5'
at.2 = overlay
type = installer
options = SPIS LH5
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_GPInstall.1.sg

; installer_Gremlin_Patcher.1.sg
[Gremlin Software Patcher/Updater [SZDD]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'SZDD'
in.2 = resource(FILES_MAIN)[0-0x100]
type = installer
options = SZDD
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Gremlin_Patcher.1.sg

; installer_I-D_Media_installer.1.sg
[I-D Media installer 1.0.0.13]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 89 65
at = entrypoint
pattern.2 = 'XXataDfOnigeB'
at.2 = overlay
type = installer
version = 1.0.0.13
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_I-D_Media_installer.1.sg

; installer_IDM_Installer.1.sg
[Internet Download Manager Installer [zlib]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? 33 DB 89 5D ?? 6A ?? FF 15
at = entrypoint
pattern.2 = 2A 33 00 00 DA 05 00 00 FE C1 CD 66 6E BC CF 01 FE C1 CD 66 6E BC CF 01 00 ?? ?? ?? ?? ?? ?? ?? 78 DA
at.2 = overlay
type = installer
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_IDM_Installer.1.sg

; installer_Inno_Setup_Module.1.sg
[Inno Setup Module]
pattern = 'zlb' 1A
at = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = version and unicode/ANSI option read from file

[Inno Setup Module]
pattern = 'idska32' 1A
at = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = version and unicode/ANSI option read from file

[Inno Setup Module [uninstall]]
pattern = 'InUn'
at = image + 0x30
pattern.2 = 'Inno Setup Messages'
in.2 = overlay[0-0x100]
type = installer
options = uninstall
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = version and unicode/ANSI option read from file

[Inno Setup Module [uninstall]]
pattern = 'InUn'
at = image + 0x30
pattern.2 = 'Inno Setup version'
in.2 = section(#0)
type = installer
options = uninstall
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = version and unicode/ANSI option read from file

[Inno Setup Module [uninstall]]
pattern = 'InUn'
at = image + 0x30
pattern.2 = 'Inno Setup Setup Data'
in.2 = section(DATA)[0-0x4000]
type = installer
options = uninstall
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = DATA section raw size < 0x4000 not checked; version and unicode/ANSI option read from file

[Inno Setup Module [uninstall]]
pattern = 'InUn'
at = image + 0x30
pattern.2 = 'Inno Setup Setup Data'
in.2 = section(.data)[0-0x4000]
type = installer
options = uninstall
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = .data section raw size < 0x4000 not checked; version and unicode/ANSI option read from file

[Inno Setup Module [uninstall]]
pattern = 'InUn'
at = image + 0x30
pattern.2 = 'i1.' ?? ?? ?? ?? ?? ?? '32' 1A
in.2 = section(DATA)[0-0x4000]
type = installer
options = uninstall
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = DATA section raw size < 0x4000 not checked; version read from file

[Inno Setup Module [uninstall]]
pattern = 'InUn'
at = image + 0x30
pattern.2 = 'i1.' ?? ?? ?? ?? ?? ?? '32' 1A
in.2 = section(.data)[0-0x4000]
type = installer
options = uninstall
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = .data section raw size < 0x4000 not checked; version read from file

[Inno Setup Module [uninstall]]
pattern = 'Inno Setup Messages'
at = overlay
type = installer
options = uninstall
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = version and unicode/ANSI option read from file

[Inno Setup Module]
pattern = 'Inno Setup Setup Data'
at = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg
x-die-loss = version and unicode/ANSI option read from file

[Inno Setup Module [zlib]]
pattern = 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 ?? 89 45
at = entrypoint
pattern.2 = 78 DA
at.2 = overlay
type = installer
options = zlib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg

[Inno Setup Module [zlib]]
pattern = 55 8B EC 83 C4 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8
at = entrypoint
pattern.2 = 78 DA
at.2 = overlay
type = installer
options = zlib
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg

[Inno Setup Module [with stub]]
pattern = 'Inno'
at = overlay + 0x34
type = installer
options = with stub
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg

[Inno Setup Module]
requires = dotnet
version_info.Comments = "This installation was built with Inno Setup."
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Inno_Setup_Module.1.sg

; installer_Instalit.1.sg
[Instalit 7.10.11, x32]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
resource = DLLFILE
type = installer
version = 7.10.11, x32
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Instalit.1.sg

; installer_Install4j_installer.1.sg
[Install4j Installer]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74
at = entrypoint
pattern.2 = D5 13 E4 E8 01 00 00 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Install4j_installer.1.sg

[Install4j Installer]
pattern = 48 83 EC ?? E8 $$$$$$$$ 48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 05 ?? ?? ?? ?? 48 83 64 24 ?? ?? 48 BF ?? ?? ?? ?? ?? ?? ?? ?? 48 3B C7 74
at = entrypoint
pattern.2 = D5 13 E4 E8 01 00 00 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Install4j_installer.1.sg

; installer_Install_Factory.1.sg
[Install Factory]
pattern = 55 89 E5 53 83 EC ?? 55 B8 ?? ?? ?? ?? 50 50 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 E4 ?? 68
at = entrypoint
pattern.2 = A7 87 08 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Install_Factory.1.sg

; installer_InstallAnywhere.1.sg
[InstallAnywhere 6.1]
pattern = 60 BE ?? ?? ?? ?? 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07
at = entrypoint
type = installer
version = 6.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallAnywhere.1.sg

[InstallAnywhere [zip]]
pattern = 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D
at = entrypoint
pattern.2 = 5B 3E
at.2 = overlay
pattern.3 = 'PK' 03 04
in.3 = overlay[0-0x500]
type = installer
options = zip
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallAnywhere.1.sg

[InstallAnywhere [zip]]
pattern = 48 83 EC ?? E8 $$$$$$$$ 48 89 5C 24 ?? 55 48 8B EC 48 83 EC ?? 48 8B ?? ?? ?? ?? ?? 48 83 65 ?? ?? 48 BB ?? ?? ?? ?? ?? ?? ?? ?? 48 3B C3 75
at = entrypoint
pattern.2 = 5B 3E
at.2 = overlay
pattern.3 = 'PK' 03 04
in.3 = overlay[0-0x500]
type = installer
options = zip
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallAnywhere.1.sg

[InstallAnywhere [zip]]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7 74 ?? 85 C6 74 ?? F7
at = entrypoint
pattern.2 = 5B 3E
at.2 = overlay
pattern.3 = 'PK' 03 04
in.3 = overlay[0-0x500]
type = installer
options = zip
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallAnywhere.1.sg

; installer_InstallAware.1.sg
[InstallAware]
version_info.Comments = This installation was built with InstallAware: http://www.installaware.com
type = installer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallAware.1.sg

; installer_InstallShield.1.sg
[InstallShield 3.X]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 13 5D 65 8C
in.2 = overlay[0xC-0x10C]
type = installer
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg
x-die-loss = magic searched in a window, DIE reads its offset from the first overlay byte

[InstallShield 2.X]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'SZDD'
at.2 = resource(IS2)
requires = !overlay
type = installer
version = 2.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
section = _cabinet
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield Java Edition]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'InstallShield Native Installer'
in.2 = overlay[0-0x100]
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield Java Edition 3.X]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'setup.class'
in.2 = overlay[0-0x100]
type = installer
version = 3.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield]
pattern = 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 85 F6 75 08 6A FF FF 15 ?? ?? ?? ?? 8A 06 57 8B 3D
at = entrypoint
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield 19.X]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15 ?? ?? ?? ?? 33 D2
at = entrypoint
pattern.2 = 'ISc('
in.2 = overlay[0-0x2000]
type = installer
version = 19.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield 18.X]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74 ?? 85 C3 74 ?? F7
at = entrypoint
pattern.2 = 'ISSetupStream'
in.2 = overlay[0-0x2000]
type = installer
version = 18.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield 25.X]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7
at = entrypoint
pattern.2 = 'ISc('
in.2 = overlay[0-0x10000]
type = installer
version = 25.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield 29.X]
pattern = E8 $$$$$$$$ 8B 0D ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B CF 74 ?? 85 CE 75 ?? E8 ?? ?? ?? ?? 8B C8
at = entrypoint
pattern.2 = 'ISSetupStream'
at.2 = overlay
type = installer
version = 29.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield 19.X]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7 74 ?? 85 C6 74 ?? F7
at = entrypoint
pattern.2 = 'ISSetupStream'
at.2 = overlay
type = installer
version = 19.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

[InstallShield]
version_info.ProductName = /^InstallShield/
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg
x-die-loss = version read from file

[InstallShield]
version_info.CompanyName = InstallShield Software Corporation
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg
x-die-loss = version read from file

[InstallShield]
pattern = 'InstallShield'
in = manifest
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallShield.1.sg

; installer_InstallUs.1.sg
[InstallUs [SPIS LZH]]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 BA ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 8B 15
at = entrypoint
pattern.2 = 'SPIS' 1A 'LZH'
in.2 = overlay[0-0x1000]
type = installer
options = SPIS LZH
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_InstallUs.1.sg

; installer_INTENIUM.1.sg
[INTENIUM]
pattern = 'stgc_hdr'
at = overlay
type = installer
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_INTENIUM.1.sg
x-die-loss = version read from file

; installer_LucasArts_Update_Installer.1.sg
[LucasArts Update Installer]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = '1CNT'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_LucasArts_Update_Installer.1.sg

; installer_Microsoft_Class_Installer.1.sg
[Microsoft Class Installer for Java 4.X [zip]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = resource(ZIP)
type = installer
version = 4.X
options = zip
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Microsoft_Class_Installer.1.sg

; installer_Microsoft_Compound-based_installer.1.sg
[Microsoft Compound-based installer (MSI)]
pattern = 55 8B EC B9 ?? ?? ?? ?? 6A ?? 6A ?? 49 75 ?? 51 53 56 57 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 33 C0 55 68
at = entrypoint
pattern.2 = D0 CF 11 E0 A1 B1 1A E1
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Microsoft_Compound-based_installer.1.sg

; installer_Miktex_Installer.1.sg
[MiKTeX Installer [tar]]
pattern = E9 $$$$$$$$ 48 83 EC ?? E8 $$$$$$$$ E9 $$$$$$$$ 48 89 5C 24 ?? 55 48 8B EC 48 83 EC ?? 48 8B 05 ?? ?? ?? ?? 48 BB ?? ?? ?? ?? ?? ?? ?? ?? 48 3B C3 75 ?? 48 83 65
at = entrypoint
pattern.2 = 'TARTARTARTARTART'
at.2 = overlay
type = installer
options = tar
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Miktex_Installer.1.sg

; installer_Mioplanet_installer.1.sg
[Mioplanet installer]
pattern = EB $$ A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 52 6A ?? E8 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? 5A E8
at = entrypoint
pattern.2 = '[(*|*)]MZ'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Mioplanet_installer.1.sg

; installer_Multimedia_Fusion_Installer.1.sg
[Multimedia Fusion Installer]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65
at = entrypoint
pattern.2 = 'wwwwI' 87 47 12
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Multimedia_Fusion_Installer.1.sg

; installer_Myriad_Install.1.sg
[Myriad Install]
pattern = 55 89 E5 53 56 83 EC ?? 55 B8 ?? ?? ?? ?? 50 50 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8
at = entrypoint
pattern.2 = 01 00 62 15
in.2 = overlay[0-0x100]
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Myriad_Install.1.sg

; installer_NOS_Installer.1.sg
[NOS Installer]
pattern = 50 E8 00 00 00 00 5B 81 EB ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B D9 8B F3 81 EB ?? ?? ?? ?? 8B FB 81 EB ?? ?? ?? ?? 57 51 56 E8 ?? ?? ?? ?? 83 C4 ?? 8B AB ?? ?? ?? ?? 8D 2C 2B 4D 8A 4D ?? 80 F9 ?? 74 ?? 83 ED ?? 8B D3 2B 53
at = entrypoint
pattern.2 = 'PK??NOS_PO'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_NOS_Installer.1.sg

[NOS Installer]
pattern = 50 E8 00 00 00 00 5B 81 EB ?? ?? ?? ?? B9 ?? ?? ?? ?? 2B D9 8B F3 81 EB ?? ?? ?? ?? 8B FB 81 EB ?? ?? ?? ?? 57 51 56 E8 ?? ?? ?? ?? 83 C4 ?? 8B AB ?? ?? ?? ?? 8D 2C 2B 4D 8A 4D ?? 80 F9 ?? 74 ?? 83 ED ?? 8B D3 2B 53
at = entrypoint
pattern.2 = 'NOS_PO'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_NOS_Installer.1.sg

[NOS Installer]
pattern = E8 $$$$$$$$ 58 BB ?? ?? ?? ?? 8B B3 ?? ?? ?? ?? 8D 04 33 48 8A 08 80 F9 ?? 74 ?? 83 E8 ?? 8B 10 8B B3 ?? ?? ?? ?? 03 F3 8D BB ?? ?? ?? ?? 57 8B CA 2B CE 51 56
at = entrypoint
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_NOS_Installer.1.sg

; installer_Nullsoft_Scriptable_Install_System.1.sg
[Nullsoft Scriptable Install System]
pattern = EF BE AD DE 'Null' ?? 'oftInst'
at = overlay + 0x4
requires = native
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg
x-die-loss = compression options read from file

[Nullsoft Scriptable Install System]
pattern = EF BE AD DE 'nsisinstall'
at = overlay
requires = native
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg
x-die-loss = compression options read from file

[Nullsoft Scriptable Install System]
pattern = EF BE AD DE 'Null' %% 'oftInst'
in = overlay[0x5-0x10000]
requires = native
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg
x-die-loss = header searched in the first 64 KB of the overlay, DIE reads its offset from the first overlay dword; compression options read from file

[Nullsoft Scriptable Install System]
pattern = 'Null' ('s' | 'S') 'oft Install System'
in = manifest
requires = native
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg
x-die-loss = version read from file

[Nullsoft Scriptable Install System 1.XX]
pattern = 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00
at = entrypoint
requires = native
type = installer
version = 1.XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 1.3X]
pattern = 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD
at = entrypoint
requires = native
type = installer
version = 1.3X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 1.X]
pattern = 83 EC 5C 53 55 56 57 FF 15
at = entrypoint
requires = native
type = installer
version = 1.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 1.98]
pattern = 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05
at = entrypoint
pattern.2 = 2C 81
at.2 = entrypoint + 0x8
requires = native
type = installer
version = 1.98
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 2.0a0]
pattern = 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05
at = entrypoint
pattern.2 = B4 10
at.2 = entrypoint + 0x8
requires = native
type = installer
version = 2.0a0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 1.XX]
pattern = 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05
at = entrypoint
requires = native
type = installer
version = 1.XX
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 2.0b2/2.0b3]
pattern = 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00
at = entrypoint
requires = native
type = installer
version = 2.0b2/2.0b3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 2.0b4]
pattern = 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00
at = entrypoint
requires = native
type = installer
version = 2.0b4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 2.0b4]
pattern = 83 EC 10 53 55 56 57 C7 44 24 14 ?? ?? 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00
at = entrypoint
pattern.2 = F0 91
at.2 = entrypoint + 0xB
requires = native
type = installer
version = 2.0b4
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 2.0 RC2]
pattern = 83 EC 10 53 55 56 57 C7 44 24 14 ?? ?? 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00
at = entrypoint
pattern.2 = 70 92
at.2 = entrypoint + 0xB
requires = native
type = installer
version = 2.0 RC2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System]
pattern = 83 EC 10 53 55 56 57 C7 44 24 14 ?? ?? 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00
at = entrypoint
requires = native
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 2.0]
pattern = 83 EC 0C 53 55 56 57 C7 44 24 10 ?? ?? ?? ?? 33 DB C6 44 24 14 20 FF 15 ?? ?? ?? ?? 53 FF 15
at = entrypoint
requires = native
type = installer
version = 2.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 2.06]
pattern = 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15
at = entrypoint
requires = native
type = installer
version = 2.06
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

[Nullsoft Scriptable Install System 0.98]
pattern = 55 8B EC 83 EC ?? 53 56 33 F6 57 56 89 75 ?? 89 75 ?? BB ?? ?? ?? ?? FF 15 ?? ?? ?? ?? BF ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 50 A3 ?? ?? ?? ?? FF 15
at = entrypoint
requires = native
type = installer
version = 0.98
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Nullsoft_Scriptable_Install_System.1.sg

; installer_O'Setup95.1.sg
[O'Setup95 [Celtech Software]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'FILE'
at.2 = overlay
type = installer
options = Celtech Software
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_O'Setup95.1.sg

; installer_PackageForTheWeb.1.sg
[PackageForTheWeb [InstallShield]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = ?? ?? 00 00 DC ED BD
at.2 = overlay
type = installer
options = InstallShield
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_PackageForTheWeb.1.sg

; installer_Pantaray_QSetup.1.sg
[Pantaray QSetup 10.0.0.X]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3
at = entrypoint
pattern.2 = 97 03 00 00 02 01
at.2 = overlay
type = installer
version = 10.0.0.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Pantaray_QSetup.1.sg

[Pantaray QSetup 11.0.0.X]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3
at = entrypoint
pattern.2 = 37 07 00 00 02 01
at.2 = overlay
type = installer
version = 11.0.0.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Pantaray_QSetup.1.sg

[Pantaray QSetup 6.0.0.0]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3
at = entrypoint
pattern.2 = '|http:'
in.2 = overlay[0-0x400]
type = installer
version = 6.0.0.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Pantaray_QSetup.1.sg

[Pantaray QSetup 8.0.0.0]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3
at = entrypoint
pattern.2 = '|www.'
in.2 = overlay[0-0x400]
type = installer
version = 8.0.0.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Pantaray_QSetup.1.sg

; installer_Paquet_Builder.1.sg
[Paquet Builder [7zip]]
pattern = 55 89 E5 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC ?? 83 EC ?? 53 56 57 89 65 ?? 68
at = entrypoint
pattern.2 = 'PB' ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? '7z'
at.2 = overlay
type = installer
options = 7zip
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Paquet_Builder.1.sg

; installer_PCInstall.1.sg
[PCInstall]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = '[20/20]'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_PCInstall.1.sg

; installer_PIMP.1.sg
[PIMP Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD ?? ?? ?? ?? F3 A5 6A ?? 33 C0 59 8D BD ?? ?? ?? ?? F3 AB 8D 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 33 F6 50 56 FF
at = entrypoint
pattern.2 = 'PIMPFILE' 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_PIMP.1.sg

; installer_QT_installer.1.sg
[QT installer]
pattern = 'qres' 00 00 00 01 ?? ?? ?? ?? 00 00 00 14 00
at = overlay
type = installer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_QT_installer.1.sg

; installer_Quick_Install.1.sg
[Quick Install [by Snow Storm Software]]
pattern = 55 8B EC 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC 04 57 E8 $$$$$$$$ DB E3 C3
at = entrypoint
section = txt0
type = installer
options = by Snow Storm Software
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Quick_Install.1.sg

; installer_RNsetup.1.sg
[RNsetup 6.0]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 ?? 53 56 57
at = entrypoint
pattern.2 = '.rzt'
at.2 = resource(*/Archive)
type = installer
version = 6.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_RNsetup.1.sg
x-die-loss = DIE only checks the first resource

; installer_SCE_installer.1.sg
[Silver Creek Entertainment [zlib]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 78 9C
at.2 = resource
type = installer
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_SCE_installer.1.sg

; installer_Setup-Specialist.1.sg
[Setup-Specialist 4.0.X]
pattern = 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15
at = entrypoint
pattern.2 = 'TGCF'
at.2 = overlay
type = installer
version = 4.0.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup-Specialist.1.sg

[Setup-Specialist 3.0]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76
at = entrypoint
pattern.2 = 'TGCF'
at.2 = overlay
type = installer
version = 3.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup-Specialist.1.sg

; installer_Setup_Factory.1.sg
[Setup Factory 6.0.0.3]
pattern = 55 8B EC 6A FF 68 ?? 61 40 00 68 ?? 43 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00
at = entrypoint
pattern.2 = 90 61 40 00
at.2 = entrypoint + 0x6
type = installer
version = 6.0.0.3
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup_Factory.1.sg
x-die-loss = Trial option from version info Comments not set

[Setup Factory 6.X]
pattern = 55 8B EC 6A FF 68 ?? 61 40 00 68 ?? 43 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00
at = entrypoint
type = installer
version = 6.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup_Factory.1.sg
x-die-loss = Trial option from version info Comments not set

[Setup Factory 8.0]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? 3B C7 BB ?? ?? ?? ?? 74 ?? 85 C3 74 ?? F7 D0 A3 ?? ?? ?? ?? EB
at = entrypoint
pattern.2 = E0 E0 E1 E1 E2 E2 E3 E3 E4 E4 E5 E5 E6 E6 E7 E7
at.2 = overlay
type = installer
version = 8.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup_Factory.1.sg
x-die-loss = Trial option from version info Comments not set

[Setup Factory 9.0]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74 ?? 85 C3 74 ?? F7 D0 A3 ?? ?? ?? ?? EB
at = entrypoint
pattern.2 = E0 E0 E1 E1 E2 E2 E3 E3 E4 E4 E5 E5 E6 E6 E7 E7
at.2 = overlay
type = installer
version = 9.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup_Factory.1.sg
x-die-loss = Trial option from version info Comments not set

[Setup Factory 9.5]
pattern = 48 83 EC ?? E8 $$$$$$$$ 48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 05 ?? ?? ?? ?? 48 83 64 24 ?? ?? 48 BF ?? ?? ?? ?? ?? ?? ?? ?? 48 3B C7 74 ?? 48 F7 D0 48 89 05 ?? ?? ?? ?? EB
at = entrypoint
pattern.2 = E0 E0 E1 E1 E2 E2 E3 E3 E4 E4 E5 E5 E6 E6 E7 E7
at.2 = overlay
type = installer
version = 9.5
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup_Factory.1.sg
x-die-loss = Trial option from version info Comments not set

[Setup Factory 5.0]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = E0 E1 E2 E3 E4 E5 E6
at.2 = overlay
type = installer
version = 5.0
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup_Factory.1.sg
x-die-loss = Trial option from version info Comments not set

[Setup Factory 4.02]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = E0 E1 E2 E3 E4 E5 E6
at.2 = overlay
type = installer
version = 4.02
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Setup_Factory.1.sg
x-die-loss = Trial option from version info Comments not set

; installer_SfxCA.1.sg
[Sfx Custom Action 3.8, by Outercurve Foundation]
pattern = 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F8 8B DA 48 8B F1 83 FA ?? 75 ?? E8 ?? ?? ?? ?? 4C 8B C7
at = entrypoint
pattern.2 = 'MSCF' 00 00 00 00
at.2 = overlay
type = installer
version = 3.8, by Outercurve Foundation
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_SfxCA.1.sg

[Sfx Custom Action 3.10, by Outercurve Foundation]
pattern = 55 8B EC 83 7D ?? ?? 75 ?? E8 $$$$$$$$ 55 8B EC 83 EC ?? 83 65 ?? ?? 83 65 ?? ?? A1 ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7
at = entrypoint
pattern.2 = 'MSCF' 00 00 00 00
at.2 = overlay
type = installer
version = 3.10, by Outercurve Foundation
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_SfxCA.1.sg

; installer_Smart_Install_Maker.1.sg
[Smart Install Maker]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3
at = entrypoint
pattern.2 = 'Smart Install Maker v'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Smart_Install_Maker.1.sg
x-die-loss = version read from file

[Smart Install Maker]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 $$$$$$$$ 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3
at = entrypoint
pattern.2 = ?? ?? ?? ?? ?? 87 00 00 01 ?? ?? ?? ?? 5D 00 00 80 00 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Smart_Install_Maker.1.sg

; installer_Sony_Windows_Installer.1.sg
[Sony Windows Installer]
pattern = 48 83 EC ?? E8 $$$$$$$$ 48 89 5C ?? ?? 57 48 83 EC ?? 48 8B ?? ?? ?? ?? ?? 48 83 64 24 ?? ?? 48 BF ?? ?? ?? ?? ?? ?? ?? ?? 48 3B C7 74
at = entrypoint
pattern.2 = 'UM' 03 0A 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Sony_Windows_Installer.1.sg

[Sony Windows Installer]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74
at = entrypoint
pattern.2 = 'UM' 03 0A 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Sony_Windows_Installer.1.sg

; installer_Spoon_Installer.1.sg
[Spoon Installer [BZIP2]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'BZh91AY&SY'
at.2 = overlay
type = installer
options = BZIP2
author = hypn0, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Spoon_Installer.1.sg
x-die-loss = version 11 2005 selected by the entry point address not set

[Spoon Installer [Lzma]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = ']' 00 00 80 00
at.2 = overlay
type = installer
options = Lzma
author = hypn0, A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Spoon_Installer.1.sg
x-die-loss = version 11 2005 selected by the entry point address not set

; installer_Squirrel.1.sg
[Squirrel 1.0.0-1.9.1]
version_info.SquirrelAwareVersion = 1
type = installer
version = 1.0.0-1.9.1
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Squirrel.1.sg

[Squirrel]
version_info.SquirrelAwareVersion = /^(?!1$)./
type = installer
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Squirrel.1.sg
x-die-loss = version read from file

; installer_sqx.1.sg
[SQX Archive Installer 2002]
pattern = 55 8B EC 83 EC 44
at = entrypoint
pattern.2 = 'SFX kann nicht gestartet werden'
in.2 = section(.data)
type = installer
author = A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_sqx.1.sg

; installer_STATICSUP.1.sg
[STATICSUP]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 67 15 52 34 FF 4D 36 42
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_STATICSUP.1.sg

; installer_SwiftView_installer.1.sg
[SwiftView Inc. installer 6.1]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 89 65
at = entrypoint
pattern.2 = 'This is the end of the executable'
at.2 = overlay
type = installer
version = 6.1
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_SwiftView_installer.1.sg

; installer_Synactis_In-The-Box_Installer.1.sg
[Synactis In-The-Box Installer [zip sfx]]
pattern = 'All In-The-Box Installer'
at = entrypoint + 0x60
type = installer
options = zip sfx
author = A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Synactis_In-The-Box_Installer.1.sg

; installer_Tarma_Installer.1.sg
[Tarma Installer [zlib]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? E8
at = entrypoint
pattern.2 = 'tiz1' ?? ?? ?? ?? 78 DA
at.2 = overlay
section = .tsustub, .tsuarch
type = installer
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

[Tarma Installer [zlib]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? E8
at = entrypoint
pattern.2 = 'tiz1' ?? ?? ?? ?? 78 DA
at.2 = overlay
section = !.tsustub
type = installer
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

[Tarma Installer [zlib]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? E8
at = entrypoint
pattern.2 = 'tiz1' ?? ?? ?? ?? 78 DA
at.2 = overlay
section = !.tsuarch
type = installer
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

[Tarma Installer [zlib]]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD ?? EB
at = entrypoint
pattern.2 = 'tiz1' ?? ?? ?? ?? 78 DA
at.2 = overlay
section = .tsustub, .tsuarch
type = installer
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

[Tarma Installer [zlib]]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD ?? EB
at = entrypoint
pattern.2 = 'tiz1' ?? ?? ?? ?? 78 DA
at.2 = overlay
section = !.tsustub
type = installer
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

[Tarma Installer [zlib]]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD ?? EB
at = entrypoint
pattern.2 = 'tiz1' ?? ?? ?? ?? 78 DA
at.2 = overlay
section = !.tsuarch
type = installer
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

[Tarma InstallMate 9.0 [zlib]]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 33 DB 57 66 89 9D ?? ?? ?? ?? 89 5D ?? 89 5D ?? FF 15
at = entrypoint
pattern.2 = 'tiz1' ?? ?? ?? ?? 78 DA
at.2 = overlay
section = .tsustub, .tsuarch
type = installer
version = 9.0
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

[Tarma InstallMate 9.0]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 33 DB 57 66 89 9D ?? ?? ?? ?? 89 5D ?? 89 5D ?? FF 15
at = entrypoint
section = .tsustub, .tsuarch
type = installer
version = 9.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

[Tarma InstallMate 9.0 [x64]]
pattern = 48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 81 EC ?? ?? ?? ?? 66 83 64 24 ?? ?? 33 F6 33 FF FF 15 ?? ?? ?? ?? 48 8D 8C 24 ?? ?? ?? ?? 8B D8 FF 15
at = entrypoint
section = .tsustub, .tsuarch
type = installer
version = 9.0
options = x64
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Tarma_Installer.1.sg

; installer_Themepak.1.sg
[THEMEPAK]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 C7 45 ?? ?? ?? ?? ?? FF 75 ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 8D 45
at = entrypoint
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Themepak.1.sg

; installer_UFI_installer.1.sg
[UFI installer 1.X, Flash]
pattern = 55 8B EC
at = entrypoint
resource = */BINFILE, */BINFILE_2
type = installer
version = 1.X, Flash
author = A.S.L
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_UFI_installer.1.sg

; installer_Vise.1.sg
[Vise]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'ESIV'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Vise.1.sg

[Vise]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'SIVM'
at.2 = image + 0xF000
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Vise.1.sg

; installer_VMWare.1.sg
[VMWare Installation Launcher]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
pattern.2 = 'RWMV'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_VMWare.1.sg
x-die-loss = version read from file

[VMWare Installation Launcher]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? 3B C7 BB ?? ?? ?? ?? 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
pattern.2 = 'RWMV'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_VMWare.1.sg
x-die-loss = version read from file

[VMWare Installation Launcher]
pattern = 48 83 EC ?? E8 $$$$$$$$ 48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 05 ?? ?? ?? ?? 48 83 64 24 ?? ?? 48 BF ?? ?? ?? ?? ?? ?? ?? ?? 48 3B C7 74 ?? 48 F7 D0
at = entrypoint
pattern.2 = 'RWMV'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_VMWare.1.sg
x-die-loss = version read from file

[VMWare Installation Launcher]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? 83 65 ?? ?? 83 65 ?? ?? A1 ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7
at = entrypoint
pattern.2 = 'RWMV'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_VMWare.1.sg
x-die-loss = version read from file

[VMWare Software Installer [bzip2]]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? 3B C7 BB ?? ?? ?? ?? 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
pattern.2 = 'BZh91AY&'
in.2 = overlay[0-0x100]
type = installer
options = bzip2
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_VMWare.1.sg
x-die-loss = version read from file

[VMWare Software Installer [MS Compound]]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? 3B C7 BB ?? ?? ?? ?? 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
pattern.2 = D0 CF 11 E0 A1 B1 1A E1
in.2 = overlay[0-0x100]
type = installer
options = MS Compound
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_VMWare.1.sg
x-die-loss = version read from file

; installer_Winamp_Installer.1.sg
[Winamp Installer 1.0 [1997-98 by Nullsoft, Inc.]]
pattern = 81 EC ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 53 89 44 24 ?? A1 ?? ?? ?? ?? 89 4C 24 ?? 8A 0D ?? ?? ?? ?? 55 56 57 89 44 24 ?? 88 4C 24 ?? B9
at = entrypoint
type = installer
version = 1.0
options = 1997-98 by Nullsoft, Inc.
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Winamp_Installer.1.sg

; installer_Windows_Installer.1.sg
[Windows Installer]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = resource
pattern.2 = 'Windows Installer'
in.2 = resource
type = installer
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Windows_Installer.1.sg
x-die-loss = the string may be in another resource than the OLE header; XML option and version read from file

; installer_WinRAR_Installer.1.sg
[WinRAR Installer [Unicode]]
pattern = E8 $$$$$$$$ 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? 53
at = entrypoint
pattern.2 = '***messages***'
at.2 = overlay
pattern.3 = FF FE 2A 00 2A 00 2A 00 6D 00 65 00 73 00 73 00 61 00 67 00 65 00 73 00 2A 00 2A 00 2A 00
at.3 = overlay
type = installer
options = Unicode
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WinRAR_Installer.1.sg

[WinRAR Installer]
pattern = E8 $$$$$$$$ 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? 53
at = entrypoint
pattern.2 = '***messages***'
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WinRAR_Installer.1.sg

[WinRAR Installer [Unicode]]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 ?? 2B CF FC F3 AA 59 5F
at = entrypoint
pattern.2 = 'Rar!' 1A
at.2 = overlay
pattern.3 = FF FE 2A 00 2A 00 2A 00 6D 00 65 00 73 00 73 00 61 00 67 00 65 00 73 00 2A 00 2A 00 2A 00
at.3 = overlay
type = installer
options = Unicode
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WinRAR_Installer.1.sg

[WinRAR Installer]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 ?? 2B CF FC F3 AA 59 5F
at = entrypoint
pattern.2 = 'Rar!' 1A
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WinRAR_Installer.1.sg

[WinRAR Installer [Unicode]]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 59 89 45 ?? 83 7D
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
pattern.3 = FF FE 2A 00 2A 00 2A 00 6D 00 65 00 73 00 73 00 61 00 67 00 65 00 73 00 2A 00 2A 00 2A 00
at.3 = overlay
type = installer
options = Unicode
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WinRAR_Installer.1.sg

[WinRAR Installer]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 59 89 45 ?? 83 7D
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WinRAR_Installer.1.sg

[WinRAR Installer 5.X [Unicode]]
pattern = 48 83 EC ?? E8 $$$$$$$$ 48 89 5C 24 ?? 55 48 8B EC 48 83 EC ?? 48 83 65 ?? ?? 48 BB ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 3B C3 75
at = entrypoint
pattern.2 = FF FE 2A 00 2A 00 2A 00 6D 00 65 00 73 00 73 00 61 00 67 00 65 00 73 00 2A 00 2A 00 2A 00
at.2 = overlay
type = installer
version = 5.X
options = Unicode
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WinRAR_Installer.1.sg

[WinRAR Installer 5.X [Unicode]]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? 83 65 ?? ?? 83 65 ?? ?? A1 ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7
at = entrypoint
pattern.2 = FF FE 2A 00 2A 00 2A 00 6D 00 65 00 73 00 73 00 61 00 67 00 65 00 73 00 2A 00 2A 00 2A 00
at.2 = overlay
type = installer
version = 5.X
options = Unicode
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WinRAR_Installer.1.sg

; installer_Wise_Installer.1.sg
[Wise Installer]
requires = overlay
section = .WISE
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg
x-die-loss = overlay size > 80 not checked

[Wise Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 6A ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F0 89 75 ?? 8A 06 3C ?? 0F 85 ?? ?? ?? ?? 8A 46 ?? 46
at = entrypoint
requires = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg
x-die-loss = overlay size > 80 not checked

[Wise Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 6A ?? 5E 6A ?? 89 75 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F8 89 7D ?? 8A 07 3C ?? 0F 85 ?? ?? ?? ?? 8A 47 ?? 47
at = entrypoint
requires = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg
x-die-loss = overlay size > 80 not checked

[Wise Installer [CAB]]
pattern = 81 EC ?? ?? ?? ?? 53 55 56 57 6A ?? FF 15 ?? ?? ?? ?? 33 DB 89 5C 24 ?? 89 5C 24 ?? 89 5C 24 ?? 89 5C 24 ?? 89 5C 24 ?? FF 15 ?? ?? ?? ?? 8A 08 89 44 24
at = entrypoint
section = .WISE
type = installer
options = CAB
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg
x-die-loss = overlay size <= 80 not checked

[Wise Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 33 F6 46 6A ?? 89 75 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B F8 8A 07
at = entrypoint
pattern.2 = 'Wise Installation Wizard...'
in.2 = overlay[0-0x1000]
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg

[Wise Installer]
pattern = 'Wise Installation Wizard...'
in = section(.WISE)[0-0x1000]
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg

[Wise Installer [ZIP]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 50 4B 03 04
in.2 = overlay[0-0x1000]
type = installer
options = ZIP
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg

[Wise Installer [CAB]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'MSCF' 00 00
at.2 = overlay
type = installer
options = CAB
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg

[Wise Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 8D 85 ?? ?? ?? ?? 56 33 DB 57 BE ?? ?? ?? ?? 56 50 53 FF 15 ?? ?? ?? ?? 56 8D 85 ?? ?? ?? ?? 50 50 FF 15 ?? ?? ?? ?? 53 8D 8D ?? ?? ?? ?? 53 6A ?? 53 6A ?? 68 ?? ?? ?? ?? 51 FF 15
at = entrypoint
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg

[Wise Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 8D 85 ?? ?? ?? ?? 56 57 33 F6
at = entrypoint
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg

[Wise Installer]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 BE ?? ?? ?? ?? 57 8D 85 ?? ?? ?? ?? 56 33 DB 50 53
at = entrypoint
pattern.2 = 'GLB' 00
at.2 = section(.data) + 0x10
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Wise_Installer.1.sg

; installer_WiX_Toolset_installer.1.sg
[WiX Toolset Installer]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7 74 ?? 85 C6 74 ?? F7
at = entrypoint
pattern.2 = 'MSCF' 00 00 00 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WiX_Toolset_installer.1.sg

[WiX Toolset Installer]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? 83 65 ?? ?? 83 65 ?? ?? A1 ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B C7 74 ?? 85 C6 74 ?? F7
at = entrypoint
pattern.2 = 'MSCF' 00 00 00 00
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WiX_Toolset_installer.1.sg

[WiX Toolset Installer 3.X]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7 74 ?? 85 C3 74 ?? F7
at = entrypoint
pattern.2 = 'MSCF' 00 00 00 00
at.2 = overlay
type = installer
version = 3.X
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WiX_Toolset_installer.1.sg

[WiX Toolset Installer 1.0]
pattern = 'MSCF' 00 00 00 00
at = overlay
section = .wixburn
type = installer
version = 1.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_WiX_Toolset_installer.1.sg

; installer_Xoreax_installer.1.sg
[Xoreax Installer]
pattern = 55 8B EC B9 ?? ?? ?? ?? 6A ?? 6A ?? 49 75 ?? 51 53 56 57 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55
at = entrypoint
pattern.2 = 5D 00 00
at.2 = resource(RT_RCDATA)
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/installer_Xoreax_installer.1.sg


; ======================================================================
; Self-extracting archives
; ======================================================================

; sfx_12Ghosts_Zip2.1.sg
[12Ghosts Zip2 8.0 [BZIP2]]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? 3B C7 BB ?? ?? ?? ?? 74
at = entrypoint
pattern.2 = 'BZh91'
in.2 = overlay[0-0x1000]
type = sfx
version = 8.0
options = BZIP2
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_12Ghosts_Zip2.1.sg

; sfx_7z.1.sg
[7-Zip]
pattern = ';!@Install@!UTF-8!'
at = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_7z.1.sg
x-die-loss = version read from file

[7-Zip]
pattern = '7z' BC AF 27 1C
at = overlay
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_7z.1.sg
x-die-loss = version read from file

[7-Zip]
pattern = EF BB BF ';!@Install@!UTF-8!'
at = overlay
type = installer
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_7z.1.sg
x-die-loss = version read from file

; sfx_Abbyy_Lingvo.1.sg
[Abbyy Lingvo]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'ArcUpdateABBYY' 00
at.2 = eof - 0xF
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Abbyy_Lingvo.1.sg

; sfx_Active_Delivery.1.sg
[Active Delivery]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 60 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'AD01'
at.2 = section(actdlvry)
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Active_Delivery.1.sg

; sfx_ARJSFX.1.sg
[ARJSFX32]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 ?? 2B CF FC F3 AA 59 5F 64 67 8B 16 ?? ?? 8B 42 ?? A3
at = entrypoint
pattern.2 = C0 AB ?? ?? ?? ?? 60 EA
at.2 = overlay
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_ARJSFX.1.sg

[ARJSFX]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 60 EA
at.2 = overlay
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_ARJSFX.1.sg

[ARJSFX]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
resource = ARJDATA
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_ARJSFX.1.sg

; sfx_ARQ.1.sg
[ARQ]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 67 57 04 02
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_ARQ.1.sg

[ARQ]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 67 57 04 02
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_ARQ.1.sg

; sfx_Bandizip.1.sg
[Bandizip]
pattern = 'BANDIZIPSFX' 00 'PK' 03 04
at = overlay
type = sfx
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Bandizip.1.sg

; sfx_Cab.1.sg
[Microsoft Cabinet]
pattern = 'wextract'
at = overlay + 0x10
type = sfx
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Cab.1.sg
x-die-loss = version read from file

[Microsoft Cabinet]
pattern = 'sfxcab'
in = manifest
type = sfx
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Cab.1.sg
x-die-loss = version read from file

[Microsoft Cabinet]
version_info.InternalName = /wextract/i
type = sfx
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Cab.1.sg
x-die-loss = version read from file

[Microsoft Cabinet]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 66 25 ?? ?? 3D
at = entrypoint
pattern.2 = 'MSCF' 00 00 00 00
at.2 = image + 0x5000
type = sfx
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Cab.1.sg

[Microsoft Cabinet]
pattern = 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 81 3D ?? ?? ?? ?? ?? ?? 75 ?? A1 ?? ?? ?? ?? 81 B8 ?? ?? ?? ?? ?? ?? ?? ?? 75 ??
at = entrypoint
pattern.2 = 'MSCF' 00 00 00 00
at.2 = overlay
type = sfx
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Cab.1.sg

[Microsoft Cabinet]
pattern = E9 $$$$$$$$ 55 8B EC 81 EC ?? ?? ?? ?? 83 0D ?? ?? ?? ?? ?? 53 56 57 6A ?? 33 DB BF ?? ?? ?? ?? 68 ?? ?? ?? ?? 89 5D ?? 88 1D
at = entrypoint
type = sfx
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Cab.1.sg

[Microsoft Cabinet]
pattern = 'MSCF' 00 00 00 00
at = resource(*/CABINET), resource(*/IDR_CABFILE)
type = sfx
author = Jason Hood
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Cab.1.sg

; sfx_Chilkat_ZIP_Self-Extractor.1.sg
[Chilkat ZIP Self-Extractor]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 07 D2 6C BF 21 59 AB AA 01 00 00 00 00
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Chilkat_ZIP_Self-Extractor.1.sg

; sfx_CoffeeCup_SFX.2.sg
[CoffeeCup]
pattern = 55 8B EC 83 C4 ?? 33 C0 89 45 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 6A ?? 68 ?? ?? ?? ?? 6A
at = entrypoint
pattern.2 = 'MPU' 00
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_CoffeeCup_SFX.2.sg

; sfx_DelZip_SFX.2.sg
[DelZip]
pattern = 55 8B EC 83 C4 ?? 33 C0 89 45 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 6A ?? 68 ?? ?? ?? ?? 6A
at = entrypoint
pattern.2 = 'MPV'
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_DelZip_SFX.2.sg

; sfx_Dimd_SFX.1.sg
[Dimd [CAB SFX]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = ?? ?? ?? ?? 'DIMDMSCF'
at.2 = overlay
type = sfx
options = CAB SFX
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Dimd_SFX.1.sg

; sfx_Envoy_Packager.1.sg
[Envoy Packager [1994 by Novell, Inc.]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = B2 97 E1 69
at.2 = overlay
type = sfx
options = 1994 by Novell, Inc.
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Envoy_Packager.1.sg

; sfx_GkSetup.1.sg
[GkSetup SFX [1998 by Gero Kuehn]]
pattern = E9 $$$$$$$$ 53 51 52 55 89 E5 83 EC ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 83 C0 ?? 24 ?? 31 D2 29 C4 89 E1 8B 1D
at = entrypoint
pattern.2 = '/SFX'
in.2 = overlay[0-0x300]
type = sfx
options = 1998 by Gero Kuehn
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_GkSetup.1.sg

[GkSetup SFX [1999 by Gero Kuehn]]
pattern = 56 68 ?? ?? ?? ?? 33 F6 68 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? A1
at = entrypoint
pattern.2 = '/SFX'
in.2 = overlay[0-0x300]
type = sfx
options = 1999 by Gero Kuehn
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_GkSetup.1.sg

[GkSetup SFX 2.0]
pattern = 56 33 F6 56 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? A1 ?? ?? ?? ?? 8B 40 ?? 48
at = entrypoint
pattern.2 = '2.00'
at.2 = overlay
type = sfx
version = 2.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_GkSetup.1.sg

; sfx_GZip.1.sg
[GZip]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 65
at = entrypoint
pattern.2 = 1F 8B 08
at.2 = resource
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_GZip.1.sg

[GZip]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 1F 8B 08
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_GZip.1.sg

; sfx_INFTool.1.sg
[INFTool]
pattern = 55 8B EC 83 C4 ?? E8 $$$$$$$$ E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05
at = entrypoint
pattern.2 = 'INFTool.pkg'
in.2 = image
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_INFTool.1.sg

; sfx_KRZIP_SFX.2.sg
[KRZIP [by Kryloff Technologies, Inc.]]
pattern = 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 A1 ?? ?? ?? ?? 83 78
at = entrypoint
pattern.2 = '<KRZIP FILE BEGINS HERE>'
at.2 = overlay
type = sfx
options = by Kryloff Technologies, Inc.
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_KRZIP_SFX.2.sg

; sfx_Lyme_SFX.1.sg
[Lyme SFX [zlib]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 78 9C
at.2 = overlay
type = sfx
options = zlib
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Lyme_SFX.1.sg

; sfx_LZH_SFX.1.sg
[LZH 2.60.w32 [by Yoshi 1991 / mH 1995 / Micco 1997-99]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 8B 0D
at = entrypoint
pattern.2 = ?? ?? '-lh' ?? '-'
at.2 = overlay
type = sfx
version = 2.60.w32
options = by Yoshi 1991 / mH 1995 / Micco 1997-99
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_LZH_SFX.1.sg

[LZH 2.71.X [by Yoshi 1991 / mH 1995 / Micco 1997-99]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 8B 0D
at = entrypoint
pattern.2 = ?? ?? ?? ?? '-lh' ?? '-'
at.2 = overlay
type = sfx
version = 2.71.X
options = by Yoshi 1991 / mH 1995 / Micco 1997-99
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_LZH_SFX.1.sg

[LZH [custom]]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF
at = entrypoint
pattern.2 = '-lh' ?? '-'
in.2 = overlay[0-0x1000]
type = sfx
options = custom
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_LZH_SFX.1.sg

; sfx_MP-ZipTool.1.sg
[MP-ZipTool SFX32]
pattern = 55 8B EC 83 C4 ?? 33 C0 89 45 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 6A ?? 68 ?? ?? ?? ?? 6A
at = entrypoint
pattern.2 = 'MPU' 0D
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_MP-ZipTool.1.sg

; sfx_MPQ.1.sg
[Blizzard MPQ]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'MPQ' 1A 20
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_MPQ.1.sg

; sfx_NanoZip.1.sg
[NanoZip 0.09a [nz_w32c.sfx]]
pattern = 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75
at = entrypoint
pattern.2 = AE 01 'NanoZip 0.09 alpha'
at.2 = overlay
type = sfx
version = 0.09a
options = nz_w32c.sfx
author = LinXP
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_NanoZip.1.sg

; sfx_Paquet.1.sg
[Paquet 1.5, 1998 by Guillaume Di Giusto]
pattern = 55 8B EC 81 C4 ?? ?? ?? ?? 53 56 57 33 C0 89 85
at = entrypoint
pattern.2 = 04 'PBG'
at.2 = overlay
type = sfx
version = 1.5, 1998 by Guillaume Di Giusto
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Paquet.1.sg

[Paquet 1.0, 1997 by Guillaume Di Giusto]
pattern = 55 8B EC 81 C4 ?? ?? ?? ?? 53 56 57 33 C0 89 85
at = entrypoint
pattern.2 = 'GSfx'
at.2 = overlay
type = sfx
version = 1.0, 1997 by Guillaume Di Giusto
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Paquet.1.sg

; sfx_PKSFX.1.sg
[PKSFX 2.50]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 ?? 53 56 57
at = entrypoint
pattern.2 = 'PK' 09 0A
at.2 = overlay
type = sfx
version = 2.50
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_PKSFX.1.sg

; sfx_Quantum.1.sg
[Quantum]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'DS' 00
at.2 = resource
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Quantum.1.sg

; sfx_rar.1.sg
[RAR (custom) [type 1]]
pattern = 55 8B EC 83 C4 ?? 53 56 57 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8
at = entrypoint
pattern.2 = 'rar!'
at.2 = resource
type = sfx
options = type 1
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_rar.1.sg

[RAR (custom) [type 2]]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3
at = entrypoint
pattern.2 = 'Rar!'
in.2 = overlay[0-0x1000]
type = sfx
options = type 2
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_rar.1.sg

; sfx_SpeedCommander.1.sg
[SpeedCommander]
pattern = 60 BE 00 40 82 00 8D BE 00 D0 BD FF 57 EB 0B 90 8A 06 46
at = entrypoint
pattern.2 = 'SCSFX' 00 CF B0 01
at.2 = overlay
type = sfx
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_SpeedCommander.1.sg
x-die-loss = version read from file

; sfx_Squeez_SFX.1.sg
[Squeez SFX 6.0.0.0]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? 33 DB 89 5D ?? 6A ?? FF 15
at = entrypoint
pattern.2 = 'SQ5SFX'
at.2 = overlay
type = sfx
version = 6.0.0.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Squeez_SFX.1.sg

; sfx_SZDD.1.sg
[SZDD]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'SZDD'
at.2 = resource(FILE)
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_SZDD.1.sg

[SZDD [1997 by Khaled Mardam-Bey]]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 ?? 2B CF FC F3 AA 59 5F
at = entrypoint
pattern.2 = 'SZDD'
at.2 = resource(RT_RCDATA)
type = sfx
options = 1997 by Khaled Mardam-Bey
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_SZDD.1.sg

[SZDD [1997 by Klever Co.]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'SZDD'
at.2 = resource(RT_RCDATA)
type = sfx
options = 1997 by Klever Co.
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_SZDD.1.sg

; sfx_WinACE.1.sg
[WinACE]
version_info.InternalName = /WinACE|UNACE/i
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinACE.1.sg
x-die-loss = version read from file

; sfx_WinImage.1.sg
[WinImage [1998 by Gilles Vollant]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 83 EC ?? 89 01 8B 15
at = entrypoint
pattern.2 = 'RsDl'
at.2 = overlay
type = sfx
options = 1998 by Gilles Vollant
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinImage.1.sg

[WinImage 0.90 [1993-97 by Gilles Vollant]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 83 EC ?? 89 01 8B 15
at = entrypoint
pattern.2 = 'WSfxPK' 03 04
at.2 = overlay + 0xC
type = sfx
version = 0.90
options = 1993-97 by Gilles Vollant
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinImage.1.sg

; sfx_WinIMP.1.sg
[WinIMP [1999 by Technelysium Pty Ltd]]
pattern = 51 52 6A ?? 2E FF 15 ?? ?? ?? ?? 50 6A ?? 6A ?? 2E FF 15 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 50 2E FF 15 ?? ?? ?? ?? 5A 59 C3
at = entrypoint
pattern.2 = 'IMP' 0A
at.2 = overlay
type = sfx
options = 1999 by Technelysium Pty Ltd
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinIMP.1.sg

; sfx_WinPatch.1.sg
[WinPatch Apply Program by Artistry, Inc. [1996-1998 (gzip)]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ?? ?? 53 56 57
at = entrypoint
pattern.2 = '@Daisy@Lucy@xyzzy@' ?? ?? ?? ?? ?? ?? ?? ?? 1F 8B 08
at.2 = overlay
type = sfx
options = 1996-1998 (gzip)
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinPatch.1.sg

[WinPatch Apply Program by Artistry, Inc. [1996-1998 (gzip)]]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ?? ?? 53 56 57
at = entrypoint
pattern.2 = '@Daisy@Lucy@xyzzy@' 1F 8B 08
at.2 = overlay
type = sfx
options = 1996-1998 (gzip)
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinPatch.1.sg

; sfx_WinRAR.1.sg
[WinRAR [ZIP]]
pattern = 'PK'
at = overlay
resource = */STARTDLG, */LICENSEDLG
requires = native
type = sfx
options = ZIP
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinRAR.1.sg

[WinRAR [ZIP]]
pattern = 'PK'
at = overlay
resource = */INSTALL, */SETUP
requires = native
type = sfx
options = ZIP
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinRAR.1.sg

[WinRAR]
pattern = 'Rar!'
at = overlay
resource = */STARTDLG, */LICENSEDLG
requires = native
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinRAR.1.sg

[WinRAR]
pattern = 'Rar!'
at = overlay
resource = */INSTALL, */SETUP
requires = native
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinRAR.1.sg

[WinRAR]
pattern = E8 $$$$$$$$ 53 BB ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 33 D2 8A 10 83 FA ?? 75 ?? 40 EB
at = entrypoint
pattern.2 = 'Rar!' 1A
at.2 = overlay
requires = native
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinRAR.1.sg

; sfx_WinZip.1.sg
[WinZip 6.X]
pattern = FF 15 ?? ?? ?? ?? B1 ?? 38 08 74 ?? B1 ?? 40 80 ?? ?? 74 ?? 38 08 74 ?? 40 80 ?? ?? 75 ?? 80 ?? ?? 74 ?? 40 33
at = entrypoint
type = sfx
version = 6.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinZip.1.sg

[WinZip 2.2]
pattern = 53 FF 15 ?? ?? ?? ?? B3 ?? 38 ?? 74 ?? 80 C3 ?? 40 33 D2 8A 08 3A CA 74 ?? 3A CB 74 ?? 40 8A 08 3A CA 75
at = entrypoint
pattern.2 = 50 4B 03 04
in.2 = overlay[0-0xFF]
type = sfx
version = 2.2
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinZip.1.sg

[WinZip]
pattern = 53 FF 15 ?? ?? ?? ?? B3 ?? 38 ?? 74 ?? 80 C3 ?? 40 33 D2 8A 08 3A CA 74 ?? 3A CB 74 ?? 40 8A 08 3A CA 75
at = entrypoint
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinZip.1.sg

[WinZip 8.X]
pattern = 53 FF 15 ?? ?? ?? ?? B3 ?? 38 ?? 74 ?? 80 C3 ?? 8A 48 ?? 40 33 D2 3A CA 74 ?? 3A CB 74 ?? 8A 48 ?? 40
at = entrypoint
type = sfx
version = 8.X
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinZip.1.sg

[WinZip]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? 3B C7 BB ?? ?? ?? ?? 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
pattern.2 = 'PK' 03 04
in.2 = resource[0-0x1100]
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinZip.1.sg
x-die-loss = resources of type RT_DIALOG are not excluded from the search

[WinZip]
pattern = E8 $$$$$$$$ 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? 3B C7 BB ?? ?? ?? ?? 74 ?? 85 C3 74 ?? F7 D0
at = entrypoint
section = _winzip_
type = sfx
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinZip.1.sg

[WinZip 3.1]
pattern = 'PK' 03 04
in = section(_winzip_)[0-0x1000]
type = sfx
version = 3.1
author = horsicq
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_WinZip.1.sg

; sfx_wrappe.1.sg
[wrappe]
pattern = 55 48 89 E5 48 83 EC 20 48 8B 05 51 E9 07 00 C7 00 00 00 00 00 E8 66 FD FF FF 90 90
at = entrypoint
pattern.2 = 28 B5 2F FD 00
at.2 = overlay
type = sfx
author = BJNFNE
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_wrappe.1.sg

; sfx_Zip_SFX.2.sg
[Zip SFX]
pattern = 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 65 ?? FF 15
at = entrypoint
pattern.2 = 'PK' 03 04
in.2 = overlay[0-0xFF]
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[Zip SFX]
pattern = 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 FF 30 64 89 20 E8
at = entrypoint
resource = ZIP
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg
x-die-loss = DIE requires the first resource to have the type ZIP, any resource is accepted here

[WinRAR 5.0+ [ZIP]]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = sfx
version = 5.0+
options = ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[WinRAR 3.0 [ZIP]]
pattern = E8 $$$$$$$$ 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? 53 BB ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F0
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = sfx
version = 3.0
options = ZIP
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[Zip SFX [by C.Ghisler & Co.]]
pattern = 55 8B EC 83 C4 ?? 53 56 E8 $$$$$$$$ E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = sfx
options = by C.Ghisler & Co.
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[Zip SFX [by Symantec]]
pattern = 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 56 BE ?? ?? ?? ?? 57 8D 45 ?? 56 33 DB 50 53 FF 15 ?? ?? ?? ?? 85 C0 0F 84
at = entrypoint
pattern.2 = 'PK' 03 04
in.2 = overlay[0-0x1000]
type = sfx
options = by Symantec
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[SymW32SFX [by Symantec]]
pattern = 83 EC ?? 56 57 FF 15 ?? ?? ?? ?? 8B F0 8D 44 24 ?? 50 C7 44 24 ?? ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8A 06 8B 3D ?? ?? ?? ?? 3C ?? 75 ?? 56 FF D7
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = sfx
options = by Symantec
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[Symantec EasyZIP SFX]
pattern = 55 8B EC 83 EC ?? 56 57 33 FF FF 15 ?? ?? ?? ?? 8B F0 89 7D ?? 8D 45 ?? 50 FF 15 ?? ?? ?? ?? 8A 06 3C ?? 75 ?? 56 FF 15
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[Zip SFX [Squeez SFX by SpeedProject 1995-1998]]
pattern = 55 8B EC 83 EC ?? 56 FF 15 ?? ?? ?? ?? 8B F0 8A 00 3C ?? 75 ?? 84 C0 74 ?? 80 3E ?? 74 ?? 46 80 3E ?? 75 ?? 80 3E ?? 75 ?? 46 EB
at = entrypoint
pattern.2 = 'PK' 03 04
in.2 = overlay[0-0x2000]
type = sfx
options = Squeez SFX by SpeedProject 1995-1998
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[Zip SFX [EasyZIP SFX by AKSoft 1995-1996]]
pattern = 6A ?? 33 C0 50 50 50 FF 15 ?? ?? ?? ?? 50 E8 $$$$$$$$ 55 B8 ?? ?? ?? ?? 8B EC E8 ?? ?? ?? ?? 53 B9 ?? ?? ?? ?? 56 57 BE
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = sfx
options = EasyZIP SFX by AKSoft 1995-1996
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

[Zip SFX [custom]]
pattern = A1 ?? ?? ?? ?? C1 E0 ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76
at = entrypoint
pattern.2 = 'PK' 03 04
in.2 = overlay[0-0x1000]
type = sfx
options = custom
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_Zip_SFX.2.sg

; sfx_ZipCentral_SFX.1.sg
[ZipCentral SFX-32 2.0]
pattern = 55 8B EC 83 C4 ?? 33 C0 89 ?? ?? B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 55 68 ?? ?? ?? ?? 64 ?? ?? 64 ?? ?? 6A
at = entrypoint
pattern.2 = 'MPV*'
at.2 = overlay
type = sfx
version = 2.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/sfx_ZipCentral_SFX.1.sg
x-die-loss = options read from file (getGeneralOptions)


; ======================================================================
; Other self-extractors and installers
; ======================================================================

; custom_sfx_installers.1.sg
[Toxsoft SFX]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57
at = entrypoint
pattern.2 = ?? ?? '-lh5-'
at.2 = overlay
type = sfx
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg

[Webest SFX 1.0]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57
at = entrypoint
pattern.2 = 'MSCF'
in.2 = overlay[0-0x100]
type = sfx
version = 1.0
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg

[Sax Software installer]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57
at = entrypoint
pattern.2 = A6 D6 B2 10
at.2 = overlay
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg

[XZIP-SFX [by Netzip]]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57
at = entrypoint
pattern.2 = 'Win_Sfx_For_Windows_'
at.2 = overlay
type = sfx
options = by Netzip
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg

[custom installer with SZDD-archives]
pattern = 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57
at = entrypoint
pattern.2 = 'SZDD' 88
at.2 = resource
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg

[ZIP-SFX [by Ashampoo]]
pattern = 55 8B EC 81 EC ?? ?? ?? ?? 53 33 DB 53 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 89 1D ?? ?? ?? ?? 89 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? 39 1D
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = sfx
options = by Ashampoo
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg

[Microsoft Windows update]
pattern = E8 $$$$$$$$ 8B 0D ?? ?? ?? ?? 56 57 BF ?? ?? ?? ?? BE ?? ?? ?? ?? 3B CF 74 ?? 85 CE 75 ?? E8 ?? ?? ?? ?? 8B C8
at = entrypoint
pattern.2 = 5D 00 00 80 00 ?? ?? ?? ?? 00 00 00 00 00 00
at.2 = resource
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg
x-die-loss = DIE checks only the first resource, any resource is accepted here

[SysDev Laboratories]
pattern = E8 $$$$$$$$ 8B FF 55 8B EC 83 EC ?? A1 ?? ?? ?? ?? 83 65 ?? ?? 83 65 ?? ?? 53 57 BF ?? ?? ?? ?? BB ?? ?? ?? ?? 3B C7
at = entrypoint
pattern.2 = ?? ?? ?? ?? 00 02 02 00
at.2 = overlay
pattern.3 = 'SDLSOPKG'
in.3 = overlay[0-0x10000]
type = installer
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg
x-die-loss = SDLSOPKG is searched in the first 0x10000 bytes of the overlay instead of at the overlay offset plus the word read from the overlay start

[ZIP-SFX [by Aeco Systems]]
pattern = 64 A1 ?? ?? ?? ?? 55 8B EC 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 A1 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 8B 0D
at = entrypoint
pattern.2 = 'PK' 03 04
at.2 = overlay
type = sfx
options = by Aeco Systems
author = hypn0
url = https://github.com/horsicq/Detect-It-Easy/blob/c9f58b9b8d1bd251c99e60565246092ff6920b1f/db/PE/custom_sfx_installers.1.sg


; ======================================================================
; Rules of Detect It Easy that were not converted or only partly
; (see docs/SIGNATURE-BACKLOG.md for the features they need)
; ======================================================================
;   packer_AlushPacker.2.sg (partial): getImportFunctionName(0, 0..4) positions and getNumberOfImports() > 2 dropped; the modified branch (pattern at the last section) is skipped, only weak checks remain without the positions [import-position]
;   packer_ASDPack.2.sg (partial): import-only branch (getNumberOfImports() === 1, getNumberOfSections() === 3, getImportLibraryName(0), isImportPositionHashPresent(0, 0x3651f68d)) skipped [import-count, import-hash, import-position, section-count]
;   packer_BatToExeConverter.2.sg (skipped): the EP patterns are the same as in Vbs To Exe Converter, only isImportPositionHashPresent(0, 0x72a2ca64 / 0x2afcef3f) tells them apart (policy 4) [import-hash]
;   packer_Fatpack.2.sg (partial): the detection (isImportPositionHashPresent(0, 0x74244911), one import, a section with FileSize 0) is dropped and only the FPACK resource / .fpack section payload variants are kept, the modified variants are skipped [import-count, import-hash, section-size]
;   packer_MEW.2.sg (partial): the SE 1.1-1.2 branch compareEP("E9......FF0C") has only 3 literal bytes and is skipped as too weak
;   packer_NsPack.2.sg (partial): the three import branches (getImportFunctionName(0, i) with getSizeOfCode(), the .NET GetSystemInfo branch, isImportPositionHashPresent with isNetObjectPresent("nsnet")) are skipped, the EP branches are converted [header-field, import-count, import-hash, import-position, section-size]
;   packer_Packer64.2.sg (skipped): EP pattern is the MSVC x64 CRT entry stub (matches clean System32 TSTheme.exe), only getNumbersOfImports() === 11 (script bug, meant getNumberOfImports) makes it specific [import-count]
;   packer_PolyEngine.2.sg (skipped): Generic x64 prologue EP plus the standard .CRT section; only getNumberOfImports() === 3 would make it specific [import-count]
;   packer_PyInstaller.2.sg (partial): Default icon branch (getResourceSizeByNumber + calculateMD5 of resource data, options custom/modified/packed) skipped, new-resource-hash = MD5 of resource data; Python version from getPythonVersionByDll dropped [new-resource-hash]
;   packer_ROPacker.2.sg (skipped): Without getSize() > 20971520 only the MinGW-w64 CRT EP stub and zlib1.dll remain, which match clean Git for Windows git.exe/curl.exe [file-size]
;   packer_Rusty.2.sg (skipped): Detection only by isImportPositionHashPresent and getNumberOfImports/getNumberOfResources; resource name STUB only sets the modified option [import-count, import-hash]
;   packer_troglodyte9.2.sg (skipped): Only section .pkr with hasFlags(0xE0000060); the short section name alone is not specific enough [section-flags]
;   packer_UPX.2.sg (partial): isPatchedUPX import heuristic skipped; version/compression options (getString, readByte at the UPX! header) dropped; version-string entries for '$Id: UPX ' and 'UPX!' in the first 0x400 bytes, the UPX! one requires 4 printable chars + 00 before it (stricter than DIE) [header-field, import-count, import-position, section-count, section-size]
;   packer_VbsToExeConverter.2.sg (skipped): the EP patterns are the same as in Bat To Exe Converter, only isImportPositionHashPresent(0, 0x182aac68) tells them apart (policy 4) [import-hash]
;   protector_AbyssMedia_ScriptCryptor.2.sg (skipped): Only the 4-char resource name AOPT remains besides isImportPositionHashPresent(0, 0xcf603a7d), getNumberOfImports() === 15 and getNumberOfExports(), too weak [import-hash]
;   protector_ACProtect.2.sg (partial): All 6 EP branches converted; skipped the else branch PE.section[".perplex"].hasFlags(0xE0000060) because the section name alone is too weak [section-flags]
;   protector_ActiveMark.2.sg (partial): Overlay branch converted; skipped the weak EP branch compareEP("8925........EB") with 3 literal bytes
;   protector_Alienyze.2.sg (partial): Kept the .alien variants without !getNumberOfImports(), getNumberOfSections() > 4 and getSectionFileOffset(0) == 0; skipped the modified variants where only the 55 8B EC prologue remains [import-count, section-count, section-size]
;   protector_Armadillo.2.sg (partial): All 7 EP branches converted; of the getMajorLinkerVersion() == 0x53 branch only the 'PDATA000' section start (6.X-9.X) is kept, linker version alone and section.length > 7 skipped [header-field]
;   protector_Arxan.2.sg (partial): GuardIT ~2013 EP branch converted; the GuardIT 12.0+/2014-2021 heuristic with getDisasmString and skipJumpsAndNops skipped [disassembly]
;   protector_ASProtect.2.sg (partial): Skipped the weak EP branches 1.1 BRS (60E9..05) and 1.2 (6801......C3) with fewer than 4 literal bytes; the other 17 EP branches converted
;   protector_bambam.2.sg (partial): branch with getNumberOfImports() === 0 and isImportPositionHashPresent skipped; modified option via section = !.bedrock [import-count, import-hash]
;   protector_DNGuard.2.sg (partial): Skipped the 32-bit 4.9+ branch (only isImportPositionHashPresent(0, 0x99f8b58e)); dropped isNetGlobalCctorPresent(), _getNumberOfResults and the import hash of the 64-bit branch [import-hash]
;   protector_EsProtect.2.sg (partial): Only the unmodified layout (sections Esp0, Esp1, .Esp!) with EP F9 converted; the modified variant relies only on getNumberOfSections and getEntryPointSection/getRelocsSection/getResourceSection/getImportSection [section-count, section-position]
;   protector_eXPressor.2.sg (partial): 1.5-1.6 branch skipped (EP 68........C3 with first section FileSize 0 and third section named .code) [section-position, section-size]
;   protector_Fish_PE.2.sg (partial): getNumberOfSections()==2 and section[0].FileSize==0 dropped; the 1.4 EP pattern (60b8........ffd05a, 5 literal bytes) is too weak without them and was skipped [section-count, section-size]
;   protector_GS60.2.sg (skipped): the EP pattern is the MSVC x64 CRT start stub; without getNumberOfImports()===14 and getNumberOfSections()===8 only it and isTLSPresent remain [import-count, section-count]
;   protector_HASP.2.sg (partial): branch with section[0].FileOffset/FileSize==0, getResourceSection()==1 and ProductName /manager/ (version from version info) skipped, the version info test alone is too generic [section-position, section-size]
;   protector_NetReactor.2.sg (partial): skipped the 2.0-2.1 branch (.reacto with section[1..3].FileSize==0) and the kernel32 branch that needs isNetGlobalCctorPresent; Anti-ILDASM option and the version carried over between .NET checks not reported [dotnet-cctor, section-size]
;   protector_NoobyProtect.2.sg (skipped): only check is that the section holding the imports is named SE (getImportSection), a 2 character section name alone is not specific [section-position]
;   protector_notcpuid.2.sg (partial): 1.X+ branch skipped (only the last section name .ptext would remain without Flags and getEntryPointSection); 1.0.5 kept with the EP pattern [section-flags, section-position]
;   protector_Obsidium.2.sg (partial): skipped the getDisasmNextAddress heuristic (1.4.X.X) and the generic branches (EP in last section, ANTS before the EP); lines 214/219 are unreachable in DIE after compareEP("EB") and were converted as intended; entries with fewer than 4 literal bytes and no other check dropped: Obsidium 1.0.0.59, Obsidium [disassembly, negative-anchor-offset, section-position]
;   protector_PE-Shield.2.sg (partial): skipped the isImportPositionHashPresent(0, 0x3651f68d) branch with section PESHiELD/ANAKiN98; "modified" option (two missing sections) omitted [import-hash]
;   protector_PELock.2.sg (skipped): getDisasmString instruction statistics, an import hash, and an EP pattern (6A6068........E8........BF94) that is the MSVC 7.x CRT prologue [disassembly, import-hash]
;   protector_Phoenix.2.sg (partial): skipped the compareEP_NET branch [dotnet-ep-il]
;   protector_Private_EXE_Protector.2.sg (partial): skipped the 1.X/1.7/2.X/2.00-2.25 branches (import counts and positions, section flags, EP offset) and the import hash branch with sections .TRIAL!/.-PEP- [header-field, import-count, import-hash, import-position, section-flags, section-position, section-size]
;   protector_Safengine_Shielden.2.sg (partial): E8........5361 branch skipped (only 3 literal EP bytes, last section FileSize/VirtualSize not expressible); versions read with getString after "Safengine Shielden v"/"Shielden v" dropped [section-position, section-size]
;   protector_SLVc0deProtector.2.sg (partial): 0.61 branch skipped: last section Flags == 0xA0000020, VirtualSize/FileSize low bytes and EP == last section VirtualAddress [section-flags, section-position, section-size]
;   protector_StarForce.2.sg (partial): else branch (.ps4 with a library imported by ordinal, getImportFunctionName/getNumberOfImportThunks) skipped; getPEFileVersion of the external protect.dll not read [import-count, import-position]
;   protector_Strongbit_EXECryptor.2.sg (partial): heuristic for 2.X/2.4X skipped (2 imports, MessageBoxA as the only function of the second, import section and empty preceding section); entries with fewer than 4 literal bytes and no other check dropped: Strongbit EXECryptor [import-count, import-position, section-count, section-position, section-size]
;   protector_Themida.2.sg (partial): isImportPositionHashPresent branches (1.XX-2.XX, ~2.XX, blank section names) and the detectThemida entropy/section layout heuristic skipped; DotNET option (_CorExeMain import) as extra entries [entropy, header-field, import-hash, section-count, section-position]
;   protector_Thinstall.2.sg (partial): 4.7.X branch skipped (overlay and PE.section[1].Name == ".res", the name alone is not distinctive); ThinAppVersion version info override not reproduced [section-position]
;   protector_UPolyX.2.sg (partial): weak 0.5 branch compareEP("EB01C3") (3 bytes) skipped, the other EP branches converted
;   protector_VbsToExe.1.sg (partial): branch with PE.resource["D"].Size == 14 and resources B, F, I, N, O skipped (resource size not expressible) [resource-type]
;   protector_VMProtect.2.sg (partial): section loop approximated with .vmp0/.vmp1 names; custom names (getSectionNameCollision), deep scan disassembly, import hash versions and the "packed" branch (two KERNEL32.dll imports) dropped [disassembly, import-position, section-name-collision]
;   protector_xObf.2.sg (skipped): only check is the last section .xObf with IsReadWriteExecute; without flags the section name alone is not specific enough [section-flags, section-position]
;   protector_Zprotect.2.sg (partial): kernel32.dll/VirtualAlloc at the start of section 1 kept without section count, empty first section and isDosStubPresent; EP section/entropy branch skipped [entropy, section-position]
;   protection_Denuvo.5.sg (partial): getNumberOfSections() > 10 dropped where the EP pattern, denuvo_atd or denuvo64.dll is specific; the 2.0a EP (4 literal bytes), the Steam/Epic/32-bit uPlay import branches and the _setResult("marker") export check are skipped [cross-detection, section-count]
;   protection_obfus_h.5.sg (partial): getCompilerVersion() !== "6.0" is not expressible: the export WhatSoundDoesACowMake is kept without it, the .obfh section regex alone is skipped [header-field]
;   cryptor_Amber.2.sg (partial): isImportPositionHashPresent(-1, 0x97c72051) dropped for the specific 32 bit EP; the 64 bit EP is the generic MinGW-w64 mainCRTStartup and is skipped [import-hash]
;   cryptor_Atyonekilla_Native-Cryptor.2.sg (skipped): Only getNumberOfImports() === 1 and isImportPositionHashPresent(0, 0x4d0979fc) [import-count, import-hash]
;   cryptor_XorCryptor.2.sg (skipped): Without the getNetAssemblyName() regex /^[A-Za-z]{10,31}$/ only LateIndexGet and generic reflection user strings remain, not specific [dotnet-assembly-name]
;   installer_DesktopX_Installer.1.sg (skipped): PE.resource[i].Type == 630/726/678/774 has no known type name; generic WinMain EP stub plus a PK resource is not specific [resource-type]
;   installer_Instalit.1.sg (partial): Only the DLLFILE (Type 854) branch kept as 7.10.11; EXEFILE/CFGFILE exist in both versions and only DIE's Type numbers (808/884 vs 640/686) tell them apart [resource-type]
;   installer_InstallShield.1.sg (partial): 3.X zip branch skipped (PE.compare at readByte(overlay)+overlay+12), 3.X magic searched in overlay[0xC-0x10C] instead, FileVersion version dropped; IS2 resource type from the DIE comment [computed-offset]
;   installer_Morton_installer.1.sg (skipped): without the resource type number 856 the checks are identical to the branch "1997 by Klever Co." of sfx_SZDD.1.sg [resource-type]
;   installer_Synactis_In-The-Box_Installer.1.sg (partial): 4.0 branch skipped (getAddressOfEntryPoint() == 0xA98B0 with only a Delphi EP and a 1 byte overlay check left) [header-field]
;   installer_Wise_Installer.1.sg (partial): Branch readDword(overlay+77) == getSize() skipped, getOverlaySize() > 80 dropped from the other branches [file-size]
;   sfx_ARJSFX.1.sg (partial): Branch 3 (resource with numeric Type == 1001 starting with 60EA, no type name in a comment) skipped; Type == 730 mapped to resource = ARJDATA by its comment [resource-type]
