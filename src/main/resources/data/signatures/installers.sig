; PortEx signature database: installers and archives in the overlay
; Format: see docs/SIGNATURES.md
; Converted from overlaysignatures of PortEx 5 by SignatureDbConverter

[PyInstaller]
pattern = 'PYZ'
at = overlay

[CreateInstall]
pattern = 'aWAW'
at = overlay

[7-zip Installer]
pattern = ';!@Install@!UTF-8!'
at = overlay

[ActiveMark protector]
pattern = 00 'TMSAMVOH'
at = overlay

[Actual Installer]
pattern = 'MSCF' 00
at = overlay + 0xA

[Adveractive Installer]
pattern = '10JP'
at = overlay

[Aeco Systems installer]
pattern = 'EWETAR  FILE!! VER 1.00 <<<>>>'
at = overlay

[ARJSFX32]
pattern = C0 AB ?? ?? ?? ?? 60 EA
at = overlay

[ARJ archive]
pattern = 60 EA
at = overlay

[ARQ archive]
pattern = 67 57 04 02
at = overlay

[AutoPlay Media Studio installer]
pattern = 0B 0B AF AF 0B 0B A4
at = overlay

[ClickTeam installer]
pattern = 'wwgT)'
at = overlay

[ClickTeam installer]
pattern = 12 01 00 ?? ?? 00 00
at = overlay + 0x1

[CrypKey Installer archive]
pattern = 'CK16'
at = overlay

[Dimd SFX , CAB]
pattern = 'DIMDMSCF'
at = overlay + 0x4

[distutils installer]
pattern = '[meta]'
at = overlay

[Envoy Packager]
pattern = B2 97 E1 69
at = overlay

[Eschalon Installer archive, SPIS LH5]
pattern = 'EPSF'
at = overlay

[GPInstall]
pattern = 'SPIS' 1A 'LH5'
at = overlay + 0x4

[GZip archive]
pattern = 1F 8B 08
at = overlay

[Inno Setup Installer]
pattern = 'zlb' 1A
at = overlay

[Inno Setup Installer]
pattern = 'idska32' 1A
at = overlay

[Inno Setup Uninstall]
pattern = 'Inno Setup Messages'
at = overlay

[Inno Setup Installer with Stub]
pattern = 'Inno'
at = overlay + 0x34

[zlib archive]
pattern = 78 DA
at = overlay

[LucasArts Update Installer]
pattern = '1CNT'
at = overlay

[MP-ZipTool SFX32]
pattern = 'MPU' 0D
at = overlay

[MPQ archive]
pattern = 'MPQ' 1A 20
at = overlay

[NOS Installer]
pattern = 'PK' ?? ?? 'NOS_PO'
at = overlay

[NOS Installer]
pattern = 'NOS_PO'
at = overlay

[Pantaray QSetup 10.x]
pattern = 97 03 00 00 02 01
at = overlay

[Pantaray QSetup 11.x]
pattern = 37 07 00 00 02 01
at = overlay

[Paquet archive]
pattern = 04 'PBG'
at = overlay

[QT installer data]
pattern = 'qres'
at = overlay

[RTPatch archive]
pattern = 4B 2A 9A
at = overlay

[RTPatch archive]
pattern = 4B 2A 84
at = overlay

[Setup Factory installer 8.x/9.x]
pattern = E0 E0 E1 E1 E2 E2 E3 E3 E4 E4 E5 E5 E6 E6 E7 E7
at = overlay

[Setup Factory installer 4.x/5.x]
pattern = E0 E1 E2 E3 E4 E5 E6
at = overlay

[STATICSUP installer]
pattern = 67 15 52 34 FF 4D 36 42
at = overlay

[Vise Installer]
pattern = 'ESIV'
at = overlay

[WinImage SFX]
pattern = 'RsDl'
at = overlay

[IMP archive]
pattern = 'IMP' 0A
at = overlay

[WinPatch Apply Program]
pattern = '@Daisy@Lucy@xyzzy@' ?? ?? ?? ?? ?? ?? ?? ?? 1F 8B 08
at = overlay

[WinRAR Installer]
pattern = '***messages***'
at = overlay

[RAR archive]
pattern = 'Rar!'
at = overlay

[ZipCentral SFX-32]
pattern = 'MPV*'
at = overlay

[PCInstall]
pattern = '[20/20]'
at = overlay

[InstallShield 18.x]
pattern = 'ISSetupStream'
at = overlay

[Adobe Flash]
pattern = 'FWS'
at = overlay

[Adobe Flash]
pattern = 'CWS'
at = overlay

[Smart Install Maker]
pattern = 'Smart Install Maker v'
at = overlay

[PackageForTheWeb, InstallShield]
pattern = 00 00 DC ED BD
at = overlay + 0x2

[Microsoft Compound]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay

[Autodesk Self-Extract]
pattern = '00000000000000BD00000000000000010000000000000001'
at = overlay + 0x19A0

[Ghost Installer archive, xored MSCF, mask: 8D]
pattern = C0 DE CE CD 8D 8D 8D 8D
at = overlay

[CreateInstall 2003.3.5]
pattern = 02 06 0A 04 05 FD 59
at = overlay

[VMWare Installation Launcher]
pattern = 'RWMV'
at = overlay

[Codegear Installer]
pattern = 'GRCSETUPINFORMATION'
at = overlay + 0x4

[Spoon Studio]
pattern = 'xvm' 00 03
at = overlay

[Advanced Installer, MS Compound-like format]
pattern = 2F 30 EE 1F 5E 4E E5 1E
at = overlay

[Adobe SVG Installer, gzip]
pattern = '^OPT'
at = overlay

[Chilkat ZIP Self-Extractor]
pattern = 07 D2 6C BF 21 59 AB AA 01 00 00 00 00
at = overlay

[Dolphin Virtual Machine, 5.0]
pattern = 'IST' 00
at = overlay

[CodeFusion Wizard]
pattern = '@._P-DATA_.@'
at = overlay

[avast! Antivirus installer]
pattern = 'ASWsetupFPkgFil3'
at = overlay

[zlib]
pattern = 78 9C
at = overlay

[InstallAnywhere, zip]
pattern = 5B 3E
at = overlay

[NSIS]
pattern = EF BE AD DE 'Null' ?? 'oftInst'
at = overlay + 0x4

[NSIS]
pattern = EF BE AD DE 'Null' ?? 'oftInst'
at = overlay

[Internet Download Manager Installer]
pattern = FE C1 CD 66 6E BC CF 01 FE C1 CD 66 6E BC CF 01 00 ?? ?? ?? ?? ?? ?? ?? 78 DA
at = overlay + 0x8

[Install4j installer]
pattern = D5 13 E4 E8 01 00 00 00
at = overlay

[7-zip Installer]
pattern = EF BB BF ';!@Install@!UTF-8!'
at = overlay

[Sony Windows installer]
pattern = 'UM' 03 0A 00
at = overlay

[ADS Self Extractor]
pattern = 7B 00 32 00 30 00 37 00 32 00 36 00 33 00 37 00 37 00 2D 00
in = overlay[0x0-0x100]

[CChaos Software Installer]
pattern = 27 63 27 63 12 26 09 75 13 18 01 78
at = overlay

[Gentee Installer]
pattern = 'OWS9G1'
at = overlay + 0xB

[Squeez SFX]
pattern = 'SQ5SFX'
at = overlay

[Inno Setup]
pattern = 'Inno Setup Setup Data'
at = overlay

[CAB archive, possibly InstallShield]
pattern = 'MSCF'
in = overlay[0x0-0x100]

[InstallShield archive]
pattern = 'ISc('
in = overlay[0x0-0x100]

[Excelsior Installer]
pattern = 'ExcelsiorII1'
at = overlay

[InstallShield 2.x-3.x]
pattern = 'InstallShield' 00
at = overlay

[Multimedia Fusion Installer]
pattern = 'wwwwI' 87 47 12
at = overlay

[BZIP2]
pattern = 'BZh'
at = overlay

[PIMP Installer]
pattern = 'PIMPFILE' 00
at = overlay

[Tarma Installer, zlib]
pattern = 'tiz1' ?? ?? ?? ?? 78 DA
at = overlay

[InnoSetup]
pattern = 'InUn'
at = msdos_header + 0x30
type = installer

[PyInstaller archive string]
pattern = 'PyInstaller archive'
in = section(.rdata)[0-0x1500]
type = installer

