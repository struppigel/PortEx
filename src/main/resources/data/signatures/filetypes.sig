; PortEx signature database: file type magic numbers in the overlay, resources and at the file start
; Format: see docs/SIGNATURES.md
; Converted from customsigs_GCK.txt of PortEx 5 by SignatureDbConverter

[JPEG2000 image files]
pattern = 00 00 00 0C 6A 50 20 20
at = overlay, resource, file
extensions = JP2

[3GPP multimedia files]
pattern = 00 00 00 14 66 74 79 70
at = overlay, resource, file
extensions = 3GP

[MPEG-4 v1]
pattern = 00 00 00 14 66 74 79 70 69 73 6F 6D
at = overlay, resource, file
extensions = MP4

[MPEG-4 video_1]
pattern = 00 00 00 18 66 74 79 70
at = overlay, resource, file
extensions = 3GP5, M4V, MP4

[MPEG-4 video_2]
pattern = 00 00 00 1C 66 74 79 70
at = overlay, resource, file
extensions = MP4

[3GPP2 multimedia files]
pattern = 00 00 00 20 66 74 79 70
at = overlay, resource, file
extensions = 3GP

[Apple audio and video]
pattern = 00 00 00 20 66 74 79 70 4D 34 41
at = overlay, resource, file
extensions = M4A

[Windows icon|printer spool file]
pattern = 00 00 01 00
at = overlay, resource, file
extensions = ICO, SPL

[MPEG video file]
pattern = 00 00 01 B3
at = overlay, resource, file
extensions = MPG

[DVD video file]
pattern = 00 00 01 BA
at = overlay, resource, file
extensions = MPG, VOB

[Windows cursor]
pattern = 00 00 02 00
at = overlay, resource, file
extensions = CUR

[QuattroPro spreadsheet]
pattern = 00 00 02 00
at = overlay, resource, file
extensions = WB2

[Lotus 1-2-3 (v1)]
pattern = 00 00 02 00 06 04 06 00
at = overlay, resource, file
extensions = WK1

[Lotus 1-2-3 (v3)]
pattern = 00 00 1A 00 00 10 04 00
at = overlay, resource, file
extensions = WK3

[Lotus 1-2-3 (v4|v5)]
pattern = 00 00 1A 00 02 10 04 00
at = overlay, resource, file
extensions = WK4, WK5

[Lotus 1-2-3 (v9)]
pattern = 00 00 1A 00 05 10 04
at = overlay, resource, file
extensions = 123

[Quark Express (Intel)]
pattern = 00 00 49 49 58 50 52
at = overlay, resource, file
extensions = QXD

[Quark Express (Motorola)]
pattern = 00 00 4D 4D 58 50 52
at = overlay, resource, file
extensions = QXD

[TrueType font file]
pattern = 00 01 00 00 00
at = overlay, resource, file
extensions = TTF

[Microsoft Money file]
pattern = 00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65
at = overlay, resource, file
extensions = MNY

[Microsoft Access 2007]
pattern = 00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42
at = overlay, resource, file
extensions = ACCDB

[Microsoft Access]
pattern = 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42
at = overlay, resource, file
extensions = MDB

[Palm Address Book Archive]
pattern = 00 01 42 41
at = overlay, resource, file
extensions = ABA

[Palm DateBook Archive]
pattern = 00 01 42 44
at = overlay, resource, file
extensions = DBA

[Netscape Navigator (v4) database]
pattern = 00 06 15 61 00 00 00 02 00 00 04 D2 00 00 10 00
at = overlay, resource, file
extensions = DB

[Mbox table of contents file]
pattern = 00 0D BB A0
at = overlay, resource, file

[BIOS details in RAM]
pattern = 00 14 00 00 01 02
at = overlay, resource, file

[Netscape Communicator (v4) mail folder]
pattern = 00 1E 84 90 00 00 00 00
at = overlay, resource, file
extensions = SNM

[Firebird and Interbase database files]
pattern = 01 00 39 30
at = overlay, resource, file
extensions = FDB, GDB

[SQL Data Base]
pattern = 01 0F 00 00
at = overlay, resource, file
extensions = MDF

[Silicon Graphics RGB Bitmap]
pattern = 01 DA 01 01 00 03
at = overlay, resource, file
extensions = RGB

[Micrografx vector graphic file]
pattern = 01 FF 02 04 03 02
at = overlay, resource, file
extensions = DRW

[Digital Speech Standard file]
pattern = 02 64 73 73
at = overlay, resource, file
extensions = DSS

[Nuitka resource]
pattern = 4B 41 59
at = overlay, resource, file
extensions = NUI

[Quicken price history]
pattern = 03 00 00 00
at = overlay, resource, file
extensions = QPH

[Approach index file]
pattern = 03 00 00 00 41 50 50 52
at = overlay, resource, file
extensions = ADX

[INFO2 Windows recycle bin_1]
pattern = 04 00 00 00
at = overlay, resource, file

[INFO2 Windows recycle bin_2]
pattern = 05 00 00 00
at = overlay, resource, file

[SkinCrafter skin]
pattern = 07 53 4B 46
at = overlay, resource, file
extensions = SKF

[DesignTools 2D Design file]
pattern = 07 64 74 32 64 64 74 64
at = overlay, resource, file
extensions = DTD

[ZSOFT Paintbrush file_1]
pattern = 0A 02 01 01
at = overlay, resource, file
extensions = PCX

[ZSOFT Paintbrush file_2]
pattern = 0A 03 01 01
at = overlay, resource, file
extensions = PCX

[ZSOFT Paintbrush file_3]
pattern = 0A 05 01 01
at = overlay, resource, file
extensions = PCX

[MultiBit Bitcoin wallet file]
pattern = 0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72
at = overlay, resource, file
extensions = WALLET

[Google Chrome extension archive]
pattern = 43 72 32 34
at = overlay, resource, file
extensions = CRX

[DeskMate Document]
pattern = 0D 44 4F 43
at = overlay, resource, file
extensions = DOC

[Nero CD compilation]
pattern = 0E 4E 65 72 6F 49 53 4F
at = overlay, resource, file
extensions = NRI

[DeskMate Worksheet]
pattern = 0E 57 4B 53
at = overlay, resource, file
extensions = WKS

[Easy CD Creator 5 Layout file]
pattern = 10 00 00 00
at = overlay, resource, file
extensions = CL5

[Windows prefetch file]
pattern = 11 00 00 00 53 43 43 41
at = overlay, resource, file
extensions = PF

[Lotus Notes database template]
pattern = 1A 00 00
at = overlay, resource, file
extensions = NTF

[Lotus Notes database]
pattern = 1A 00 00 04 00 00
at = overlay, resource, file
extensions = NSF

[WinPharoah capture file]
pattern = 1A 35 01 00
at = overlay, resource, file
extensions = ETH

[WebM video file]
pattern = 1A 45 DF A3
at = overlay, resource, file
extensions = WEBM

[Matroska stream file]
pattern = 1A 45 DF A3 93 42 82 88
at = overlay, resource, file
extensions = MKV

[Runtime Software disk image]
pattern = 1A 52 54 53 20 43 4F 4D
at = overlay, resource, file
extensions = DAT

[GZIP archive file]
pattern = 1F 8B 08
at = overlay, resource, file
extensions = GZ

[VLC Player Skin file]
pattern = 1F 8B 08
at = overlay, resource, file
extensions = VLT

[Compressed tape archive_1]
pattern = 1F 9D 90
at = overlay, resource, file
extensions = TAR.Z

[Unix archiver (ar)|MS Program Library Common Object File Format (COFF)]
pattern = 21 3C 61 72 63 68 3E 0A
at = overlay, resource, file
extensions = LIB

[VMware 4 Virtual Disk description]
pattern = 23 20 44 69 73 6B 20 44
at = overlay, resource, file
extensions = VMDK

[MS Developer Studio project file]
pattern = 23 20 4D 69 63 72 6F 73
at = overlay, resource, file
extensions = DSP

[Adaptive Multi-Rate ACELP Codec (GSM)]
pattern = 23 21 41 4D 52
at = overlay, resource, file
extensions = AMR

[Radiance High Dynamic Range image file]
pattern = 23 3F 52 41 44 49 41 4E
at = overlay, resource, file
extensions = HDR

[SPSS Data file]
pattern = 24 46 4C 32 40 28 23 29
at = overlay, resource, file
extensions = SAV

[Encapsulated PostScript file]
pattern = 25 21 50 53 2D 41 64 6F
at = overlay, resource, file
extensions = EPS

[PDF file]
pattern = 25 50 44 46
at = overlay, resource, file
extensions = PDF, FDF

[Fuzzy bitmap (FBM) file]
pattern = 25 62 69 74 6D 61 70
at = overlay, resource, file
extensions = FBM

[BinHex 4 Compressed Archive]
pattern = 28 54 68 69 73 20 66 69
at = overlay, resource, file
extensions = HQX

[Symantec Wise Installer log]
pattern = 2A 2A 2A 20 20 49 6E 73
at = overlay, resource, file
extensions = LOG

[RealPlayer video file (V11+)]
pattern = 2E 52 45 43
at = overlay, resource, file
extensions = IVR

[RealMedia streaming media]
pattern = 2E 52 4D 46
at = overlay, resource, file
extensions = RM, RMVB

[RealAudio file]
pattern = 2E 52 4D 46 00 00 00 12
at = overlay, resource, file
extensions = RA

[RealAudio streaming media]
pattern = 2E 72 61 FD 00
at = overlay, resource, file
extensions = RA

[NeXT|Sun Microsystems audio file]
pattern = 2E 73 6E 64
at = overlay, resource, file
extensions = AU

[Thunderbird|Mozilla Mail Summary File]
pattern = 2F 2F 20 3C 21 2D 2D 20 3C 6D 64 62 3A 6D 6F 72 6B 3A 7A
at = overlay, resource, file
extensions = MSF

[Windows Event Viewer file]
pattern = 30 00 00 00 4C 66 4C 65
at = overlay, resource, file
extensions = EVT

[Windows Media Audio|Video File]
pattern = 30 26 B2 75 8E 66 CF 11
at = overlay, resource, file
extensions = ASF, WMA, WMV

[National Transfer Format Map]
pattern = 30 31 4F 52 44 4E 41 4E
at = overlay, resource, file
extensions = NTF

[cpio archive]
pattern = 30 37 30 37 30
at = overlay, resource, file

[Tcpdump capture file]
pattern = 34 CD B2 A1
at = overlay, resource, file

[7-Zip compressed file]
pattern = 37 7A BC AF 27 1C
at = overlay, resource, file
extensions = 7Z

[zisofs compressed file]
pattern = 37 E4 53 96 C9 DB D6 07
at = overlay, resource, file

[Photoshop image]
pattern = 38 42 50 53
at = overlay, resource, file
extensions = PSD

[Surfplan kite project file]
pattern = 3A 56 45 52 53 49 4F 4E
at = overlay, resource, file
extensions = SLE

[AOL HTML mail]
pattern = 3C 21 64 6F 63 74 79 70
at = overlay, resource, file
extensions = DCI

[Windows Visual Stylesheet]
pattern = 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D
at = overlay, resource, file
extensions = MANIFEST

[User Interface Language]
pattern = 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E
at = overlay, resource, file
extensions = XML

[MMC Snap-in Control file]
pattern = 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E 0D 0A 3C 4D 4D 43 5F 43 6F 6E 73 6F 6C 65 46 69 6C 65 20 43 6F 6E 73 6F 6C 65 56 65 72 73 69 6F 6E 3D 22
at = overlay, resource, file
extensions = MSC

[Adobe FrameMaker]
pattern = 3C 4D 61 6B 65 72 46 69
at = overlay, resource, file
extensions = FM, MIF

[BASE85 file]
pattern = 3C 7E 36 3C 5C 25 5F 30 67 53 71 68 3B
at = overlay, resource, file
extensions = B85

[Windows Help file_2]
pattern = 3F 5F 03 00
at = overlay, resource, file
extensions = GID, HLP

[Generic AutoCAD drawing]
pattern = 41 43 31 30
at = overlay, resource, file
extensions = DWG

[Steganos virtual secure drive]
pattern = 41 43 76
at = overlay, resource, file
extensions = SLE

[AOL parameter|info files]
pattern = 41 43 53 44
at = overlay, resource, file

[Harvard Graphics symbol graphic]
pattern = 41 4D 59 4F
at = overlay, resource, file
extensions = SYW

[AOL config files]
pattern = 41 4F 4C
at = overlay, resource, file
extensions = ABI, ABY, BAG, IDX, IND, PFC

[AOL and AIM buddy list]
pattern = 41 4F 4C 20 46 65 65 64
at = overlay, resource, file
extensions = BAG

[AOL address book]
pattern = 41 4F 4C 44 42
at = overlay, resource, file
extensions = ABY

[AOL user configuration]
pattern = 41 4F 4C 44 42
at = overlay, resource, file
extensions = IDX

[AOL client preferences|settings file]
pattern = 41 4F 4C 49 44 58
at = overlay, resource, file
extensions = IND

[AOL address book index]
pattern = 41 4F 4C 49 4E 44 45 58
at = overlay, resource, file
extensions = ABI

[AOL personal file cabinet]
pattern = 41 4F 4C 56 4D 31 30 30
at = overlay, resource, file
extensions = ORG, PFC

[AVG6 Integrity database]
pattern = 41 56 47 36 5F 49 6E 74
at = overlay, resource, file
extensions = DAT

[FreeArc compressed file]
pattern = 41 72 43 01
at = overlay, resource, file
extensions = ARC

[NTFS MFT (BAAD)]
pattern = 42 41 41 44
at = overlay, resource, file

[vCard]
pattern = 42 45 47 49 4E 3A 56 43
at = overlay, resource, file
extensions = VCF

[Speedtouch router firmware]
pattern = 42 4C 49 32 32 33
at = overlay, resource, file
extensions = BIN, BLI, RBI

[Palmpilot resource file]
pattern = 42 4F 4F 4B 4D 4F 42 49
at = overlay, resource, file
extensions = PRC

[bzip2 compressed archive]
pattern = 42 5A 68
at = overlay, resource, file
extensions = BZ2, TAR.BZ2, TBZ2, TB2

[Puffer ASCII encrypted archive]
pattern = 42 65 67 69 6E 20 50 75 66 66 65 72
at = overlay, resource, file
extensions = APUF

[Blink compressed archive]
pattern = 42 6C 69 6E 6B
at = overlay, resource, file
extensions = BLI

[RagTime document]
pattern = 43 23 2B 44 A4 43 4D A5
at = overlay, resource, file
extensions = RTD

[WordPerfect dictionary]
pattern = 43 42 46 49 4C 45
at = overlay, resource, file
extensions = CBD

[ISO-9660 CD Disc Image]
pattern = 43 44 30 30 31
at = overlay, resource, file
extensions = ISO

[Compressed ISO CD image]
pattern = 43 49 53 4F
at = overlay, resource, file
extensions = CSO

[Corel Binary metafile]
pattern = 43 4D 58 31
at = overlay, resource, file
extensions = CLB

[COM+ Catalog]
pattern = 43 4F 4D 2B
at = overlay, resource, file
extensions = CLB

[VMware 3 Virtual Disk]
pattern = 43 4F 57 44
at = overlay, resource, file
extensions = VMDK

[Corel Photopaint file_1]
pattern = 43 50 54 37 46 49 4C 45
at = overlay, resource, file
extensions = CPT

[Corel Photopaint file_2]
pattern = 43 50 54 46 49 4C 45
at = overlay, resource, file
extensions = CPT

[Win9x registry hive]
pattern = 43 52 45 47
at = overlay, resource, file
extensions = DAT

[Crush compressed archive]
pattern = 43 52 55 53 48 20 76
at = overlay, resource, file
extensions = CRU

[Shockwave Flash file]
pattern = 43 57 53
at = overlay, resource, file
extensions = SWF

[Calculux Indoor lighting project file]
pattern = 43 61 6C 63 75 6C 75 78 20 49 6E 64 6F 6F 72 20
at = overlay, resource, file
extensions = CIN

[WhereIsIt Catalog]
pattern = 43 61 74 61 6C 6F 67 20
at = overlay, resource, file
extensions = CTF

[IE History file]
pattern = 43 6C 69 65 6E 74 20 55
at = overlay, resource, file
extensions = DAT

[DAX Compressed CD image]
pattern = 44 41 58 00
at = overlay, resource, file
extensions = DAX

[Palm Zire photo database]
pattern = 44 42 46 48
at = overlay, resource, file
extensions = DB

[Amiga DiskMasher compressed archive]
pattern = 44 4D 53 21
at = overlay, resource, file
extensions = DMS

[Amiga disk file]
pattern = 44 4F 53
at = overlay, resource, file
extensions = ADF

[DVR-Studio stream file]
pattern = 44 56 44
at = overlay, resource, file
extensions = DVR

[DVD info file]
pattern = 44 56 44
at = overlay, resource, file
extensions = IFO

[Elite Plus Commander game file]
pattern = 45 4C 49 54 45 20 43 6F
at = overlay, resource, file
extensions = CDR

[VideoVCD|VCDImager file]
pattern = 45 4E 54 52 59 56 43 44
at = overlay, resource, file
extensions = VCD

[EasyRecovery Saved State file]
pattern = 45 52 46 53 53 41 56 45
at = overlay, resource, file
extensions = DAT

[Expert Witness Compression Format]
pattern = 45 56 46 09 0D 0A FF 00
at = overlay, resource, file
extensions = E01

[EnCase Evidence File Format V2]
pattern = 45 56 46 32 0D 0A 81
at = overlay, resource, file
extensions = Ex01

[Windows Vista event log]
pattern = 45 6C 66 46 69 6C 65 00
at = overlay, resource, file
extensions = EVTX

[QuickBooks backup]
pattern = 45 86 00 00 06 00
at = overlay, resource, file
extensions = QBB

[MS Fax Cover Sheet]
pattern = 46 41 58 43 4F 56 45 52
at = overlay, resource, file
extensions = CPE

[Fiasco database definition file]
pattern = 46 44 42 48 00
at = overlay, resource, file
extensions = FDB

[NTFS MFT (FILE)]
pattern = 46 49 4C 45
at = overlay, resource, file

[Flash video file]
pattern = 46 4C 56
at = overlay, resource, file
extensions = FLV

[Audio Interchange File]
pattern = 46 4F 52 4D 00
at = overlay, resource, file
extensions = AIFF

[DAKX Compressed Audio]
pattern = 46 4F 52 4D 00
at = overlay, resource, file
extensions = DAX

[Shockwave Flash player]
pattern = 46 57 53
at = overlay, resource, file
extensions = SWF

[Generic e-mail_2]
pattern = 46 72 6F 6D
at = overlay, resource, file
extensions = EML

[GIF file]
pattern = 47 49 46 38
at = overlay, resource, file
extensions = GIF

[GIMP pattern file]
pattern = 47 50 41 54
at = overlay, resource, file
extensions = PAT

[Show Partner graphics file]
pattern = 47 58 32
at = overlay, resource, file
extensions = GX2

[Genetec video archive]
pattern = 47 65 6E 65 74 65 63 20 4F 6D 6E 69 63 61 73 74
at = overlay, resource, file
extensions = G64

[SAS Transport dataset]
pattern = 48 45 41 44 45 52 20 52 45 43 4F 52 44 2A 2A 2A
at = overlay, resource, file
extensions = XPT

[Harvard Graphics presentation file]
pattern = 48 48 47 42 31
at = overlay, resource, file
extensions = SH3

[TIFF file_1]
pattern = 49 20 49
at = overlay, resource, file
extensions = TIF, TIFF

[MP3 audio file]
pattern = 49 44 33
at = overlay, resource, file
extensions = MP3

[Sprint Music Store audio]
pattern = 49 44 33 03 00 00 00
at = overlay, resource, file
extensions = KOZ

[Canon RAW file]
pattern = 49 49 1A 00 00 00 48 45
at = overlay, resource, file
extensions = CRW

[TIFF file_2]
pattern = 49 49 2A 00
at = overlay, resource, file
extensions = TIF, TIFF

[Install Shield compressed file]
pattern = 49 53 63 28
at = overlay, resource, file
extensions = CAB, HDR

[MS Reader eBook]
pattern = 49 54 4F 4C 49 54 4C 53
at = overlay, resource, file
extensions = LIT

[MS Compiled HTML Help File]
pattern = 49 54 53 46
at = overlay, resource, file
extensions = CHI, CHM

[Inno Setup Uninstall Log]
pattern = 49 6E 6E 6F 20 53 65 74
at = overlay, resource, file
extensions = DAT

[Inter@ctive Pager Backup (BlackBerry file]
pattern = 49 6E 74 65 72 40 63 74 69 76 65 20 50 61 67 65
at = overlay, resource, file
extensions = IPD

[JARCS compressed archive]
pattern = 4A 41 52 43 53 00
at = overlay, resource, file
extensions = JAR

[AOL ART file_1]
pattern = 4A 47 03 0E
at = overlay, resource, file
extensions = JG

[AOL ART file_2]
pattern = 4A 47 04 0E
at = overlay, resource, file
extensions = JG

[VMware 4 Virtual Disk]
pattern = 4B 44 4D
at = overlay, resource, file
extensions = VMDK

[KGB archive]
pattern = 4B 47 42 5F 61 72 63 68
at = overlay, resource, file
extensions = KGB

[Win9x printer spool file]
pattern = 4B 49 00 00
at = overlay, resource, file
extensions = SHD

[KWAJ (compressed) file]
pattern = 4B 57 41 4A 88 F0 27 D1
at = overlay, resource, file

[Windows shortcut file]
pattern = 4C 00 00 00 01 14 02 00
at = overlay, resource, file
extensions = LNK

[Windows help file_3]
pattern = 4C 4E 02 00
at = overlay, resource, file
extensions = GID, HLP

[Logical File Evidence Format]
pattern = 4C 56 46 09 0D 0A FF 00
at = overlay, resource, file
extensions = E01

[Merriam-Webster Pocket Dictionary]
pattern = 4D 2D 57 20 50 6F 63 6B
at = overlay, resource, file
extensions = PDB

[Microsoft|MSN MARC archive]
pattern = 4D 41 52 43
at = overlay, resource, file
extensions = MAR

[MAr compressed archive]
pattern = 4D 41 72 30 00
at = overlay, resource, file
extensions = MAR

[TargetExpress target file]
pattern = 4D 43 57 20 54 65 63 68 6E 6F 67 6F 6C 69 65 73
at = overlay, resource, file
extensions = MTE

[Windows dump file]
pattern = 4D 44 4D 50 93 A7
at = overlay, resource, file
extensions = DMP, HDMP

[Milestones project management file]
pattern = 4D 49 4C 45 53
at = overlay, resource, file
extensions = MLS

[Skype localization data file]
pattern = 4D 4C 53 57
at = overlay, resource, file
extensions = MLS

[TIFF file_3]
pattern = 4D 4D 00 2A
at = overlay, resource, file
extensions = TIF, TIFF

[TIFF file_4]
pattern = 4D 4D 00 2B
at = overlay, resource, file
extensions = TIF, TIFF

[Yamaha Synthetic music Mobile Application Format]
pattern = 4D 4D 4D 44 00 00
at = overlay, resource, file
extensions = MMF

[VMware BIOS state file]
pattern = 4D 52 56 4E
at = overlay, resource, file
extensions = NVRAM

[Microsoft cabinet file]
pattern = 4D 53 43 46
at = overlay, resource, file
extensions = CAB

[Powerpoint Packaged Presentation]
pattern = 4D 53 43 46
at = overlay, resource, file
extensions = PPZ

[MS Access Snapshot Viewer file]
pattern = 4D 53 43 46
at = overlay, resource, file
extensions = SNP

[OLE|SPSS|Visual C++ library file]
pattern = 4D 53 46 54 02 00 01 00
at = overlay, resource, file
extensions = TLB

[Microsoft Windows Imaging Format]
pattern = 4D 53 57 49 4D
at = overlay, resource, file
extensions = WIM

[Sony Compressed Voice File]
pattern = 4D 53 5F 56 4F 49 43 45
at = overlay, resource, file
extensions = CDR, DVF, MSV

[MIDI sound file]
pattern = 4D 54 68 64
at = overlay, resource, file
extensions = MID, MIDI

[Milestones project management file_1]
pattern = 4D 56 32 31 34
at = overlay, resource, file
extensions = MLS

[Milestones project management file_2]
pattern = 4D 56 32 43
at = overlay, resource, file
extensions = MLS

[MS-DOS or Portable Executable]
pattern = 4D 5A
at = overlay, resource, file
extensions = COM, DLL, DRV, EXE, PIF, QTS, QTX, SYS

[MS C++ debugging symbols file]
pattern = 4D 69 63 72 6F 73 6F 66 74 20 43 2F 43 2B 2B 20
at = overlay, resource, file
extensions = PDB

[Visual Studio .NET file]
pattern = 4D 69 63 72 6F 73 6F 66 74 20 56 69 73 75 61 6C
at = overlay, resource, file
extensions = SLN

[VMapSource GPS Waypoint Database]
pattern = 4D 73 52 63 66
at = overlay, resource, file
extensions = GDB

[TomTom traffic data]
pattern = 4E 41 56 54 52 41 46 46
at = overlay, resource, file
extensions = DAT

[MS Windows journal]
pattern = 4E 42 2A 00
at = overlay, resource, file
extensions = JNT, JTP

[NES Sound file]
pattern = 4E 45 53 4D 1A 01
at = overlay, resource, file
extensions = NSF

[National Imagery Transmission Format file]
pattern = 4E 49 54 46 30
at = overlay, resource, file
extensions = NTF

[Agent newsreader character map]
pattern = 4E 61 6D 65 3A 20
at = overlay, resource, file
extensions = COD

[1Password 4 Cloud Keychain]
pattern = 4F 50 43 4C 44 41 54
at = overlay, resource, file
extensions = attachment

[Psion Series 3 Database]
pattern = 4F 50 4C 44 61 74 61 62
at = overlay, resource, file
extensions = DBF

[Ogg Vorbis Codec compressed file]
pattern = 4F 67 67 53 00 02 00 00
at = overlay, resource, file
extensions = OGA, OGG, OGV, OGX

[Quicken QuickFinder Information File]
pattern = 50 00 00 00 20 00 00 00
at = overlay, resource, file
extensions = IDX

[Portable Graymap Graphic]
pattern = 50 35 0A
at = overlay, resource, file
extensions = PGM

[Quake archive file]
pattern = 50 41 43 4B
at = overlay, resource, file
extensions = PAK

[Windows memory dump]
pattern = 50 41 47 45 44 55
at = overlay, resource, file
extensions = DMP

[PAX password protected bitmap]
pattern = 50 41 58
at = overlay, resource, file
extensions = PAX

[PestPatrol data|scan strings]
pattern = 50 45 53 54
at = overlay, resource, file
extensions = DAT

[PGP disk image]
pattern = 50 47 50 64 4D 41 49 4E
at = overlay, resource, file
extensions = PGD

[ChromaGraph Graphics Card Bitmap]
pattern = 50 49 43 54 00 08
at = overlay, resource, file
extensions = IMG

[PKZIP archive_1]
pattern = 50 4B 03 04
at = overlay, resource, file
extensions = ZIP

[PKZIP archive_2]
pattern = 50 4B 05 06
at = overlay, resource, file
extensions = ZIP

[PKZIP archive_3]
pattern = 50 4B 07 08
at = overlay, resource, file
extensions = ZIP

[Windows Program Manager group file]
pattern = 50 4D 43 43
at = overlay, resource, file
extensions = GRP

[Norton Disk Doctor undo file]
pattern = 50 4E 43 49 55 4E 44 4F
at = overlay, resource, file
extensions = DAT

[Microsoft Windows User State Migration Tool]
pattern = 50 4D 4F 43 43 4D 4F 43
at = overlay, resource, file
extensions = PMOCCMOC

[Puffer encrypted archive]
pattern = 50 55 46 58
at = overlay, resource, file
extensions = PUF

[Qcow Disk Image]
pattern = 51 46 49
at = overlay, resource, file
extensions = QEMU

[Quicken data file]
pattern = 51 57 20 56 65 72 2E 20
at = overlay, resource, file
extensions = ABD, QSD

[Shareaza (P2P) thumbnail]
pattern = 52 41 5A 41 54 44 42 31
at = overlay, resource, file
extensions = DAT

[WinNT Registry|Registry Undo files]
pattern = 52 45 47 45 44 49 54
at = overlay, resource, file
extensions = REG, SUD

[Antenna data file]
pattern = 52 45 56 4E 55 4D 3A 2C
at = overlay, resource, file
extensions = AD

[Windows animated cursor]
pattern = 52 49 46 46
at = overlay, resource, file
extensions = ANI

[Corel Presentation Exchange metadata]
pattern = 52 49 46 46
at = overlay, resource, file
extensions = CMX

[CorelDraw document]
pattern = 52 49 46 46
at = overlay, resource, file
extensions = CDR

[Video CD MPEG movie]
pattern = 52 49 46 46
at = overlay, resource, file
extensions = DAT

[Micrografx Designer graphic]
pattern = 52 49 46 46
at = overlay, resource, file
extensions = DS4

[4X Movie video]
pattern = 52 49 46 46
at = overlay, resource, file
extensions = 4XM

[Resource Interchange File Format]
pattern = 52 49 46 46
at = overlay, resource, file
extensions = AVI, CDA, QCP, RMI, WAV

[WinNT Netmon capture file]
pattern = 52 54 53 53
at = overlay, resource, file
extensions = CAP

[WinRAR compressed archive]
pattern = 52 61 72 21 1A 07 00
at = overlay, resource, file
extensions = RAR

[Generic e-mail_1]
pattern = 52 65 74 75 72 6E 2D 50
at = overlay, resource, file
extensions = EML

[Underground Audio]
pattern = 53 43 48 6C
at = overlay, resource, file
extensions = AST

[Img Software Bitmap]
pattern = 53 43 4D 49
at = overlay, resource, file
extensions = IMG

[SMPTE DPX (big endian)]
pattern = 53 44 50 58
at = overlay, resource, file
extensions = SDPX

[Harvard Graphics presentation]
pattern = 53 48 4F 57
at = overlay, resource, file
extensions = SHW

[Sietronics CPI XRD document]
pattern = 53 49 45 54 52 4F 4E 49
at = overlay, resource, file
extensions = CPI

[Flexible Image Transport System (FITS) file]
pattern = 53 49 4D 50 4C 45 20 20 3D 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54
at = overlay, resource, file
extensions = FITS

[StuffIt archive]
pattern = 53 49 54 21 00
at = overlay, resource, file
extensions = SIT

[SmartDraw Drawing file]
pattern = 53 4D 41 52 54 44 52 57
at = overlay, resource, file
extensions = SDR

[StorageCraft ShadownProtect backup file]
pattern = 53 50 46 49 00
at = overlay, resource, file
extensions = SPF

[MultiBit Bitcoin blockchain file]
pattern = 53 50 56 42
at = overlay, resource, file
extensions = SPVB

[SQLite database file]
pattern = 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00
at = overlay, resource, file
extensions = DB

[DB2 conversion file]
pattern = 53 51 4C 4F 43 4F 4E 56
at = overlay, resource, file
extensions = CNV

[QBASIC SZDD file]
pattern = 53 5A 20 88 F0 27 33 D1
at = overlay, resource, file

[SZDD file format]
pattern = 53 5A 44 44 88 F0 27 33
at = overlay, resource, file

[StuffIt compressed archive]
pattern = 53 74 75 66 66 49 74 20
at = overlay, resource, file
extensions = SIT

[SuperCalc worksheet]
pattern = 53 75 70 65 72 43 61 6C
at = overlay, resource, file
extensions = CAL

[GNU Info Reader file]
pattern = 54 68 69 73 20 69 73 20
at = overlay, resource, file
extensions = INFO

[Unicode extensions]
pattern = 55 43 45 58
at = overlay, resource, file
extensions = UCE

[UFA compressed archive]
pattern = 55 46 41 C6 D2 C1
at = overlay, resource, file
extensions = UFA

[UFO Capture map file]
pattern = 55 46 4F 4F 72 62 69 74
at = overlay, resource, file
extensions = DAT

[Visual C PreCompiled header]
pattern = 56 43 50 43 48 30
at = overlay, resource, file
extensions = PCH

[Visual Basic User-defined Control file]
pattern = 56 45 52 53 49 4F 4E 20
at = overlay, resource, file
extensions = CTL

[MapInfo Interchange Format file]
pattern = 56 65 72 73 69 6F 6E 20
at = overlay, resource, file
extensions = MIF

[Walkman MP3 file]
pattern = 57 4D 4D 50
at = overlay, resource, file
extensions = DAT

[WordStar for Windows file]
pattern = 57 53 32 30 30 30
at = overlay, resource, file
extensions = WS2

[Lotus WordPro file]
pattern = 57 6F 72 64 50 72 6F
at = overlay, resource, file
extensions = LWP

[Packet sniffer files]
pattern = 58 43 50 00
at = overlay, resource, file
extensions = CAP

[XPCOM libraries]
pattern = 58 50 43 4F 4D 0A 54 79
at = overlay, resource, file
extensions = XPT

[SMPTE DPX file (little endian)]
pattern = 58 50 44 53
at = overlay, resource, file
extensions = DPX

[ZOO compressed archive]
pattern = 5A 4F 4F 20
at = overlay, resource, file
extensions = ZOO

[MS Exchange configuration file]
pattern = 5B 47 65 6E 65 72 61 6C
at = overlay, resource, file
extensions = ECF

[Visual C++ Workbench Info File]
pattern = 5B 4D 53 56 43
at = overlay, resource, file
extensions = VCW

[Dial-up networking file]
pattern = 5B 50 68 6F 6E 65 5D
at = overlay, resource, file
extensions = DUN

[Lotus AMI Pro document_1]
pattern = 5B 56 45 52 5D
at = overlay, resource, file
extensions = SAM

[VocalTec VoIP media file]
pattern = 5B 56 4D 44 5D
at = overlay, resource, file
extensions = VMD

[Microsoft Code Page Translation file]
pattern = 5B 57 69 6E 64 6F 77 73
at = overlay, resource, file
extensions = CPX

[Flight Simulator Aircraft Configuration]
pattern = 5B 66 6C 74 73 69 6D 2E
at = overlay, resource, file
extensions = CFG

[WinAmp Playlist]
pattern = 5B 70 6C 61 79 6C 69 73 74 5D
at = overlay, resource, file
extensions = PLS

[Lotus AMI Pro document_2]
pattern = 5B 76 65 72 5D
at = overlay, resource, file
extensions = SAM

[Jar archive]
pattern = 5F 27 A8 89
at = overlay, resource, file
extensions = JAR

[EnCase case file]
pattern = 5F 43 41 53 45 5F
at = overlay, resource, file
extensions = CAS, CBK

[UUencoded file]
pattern = 62 65 67 69 6E
at = overlay, resource, file

[UUencoded BASE64 file]
pattern = 62 65 67 69 6E 2D 62 61 73 65 36 34
at = overlay, resource, file
extensions = b64

[Binary property list (plist)]
pattern = 62 70 6C 69 73 74
at = overlay, resource, file

[Apple Core Audio File]
pattern = 63 61 66 66
at = overlay, resource, file
extensions = CAF

[Virtual PC HD image]
pattern = 63 6F 6E 65 63 74 69 78
at = overlay, resource, file
extensions = VHD

[Photoshop Custom Shape]
pattern = 63 75 73 68 00 00 00 02
at = overlay, resource, file
extensions = CSH

[Intel PROset|Wireless Profile]
pattern = 64 00 00 00
at = overlay, resource, file
extensions = P10

[Dalvik (Android) executable file]
pattern = 64 65 78 0A
at = overlay, resource, file
extensions = dex

[Audacity audio file]
pattern = 64 6E 73 2E
at = overlay, resource, file
extensions = AU

[MS Visual Studio workspace file]
pattern = 64 73 77 66 69 6C 65
at = overlay, resource, file
extensions = DSW

[WinNT printer spool file]
pattern = 66 49 00 00
at = overlay, resource, file
extensions = SHD

[Free Lossless Audio Codec file]
pattern = 66 4C 61 43 00 00 00 22
at = overlay, resource, file
extensions = FLAC

[Win2000|XP printer spool file]
pattern = 67 49 00 00
at = overlay, resource, file
extensions = SHD

[GIMP file]
pattern = 67 69 6D 70 20 78 63 66
at = overlay, resource, file
extensions = XCF

[Win Server 2003 printer spool file]
pattern = 68 49 00 00
at = overlay, resource, file
extensions = SHD

[Skype user data file]
pattern = 6C 33 33 6C
at = overlay, resource, file
extensions = DBB

[MultiBit Bitcoin wallet information]
pattern = 6D 75 6C 74 69 42 69 74 2E 69 6E 66 6F
at = overlay, resource, file
extensions = INFO

[1Password 4 Cloud Keychain encrypted data]
pattern = 6F 70 64 61 74 61 30 31
at = overlay, resource, file

[WinNT registry file]
pattern = 72 65 67 66
at = overlay, resource, file
extensions = DAT

[Sonic Foundry Acid Music File]
pattern = 72 69 66 66
at = overlay, resource, file
extensions = AC

[RealMedia metafile]
pattern = 72 74 73 70 3A 2F 2F
at = overlay, resource, file
extensions = RAM

[Allegro Generic Packfile (compressed)]
pattern = 73 6C 68 21
at = overlay, resource, file
extensions = DAT

[Allegro Generic Packfile (uncompressed)]
pattern = 73 6C 68 2E
at = overlay, resource, file
extensions = DAT

[PalmOS SuperMemo]
pattern = 73 6D 5F
at = overlay, resource, file
extensions = PDB

[CALS raster bitmap]
pattern = 73 72 63 64 6F 63 69 64
at = overlay, resource, file
extensions = CAL

[PowerBASIC Debugger Symbols]
pattern = 73 7A 65 7A
at = overlay, resource, file
extensions = PDB

[OpenEXR bitmap image]
pattern = 76 2F 31 01
at = overlay, resource, file
extensions = EXR

[Qimage filter]
pattern = 76 32 30 30 33 2E 31 30
at = overlay, resource, file
extensions = FLT

[MacOS X image file]
pattern = 78 01 73 0D 62 62 60
at = overlay, resource, file
extensions = DMG

[eXtensible ARchive file]
pattern = 78 61 72 21
at = overlay, resource, file
extensions = XAR

[ZoomBrowser Image Index]
pattern = 7A 62 65 78
at = overlay, resource, file
extensions = INFO

[Windows application log]
pattern = 7B 0D 0A 6F 20
at = overlay, resource, file
extensions = LGC, LGD

[MS WinMobile personal note]
pattern = 7B 5C 70 77 69
at = overlay, resource, file
extensions = PWI

[RTF file]
pattern = 7B 5C 72 74 66 31
at = overlay, resource, file
extensions = RTF

[Corel Paint Shop Pro image]
pattern = 7E 42 4B 00
at = overlay, resource, file
extensions = PSP

[Digital Watchdog DW-TP-500G audio]
pattern = 7E 74 2C 01 50 70 02 4D 52
at = overlay, resource, file
extensions = IMG

[ELF executable]
pattern = 7F 45 4C 46
at = overlay, resource, file

[Dreamcast audio]
pattern = 80 00 00 20 03 12 04
at = overlay, resource, file
extensions = ADX

[Kodak Cineon image]
pattern = 80 2A 5F D7
at = overlay, resource, file
extensions = CIN

[Outlook Express address book (Win95)]
pattern = 81 32 84 C1 85 05 D0 11
at = overlay, resource, file
extensions = WAB

[WordPerfect text]
pattern = 81 CD AB
at = overlay, resource, file
extensions = WPF

[PNG image]
pattern = 89 50 4E 47 0D 0A 1A 0A
at = overlay, resource, file
extensions = PNG

[MS Answer Wizard]
pattern = 8A 01 09 00 00 00 E1 08
at = overlay, resource, file
extensions = AW

[Hamarsoft compressed archive]
pattern = 91 33 48 46
at = overlay, resource, file
extensions = HAP

[JBOG2 image file]
pattern = 97 4A 42 32 0D 0A 1A 0A
at = overlay, resource, file
extensions = JB2

[Outlook address file]
pattern = 9C CB CB 8D 13 75 D2 11
at = overlay, resource, file
extensions = WAB

[tcpdump (libpcap) capture file]
pattern = A1 B2 C3 D4
at = overlay, resource, file

[Extended tcpdump (libpcap) capture file]
pattern = A1 B2 CD 34
at = overlay, resource, file

[Access Data FTK evidence]
pattern = A9 0D 00 00 00 00 00 00
at = overlay, resource, file
extensions = DAT

[Quicken data]
pattern = AC 9E BD 8F 00 00
at = overlay, resource, file
extensions = QDF

[BGBlitz position database file]
pattern = AC ED 00 05 73 72 00 12
at = overlay, resource, file
extensions = PDB

[Win95 password file]
pattern = B0 4D 46 43
at = overlay, resource, file
extensions = PWL

[PCX bitmap]
pattern = B1 68 DE 3A
at = overlay, resource, file
extensions = DCX

[Acronis True Image]
pattern = B4 6E 68 44
at = overlay, resource, file
extensions = TIB

[Windows calendar]
pattern = B5 A2 B0 B3 B3 B0 A5 B5
at = overlay, resource, file
extensions = CAL

[MS Write file_3]
pattern = BE 00 00 00 AB
at = overlay, resource, file
extensions = WRI

[Palm Desktop DateBook]
pattern = BE BA FE CA 0F 50 61 6C 6D 53 47 20 44 61 74 61
at = overlay, resource, file
extensions = DAT

[MS Agent Character file]
pattern = C3 AB CD AB
at = overlay, resource, file
extensions = ACS

[Adobe encapsulated PostScript]
pattern = C5 D0 D3 C6
at = overlay, resource, file
extensions = EPS

[Jeppesen FliteLog file]
pattern = C8 00 79 00
at = overlay, resource, file
extensions = LBK

[Java bytecode]
pattern = CA FE BA BE
at = overlay, resource, file
extensions = CLASS

[NAV quarantined virus file]
pattern = CD 20 AA AA 02 00 00 00
at = overlay, resource, file

[Java Cryptography Extension keystore]
pattern = CE CE CE CE
at = overlay, resource, file
extensions = JCEKS

[OS X ABI Mach-O binary (32-bit reverse)]
pattern = CE FA ED FE
at = overlay, resource, file

[Perfect Office document]
pattern = CF 11 E0 A1 B1 1A E1 00
at = overlay, resource, file
extensions = DOC

[Outlook Express e-mail folder]
pattern = CF AD 12 FE
at = overlay, resource, file
extensions = DBX

[OS X ABI Mach-O binary (64-bit reverse)]
pattern = CF FA ED FE
at = overlay, resource, file

[Microsoft Office document]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = DOC, DOT, PPS, PPT, XLA, XLS, WIZ

[CaseWare Working Papers]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = AC_

[Access project file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = ADP

[Lotus|IBM Approach 97 file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = APR

[MSWorks database file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = DB

[Microsoft Common Console Document]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = MSC

[Microsoft Installer package]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = MSI

[Minitab data file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = MTW

[Developer Studio File Options file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = OPT

[MS Publisher file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = PUB

[Revit Project file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = RVT

[Visual Studio Solution User Options file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = SOU

[SPSS output file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = SPO

[Visio file]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = VSD

[MSWorks text document]
pattern = D0 CF 11 E0 A1 B1 1A E1
at = overlay, resource, file
extensions = WPS

[WinPharoah filter file]
pattern = D2 0A 00 00
at = overlay, resource, file
extensions = FTR

[WinDump (winpcap) capture file]
pattern = D4 C3 B2 A1
at = overlay, resource, file

[Windows graphics metafile]
pattern = D7 CD C6 9A
at = overlay, resource, file
extensions = WMF

[Word 2.0 file]
pattern = DB A5 2D 00
at = overlay, resource, file
extensions = DOC

[Amiga icon]
pattern = E3 10 00 01 00 00 00 00
at = overlay, resource, file
extensions = INFO

[Win98 password file]
pattern = E3 82 85 96
at = overlay, resource, file
extensions = PWL

[MS OneNote note]
pattern = E4 52 5C 7B 8C D8 A7 4D
at = overlay, resource, file
extensions = ONE

[GEM Raster file]
pattern = EB 3C 90 2A
at = overlay, resource, file
extensions = IMG

[BitLocker boot sector (Vista)]
pattern = EB 52 90 2D 46 56 45 2D
at = overlay, resource, file

[BitLocker boot sector (Win7)]
pattern = EB 58 90 2D 46 56 45 2D
at = overlay, resource, file

[RedHat Package Manager]
pattern = ED AB EE DB
at = overlay, resource, file
extensions = RPM

[UTF8 file]
pattern = EF BB BF
at = overlay, resource, file

[FAT12 File Allocation Table]
pattern = F0 FF FF
at = overlay, resource, file

[FAT16 File Allocation Table]
pattern = F8 FF FF FF
at = overlay, resource, file

[FAT32 File Allocation Table_1]
pattern = F8 FF FF 0F FF FF FF 0F
at = overlay, resource, file

[FAT32 File Allocation Table_2]
pattern = F8 FF FF 0F FF FF FF FF
at = overlay, resource, file

[Bitcoin-Qt blockchain block file]
pattern = F9 BE B4 D9
at = overlay, resource, file
extensions = DAT

[XZ archive]
pattern = FD 37 7A 58 5A 00
at = overlay, resource, file
extensions = XZ

[OS X ABI Mach-O binary (32-bit)]
pattern = FE ED FA CE
at = overlay, resource, file

[OS X ABI Mach-O binary (64-bit)]
pattern = FE ED FA CF
at = overlay, resource, file

[JavaKeyStore]
pattern = FE ED FE ED
at = overlay, resource, file

[Works for Windows spreadsheet]
pattern = FF 00 02 00 04 04 05 54
at = overlay, resource, file
extensions = WKS

[Windows international code page]
pattern = FF 46 4F 4E 54
at = overlay, resource, file
extensions = CPI

[Keyboard driver file]
pattern = FF 4B 45 59 42 20 20 20
at = overlay, resource, file
extensions = SYS

[WordPerfect text and graphics]
pattern = FF 57 50 43
at = overlay, resource, file
extensions = WP, WPD, WPG, WPP, WP5, WP6

[JPEG|EXIF|SPIFF images]
pattern = FF D8 FF
at = overlay, resource, file
extensions = JFIF, JPE, JPEG, JPG

[UTF-32|UCS-4 file]
pattern = FF FE 00 00
at = overlay, resource, file
extensions = (NONE)

[MSinfo file]
pattern = FF FE 23 00 6C 00 69 00
at = overlay, resource, file
extensions = MOF

[DOS system driver]
pattern = FF FF FF FF
at = overlay, resource, file
extensions = SYS

[RSDS Debug info]
pattern = 52 53 44 53
at = overlay, resource, file

[NB10 Debug info]
pattern = 4E 42 31 30
at = overlay, resource, file

[Visual Basic]
pattern = 56 42 35 21
at = overlay, resource, file

