/*******************************************************************************
 * Copyright 2024 Karsten Phillip Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package io.github.struppigel.tools.rehints;


import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PELoaderTest;
import io.github.struppigel.parser.optheader.DataDirEntry;
import io.github.struppigel.parser.optheader.DataDirectoryKey;
import io.github.struppigel.tools.ReportCreator;
import io.github.struppigel.tools.anomalies.PEAnomalyScanner;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class PEReHintScannerTest  {
    private Map<String, PEData> pedata = new HashMap<>();
    private Map<String, List<ReHint>> hintData = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        pedata = PELoaderTest.getPEData();
    }

    private List<ReHint> getHintsFor(String testfile) {
        if(!hintData.containsKey(testfile)) {
            PEData pe = pedata.get(testfile);
            PEReHintScanner scanner = PEReHintScanner.newInstance(pe, PEAnomalyScanner.newInstance(pe).getAnomalies());
            List<ReHint> rehints = scanner.getReHints();
            hintData.put(testfile, rehints);
        }
        return hintData.get(testfile);
    }

    @Test
    public void ahkTest() {
        assertHasReHintWithTypeAndReason("ahk", ReHintType.AHK_RE_HINT, "Resource named >AUTOHOTKEY SCRIPT< in resource 0xaade0");
        assertHasNotReHint("pyinstaller", ReHintType.AHK_RE_HINT);
    }

    @Test
    public void archiveTest() {
        assertHasReHintWithTypeAndReason("pyinstaller", ReHintType.ARCHIVE_RE_HINT, "Overlay has signature zlib archive");
        assertHasNotReHint("upx.exe", ReHintType.ARCHIVE_RE_HINT);
    }

    @Test
    public void autoitTest() {
        assertHasReHintWithTypeAndReason("autoit", ReHintType.AUTOIT_RE_HINT, "Resource named SCRIPT in resource 0x118068");
        assertHasNotReHint("pyinstaller", ReHintType.AUTOIT_RE_HINT);
    }

    @Test
    public void electronTest() {
        assertHasReHintWithTypeAndReason("electron.exe", ReHintType.ELECTRON_PACKAGE_RE_HINT, "Section name 'CPADinfo'");
        assertHasReHintWithTypeAndReason("electron.exe", ReHintType.ELECTRON_PACKAGE_RE_HINT, "PDB path is 'electron.exe.pdb'");
        assertHasNotReHint("pyinstaller", ReHintType.ELECTRON_PACKAGE_RE_HINT);
    }

    @Test
    public void embeddedExeTest() {
        ReHintType rtype = ReHintType.EMBEDDED_EXE_RE_HINT;
        String reason = "Resource named ID: 1 in resource 0xd74 is an executable (MS-DOS or Portable Executable)";
        assertHasReHintWithTypeAndReason("embedded_exe_resources", rtype, reason);
        assertHasReHint("embedded_exe_overlay", rtype);
        assertHasNotReHint("upx.exe", rtype);
    }

    @Test
    public void fakeVMPTest() {
        assertHasReHintWithTypeAndReason("upx_vmp", ReHintType.FAKE_VMP_RE_HINT, "Section name .vmp0");
        assertHasNotReHint("upx.exe", ReHintType.FAKE_VMP_RE_HINT);
    }

    @Test
    public void innoTest() {
        ReHintType rtype = ReHintType.INNO_SETUP_RE_HINT;
        assertHasReHintWithTypeAndReason("innosetup", rtype, "MSDOS Header has Inno Setup signature 'InUn' at offset 0x30");
        assertHasReHintWithTypeAndReason("inno_with_stub", rtype, "Overlay has signature Inno Setup Installer with Stub");
        assertHasNotReHint("nsis", rtype);
    }

    @Test
    public void nsisTest() {
        assertHasReHintWithTypeAndReason("nsis", ReHintType.NULLSOFT_RE_HINT, "Overlay has signature NSIS");
        assertHasReHintWithTypeAndReason("nsis", ReHintType.NULLSOFT_RE_HINT, "Section name .ndata");
        assertHasNotReHint("upx.exe", ReHintType.NULLSOFT_RE_HINT);
    }

    @Test
    public void pyinstallerTest() {
        assertHasReHintWithTypeAndReason("pyinstaller", ReHintType.PYINSTALLER_RE_HINT, "Overlay has signature zlib archive");
        assertHasReHintWithTypeAndReason("pyinstaller", ReHintType.PYINSTALLER_RE_HINT, "'PyInstaller archive' string in .rdata");
        assertHasNotReHint("ahk", ReHintType.PYINSTALLER_RE_HINT);
    }

    @Test
    public void script2exeTest() {
        ReHintType rtype = ReHintType.SCRIPT_TO_EXE_WRAPPED_RE_HINT;
        assertHasReHintWithTypeAndReason("batch2exe", rtype, "Signature for PureBasic matches at entry point");
        assertHasReHintWithTypeAndReason("batch2exe", rtype, "Resource B17E574496F7821F47CE650786DFFB at 0x11748 has size 6 and bytes 0x01 0x01 0x00 0x00 0x00 0x00 which is a sign of a Script-to-Exe converter");
        assertHasNotReHint("upx.exe", rtype);
    }

    @Test
    public void sfxTest() {
        assertHasReHintWithTypeAndReason("7zipsfx", ReHintType.INSTALLER_RE_HINT, "Overlay has signature 7-zip Installer");
        assertHasNotReHint("upx.exe", ReHintType.INSTALLER_RE_HINT);
    }

    @Test
    public void upxTest() {
        assertHasReHintWithTypeAndReason("upx.exe", ReHintType.UPX_PACKER_RE_HINT, "Section name UPX0");
        assertHasReHintWithTypeAndReason("upx.exe", ReHintType.UPX_PACKER_RE_HINT, "Section name UPX1");
        assertHasNotReHint("ahk", ReHintType.UPX_PACKER_RE_HINT);
    }
    @Test
    public void compressedArchiveIsNoCompressor() {
        // the signature "WinRAR compressed archive" must not match the MPRESS check
        assertHasNotReHint("WinRar.exe", ReHintType.COMPRESSOR_PACKER_RE_HINT);
    }

    @Test
    public void threadNameCallingInjection(){
        assertHasReHintWithTypeAndReason("GetThreadDescription", ReHintType.THREAD_NAME_CALLING_INJECTION_HINT, "GetThreadDescription can be used to inject shellcode");
        assertHasReHintWithTypeAndReason("GetThreadDescription", ReHintType.THREAD_NAME_CALLING_INJECTION_HINT, "SetThreadDescription can be used to inject shellcode");
    }

    @Test
    public void processDoppelGaenging() {
        assertHasReHintWithTypeAndReason("proc_doppel32.exe", ReHintType.PROCESS_DOPPELGAENGING_INJECTION_HINT, "Process Doppelgänging");
        assertHasReHintWithTypeAndReason("proc_doppel64.exe", ReHintType.PROCESS_DOPPELGAENGING_INJECTION_HINT, "Process Doppelgänging");
    }

    @Test
    public void dotNetCoreAppBundle() {
        assertHasReHintWithTypeAndReason("DotNetBundle.exe", ReHintType.DOT_NET_CORE_APP_BUNDLE_HINT, "apphost.pdb");
    }

    @Test
    public void certificateDataTest() throws IOException {
        File strings = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/strings.exe");
        assertFalse(hintsOf(PELoader.loadPE(strings)).stream()
                .anyMatch(h -> h.reType() == ReHintType.CERTIFICATE_DATA_RE_HINT));
        // data appended to the PKCS#7 signature inside the WIN_CERTIFICATE, the table is at the end of the file
        DataDirEntry entry = PELoader.loadPE(strings).getOptionalHeader()
                .maybeGetDataDirEntry(DataDirectoryKey.CERTIFICATE_TABLE).get();
        byte[] original = Files.readAllBytes(strings.toPath());
        byte[] bytes = Arrays.copyOf(original, original.length + 64);
        Arrays.fill(bytes, original.length, bytes.length, (byte) 0x41);
        long newSize = entry.getDirectorySize() + 64;
        putLe32(bytes, (int) entry.getVirtualAddress(), newSize);
        putLe32(bytes, (int) entry.getTableEntryOffset() + 4, newSize);
        Path stuffed = Files.createTempFile("portex-stuffed-certificate", ".exe");
        try {
            Files.write(stuffed, bytes);
            List<ReHint> hints = hintsOf(PELoader.loadPE(stuffed.toFile())).stream()
                    .filter(h -> h.reType() == ReHintType.CERTIFICATE_DATA_RE_HINT).collect(Collectors.toList());
            assertEquals(hints.size(), 1);
            assertTrue(hints.get(0).reasons().stream().anyMatch(r -> r.contains("bytes after the signature structure")),
                    hints.get(0).reasons().toString());
            assertTrue(hints.get(0).description().contains("--dump certificates"));
        } finally {
            Files.deleteIfExists(stuffed);
        }
    }

    private static List<ReHint> hintsOf(PEData pe) {
        return PEReHintScanner.newInstance(pe, PEAnomalyScanner.newInstance(pe).getAnomalies()).getReHints();
    }

    private static void putLe32(byte[] b, int p, long value) {
        for (int i = 0; i < 4; i++) {
            b[p + i] = (byte) (value >>> (8 * i));
        }
    }

    private void assertHasReHint(String testfile, ReHintType rhType){
        List<ReHint> rehints = getHintsFor(testfile);
        List<ReHint> rehintsFiltered = rehints.stream()
                .filter(rh -> rh.reType() == rhType)
                .collect(Collectors.toList());

        assertTrue(!rehintsFiltered.isEmpty());
    }

    private void assertHasReHintWithTypeAndReason(String testfile, ReHintType rhType, String reason){
        List<ReHint> rehints = getHintsFor(testfile);
        List<ReHint> rehintsFiltered = rehints.stream()
                .filter(rh -> rh.reType() == rhType)
                .collect(Collectors.toList());
        assertTrue(!rehintsFiltered.isEmpty());
        List<ReHint> rehintsContentFiltered = rehintsFiltered.stream()
                .filter(h -> !h.reasons().stream().filter(r -> r.contains(reason)).collect(Collectors.toList()).isEmpty())
                .collect(Collectors.toList());
        assertTrue(!rehintsContentFiltered.isEmpty());
    }

    private void printReHintsReport(String testfile) {
        System.out.println(new ReportCreator(pedata.get(testfile)).reversingHintsReport());
    }

    private void assertHasNotReHint(String testfile, ReHintType rhType){
        List<ReHint> rehints = getHintsFor(testfile);
        List<ReHint> rehintsFiltered = rehints.stream()
                .filter(rh -> rh.reType() == rhType)
                .collect(Collectors.toList());
        assertTrue(rehintsFiltered.isEmpty());
    }
}
