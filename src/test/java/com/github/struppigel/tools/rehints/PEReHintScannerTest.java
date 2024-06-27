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
package com.github.struppigel.tools.rehints;


import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoaderTest;
import com.github.struppigel.tools.anomalies.PEAnomalyScanner;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
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
        assertHasReHint("ahk", ReHintType.AHK_RE_HINT);
        assertHasNotReHint("pyinstaller", ReHintType.AHK_RE_HINT);
    }

    @Test
    public void autoitTest() {
        assertHasReHint("autoit", ReHintType.AUTOIT_RE_HINT);
        assertHasNotReHint("pyinstaller", ReHintType.AUTOIT_RE_HINT);
    }

    @Test
    public void pyinstallerTest() {
        assertHasReHint("pyinstaller", ReHintType.PYINSTALLER_RE_HINT);
        assertHasNotReHint("ahk", ReHintType.PYINSTALLER_RE_HINT);
    }

    @Test
    public void fakeVMPTest() {
        assertHasReHint("upx_vmp", ReHintType.FAKE_VMP_RE_HINT);
        assertHasNotReHint("upx.exe", ReHintType.FAKE_VMP_RE_HINT);
    }

    @Test
    public void upxTest() {
        assertHasReHint("upx.exe", ReHintType.UPX_PACKER_RE_HINT);
        assertHasNotReHint("ahk", ReHintType.UPX_PACKER_RE_HINT);
    }

    @Test
    public void electronTest() {
        assertHasReHint("electron.exe", ReHintType.ELECTRON_PACKAGE_RE_HINT);
        assertHasNotReHint("pyinstaller", ReHintType.ELECTRON_PACKAGE_RE_HINT);
    }

    @Test
    public void archiveTest() {
        assertHasReHint("pyinstaller", ReHintType.ARCHIVE_RE_HINT);
        assertHasNotReHint("upx.exe", ReHintType.ARCHIVE_RE_HINT);
    }

    // TODO find test samples for
    //  NSIS, Script-to-Exe-Wrapped
    //  installer, SFX, embedded_exe
    //  fake vmp

    private void assertHasReHint(String testfile, ReHintType rhType){
        List<ReHint> rehints = getHintsFor(testfile);
        List<ReHint> rehintsFiltered = rehints.stream()
                .filter(rh -> rh.reType() == rhType)
                .collect(Collectors.toList());

        assertTrue(!rehintsFiltered.isEmpty());
    }

    private void assertHasNotReHint(String testfile, ReHintType rhType){
        List<ReHint> rehints = getHintsFor(testfile);
        List<ReHint> rehintsFiltered = rehints.stream()
                .filter(rh -> rh.reType() == rhType)
                .collect(Collectors.toList());
        assertTrue(rehintsFiltered.isEmpty());
    }
}
