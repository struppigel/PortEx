/*******************************************************************************
 * Copyright 2014 Katja Hahn
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
package com.github.struppigel.parser.coffheader;

import com.github.struppigel.TestreportsReader;
import com.github.struppigel.TestreportsReader.TestData;
import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoader;
import com.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;

import static org.testng.Assert.*;

public class COFFFileHeaderTest {

    private COFFFileHeader winRarCoff;
    private List<TestData> testdata;
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        testdata = PELoaderTest.getTestData();
        pedata = PELoaderTest.getPEData();
        winRarCoff = PELoader.loadPE(
                Paths.get(TestreportsReader.RESOURCE_DIR, TestreportsReader.TEST_FILE_DIR, "WinRar.exe").toFile())
                .getCOFFFileHeader();
    }

    @Test
    public void get() {
        assertEquals(winRarCoff.get(COFFHeaderKey.MACHINE), 0x14c);
        assertEquals(winRarCoff.get(COFFHeaderKey.TIME_DATE), 0x45adfc46);
        assertEquals(winRarCoff.get(COFFHeaderKey.SECTION_NR), 0x4);
        assertEquals(winRarCoff.get(COFFHeaderKey.NR_OF_SYMBOLS), 0x0);
        assertEquals(winRarCoff.get(COFFHeaderKey.POINTER_TO_SYMB_TABLE), 0x0);
        assertEquals(winRarCoff.get(COFFHeaderKey.SIZE_OF_OPT_HEADER), 0xe0);
        assertEquals(winRarCoff.get(COFFHeaderKey.CHARACTERISTICS), 0x10f);
    }

    private int convertToInt(String value) {
        if (value.startsWith("0x")) {
            value = value.replace("0x", "");
            return Integer.parseInt(value, 16);
        } else {
            return Integer.parseInt(value);
        }
    }

    @Test
    public void getMachineDescription() {
        assertEquals(winRarCoff.getMachineType().getDescription(),
                "Intel 386 or later processors and compatible processors");
    }

    @Test
    public void getMachineType() {
        assertEquals(winRarCoff.getMachineType(), MachineType.I386);
    }

    @Test
    public void getInfo() {
        String info = winRarCoff.getInfo();
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }

    @Test
    public void characteristicsSize() {
        List<FileCharacteristic> description = winRarCoff.getCharacteristics();
        assertEquals(description.size(), 5);
    }

    @Test
    public void getNumberOfSections() {
        assertEquals(winRarCoff.getNumberOfSections(), 0x04);
    }

    @Test
    public void getSizeOfOptionalHeader() {
        assertEquals(winRarCoff.getSizeOfOptionalHeader(), 0x00e0);
    }

    @Test
    public void getTimeDate() {
        Date date = winRarCoff.getTimeDate();
        Calendar calendar = Calendar.getInstance();
        calendar.clear();
        calendar.set(2007, Calendar.JANUARY, 17, 11, 36, 54);
        assertEquals(calendar.getTime().compareTo(date), 0);
    }
}
