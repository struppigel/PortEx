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
package com.github.katjahahn.parser.optheader;

import static com.github.katjahahn.parser.optheader.DataDirectoryKey.*;
import static org.testng.Assert.*;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader.TestData;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoaderTest;
import com.github.katjahahn.parser.StandardField;
import com.github.katjahahn.parser.optheader.OptionalHeader.MagicNumber;
import com.google.common.base.Optional;

public class OptionalHeaderTest {

    private static final Logger logger = LogManager
            .getLogger(OptionalHeaderTest.class.getName());

    private List<TestData> testdata;
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        testdata = PELoaderTest.getTestData();
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void dataDirEntriesListValid() {
        for (PEData pedatum : pedata.values()) {
            Collection<DataDirEntry> coll = pedatum.getOptionalHeader()
                    .getDataDirectory().values();
            assertNotNull(coll);
            assertTrue(coll.size() >= 0);
        }
    }

    @Test
    public void getDataDirEntries() {
            PEData pedatum = pedata.get("strings.exe");
            OptionalHeader opt = pedatum.getOptionalHeader();
            Collection<DataDirEntry> peDataEntries = opt.getDataDirectory()
                    .values();
            List<DataDirEntry> expectedDataEntries = new LinkedList<DataDirEntry>();
            expectedDataEntries.add(new DataDirEntry("import table", 0x4fda4, 0x8c, 0x4e3a4));
            expectedDataEntries.add(new DataDirEntry("resource table", 0x53000, 0x588, 0x4fc00));
            expectedDataEntries.add(new DataDirEntry("certificate table", 0x52800, 0x2388, 0x50800));
            expectedDataEntries.add(new DataDirEntry("base relocation table", 0x54000, 0x2524, 0x50200));
            expectedDataEntries.add(new DataDirEntry("debug", 0x4ed40, 0x54,0x4d340));
            expectedDataEntries.add(new DataDirEntry("load config table", 0x4ed98, 0x40, 0x4d398));
            expectedDataEntries.add(new DataDirEntry("IAT", 0x41000, 0x220, 0x3f600));

            assertEquals(peDataEntries.size(), expectedDataEntries.size());
            for (DataDirEntry expected : expectedDataEntries) {
                assertTrue(peDataEntries.contains(expected));
            }
    }

    @Test
    public void getDataDirEntry() {
        OptionalHeader header = pedata.get("strings.exe").getOptionalHeader();
        DataDirectoryKey[] existant = { IMPORT_TABLE, RESOURCE_TABLE,
                CERTIFICATE_TABLE,BASE_RELOCATION_TABLE , DEBUG, LOAD_CONFIG_TABLE, IAT };
        for (DataDirectoryKey key : DataDirectoryKey.values()) {
            Optional<DataDirEntry> entry = header.maybeGetDataDirEntry(key);
            assertTrue((entry.isPresent() && isIn(existant, key))
                    || !entry.isPresent());
        }
    }

    private <T> boolean isIn(T[] array, T item) {
        for (T t : array) {
            if (t.equals(item)) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void getDataDirInfo() {
        String info = pedata.get("strings.exe").getOptionalHeader()
                .getDataDirInfo();
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }

    @Test
    // TODO maybe better
    public void getImageBaseDescription() {
        String info = OptionalHeader.getImageBaseDescription(0x10000000);
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }

    @Test
    public void getInfo() {
        String info = pedata.get("strings.exe").getOptionalHeader().getInfo();
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }

    @Test
    public void getMagicNumberAndString() {
        for (TestData testdatum : testdata) {
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            OptionalHeader opt = pedatum.getOptionalHeader();
            MagicNumber magic = opt.getMagicNumber();
            String string = magic.getDescription();
            assertNotNull(magic);
            assertNotNull(string);
            assertTrue(string.length() > 0);
        }
    }

    @Test
    public void getStandardFieldEntry() {
        for (TestData testdatum : testdata) {
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            for (Entry<StandardFieldEntryKey, String> entry : testdatum.standardOpt
                    .entrySet()) {
                StandardFieldEntryKey key = entry.getKey();
                OptionalHeader opt = pedatum.getOptionalHeader();
                Long actual = opt.getStandardFieldEntry(key).getValue();
                String value = entry.getValue().trim();
                Long expected = convertToLong(value);
                assertEquals(expected, actual);
            }
        }
    }

    @Test
    public void baseOfData() {
        for (TestData testdatum : testdata) {
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            OptionalHeader opt = pedatum.getOptionalHeader();
            Map<StandardFieldEntryKey, StandardField> standardFields = opt
                    .getStandardFields();
            if (opt.getMagicNumber() == MagicNumber.PE32_PLUS) {
                assertFalse(standardFields
                        .containsKey(StandardFieldEntryKey.BASE_OF_DATA));
            } else {
                assertTrue(standardFields
                        .containsKey(StandardFieldEntryKey.BASE_OF_DATA));
            }
        }
    }

    // TODO in Oberklasse auslagern, ebenso prepare
    private long convertToLong(String value) {
        if (value.startsWith("0x")) {
            value = value.replace("0x", "");
            return Long.parseLong(value, 16);
        } else {
            return Long.parseLong(value);
        }
    }

    @Test
    public void getStandardFields() {
        for (PEData pedatum : pedata.values()) {
            Collection<StandardField> list = pedatum.getOptionalHeader()
                    .getStandardFields().values();
            MagicNumber magic = pedatum.getOptionalHeader().getMagicNumber();
            assertNotNull(list);
            int expected = StandardFieldEntryKey.values().length;
            if (magic == MagicNumber.PE32_PLUS) {
                expected--;
            }
            int actual = list.size();
            if (actual != expected) {
                for (StandardField entry : list) {
                    logger.error(entry.getDescription() + " | " + entry.getKey());
                }
            }
            assertEquals(actual, expected);
        }
    }

    @Test
    public void getStandardFieldsInfo() {
        String info = pedata.get("strings.exe").getOptionalHeader()
                .getStandardFieldsInfo();
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }

    @Test
    // TODO maybe better
    public void getSubsystemDescription() {
        String info = Subsystem.getForValue(13).getDescription();
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }

    @Test
    public void getWindowsFieldEntry() {
        for (TestData testdatum : testdata) {
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            for (Entry<WindowsEntryKey, String> entry : testdatum.windowsOpt
                    .entrySet()) {
                WindowsEntryKey key = entry.getKey();
                OptionalHeader opt = pedatum.getOptionalHeader();
                long actual = opt.getWindowsFieldEntry(key).getValue();
                String value = entry.getValue().trim();
                long expected = convertToLong(value);
                assertEquals(actual, expected);
            }
        }
    }

    @Test
    public void getWindowsSpecificFields() {
        for (PEData pedatum : pedata.values()) {
            Collection<StandardField> list = pedatum.getOptionalHeader()
                    .getWindowsSpecificFields().values();
            assertNotNull(list);
            assertEquals(list.size(), WindowsEntryKey.values().length);
        }
    }

    @Test
    public void getWindowsSpecificInfo() {
        String info = pedata.get("strings.exe").getOptionalHeader()
                .getWindowsSpecificInfo();
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }
}
