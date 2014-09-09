package com.github.katjahahn.parser.sections;

import static com.github.katjahahn.parser.sections.SectionHeaderKey.*;
import static org.testng.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader.TestData;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoaderTest;

public class SectionTableTest {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(SectionTableTest.class.getName());
    private List<TestData> testdata;
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        testdata = PELoaderTest.getTestData();
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void getInfo() {
        String info = pedata.get("strings.exe").getSectionTable().getInfo();
        assertNotNull(info);
        assertTrue(info.length() > 0);
    }

    // @Test slows down performance too much
    // public void maxSect() throws IOException {
    // PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR +
    // "/unusualfiles/corkami/65535sects.exe"));
    // System.out.println("Number of sections read: " +
    // data.getSectionTable().getNumberOfSections());
    // }

    @Test
    public void getPointerToRawData() {
        SectionTable table = pedata.get("strings.exe").getSectionTable();
        for (SectionHeader section : table.getSectionHeaders()) {
            long pointer = section.get(POINTER_TO_RAW_DATA);
            assertEquals(
                    table.getSectionHeader(section.getName()).get(
                            POINTER_TO_RAW_DATA), pointer);
        }
    }

    @Test
    public void getSectionByNumber() {
        for (PEData datum : pedata.values()) {
            SectionTable table = datum.getSectionTable();
            for (SectionHeader header : table.getSectionHeaders()) {
                SectionHeader entryByNum = table.getSectionHeader(header
                        .getNumber());
                assertEquals(entryByNum, header);
            }
        }
    }

    @Test
    public void getSectionByName() {
        for (PEData datum : pedata.values()) {
            SectionTable table = datum.getSectionTable();
            for (SectionHeader header : table.getSectionHeaders()) {
                SectionHeader entryByNum = table.getSectionHeader(header
                        .getName());
                assertEquals(entryByNum, header);
            }
        }
    }

    @Test
    public void getSectionEntries() {
        for (TestData testdatum : testdata) {
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            List<SectionHeader> list = pedatum.getSectionTable()
                    .getSectionHeaders();
            assertEquals(list.size(), testdatum.sections.size());
            assertEquality(list, testdatum.sections);
            assertSectionNumbers(list);
        }
    }

    private void assertSectionNumbers(List<SectionHeader> list) {
        for (int i = 0; i < list.size(); i++) {
            SectionHeader section = list.get(i);
            assertEquals(section.getNumber(), i + 1);
        }
    }

    private void assertEquality(List<SectionHeader> actualData,
            List<SectionHeader> testData) {
        for (SectionHeader section : testData) {
            assertContains(actualData, section);
        }
    }

    private void assertContains(List<SectionHeader> list, SectionHeader section) {
        // keys that are tested for equality
        SectionHeaderKey[] relevantKeys = { CHARACTERISTICS, VIRTUAL_ADDRESS,
                VIRTUAL_SIZE, POINTER_TO_RAW_DATA, SIZE_OF_RAW_DATA };
        for (SectionHeader entry : list) {
            if (entry.getName().equals(section.getName())) {
                for (SectionHeaderKey key : relevantKeys) {
                    long value1 = entry.get(key);
                    long value2 = section.get(key);
                    assertEquals(value1, value2);
                }
            }
        }
    }

    @Test
    public void getSectionEntry() {
        SectionTable table = pedata.get("strings.exe").getSectionTable();
        for (SectionHeader section : table.getSectionHeaders()) {
            SectionHeader entry = table.getSectionHeader(section.getName());
            assertEquals(entry, section);
        }
    }
}
