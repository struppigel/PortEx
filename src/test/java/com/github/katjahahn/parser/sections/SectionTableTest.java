package com.github.katjahahn.parser.sections;

import static com.github.katjahahn.parser.sections.SectionHeaderKey.*;
import static org.testng.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.github.katjahahn.parser.HeaderKey;
import com.github.katjahahn.parser.StandardField;
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
            // ignore
            if(datum.getFile().getName().equals("baed21297974b6adf3298585baa78691")) continue;
            System.out.println(datum.getFile().getName());
            for (SectionHeader header : table.getSectionHeaders()) {
                SectionHeader entryByNum = table.getSectionHeader(header
                        .getName());
                assertEquals(entryByNum, header);
            }
        }
    }

    @Test
    public void getSectionEntries() {
        PEData data = pedata.get("strings.exe");
        List<SectionHeader> expectedHeaders = new LinkedList<SectionHeader>();
        Map<SectionHeaderKey, StandardField> textEntries = new HashMap<>();
        put(textEntries, POINTER_TO_RAW_DATA, 0x400L);
        put(textEntries, VIRTUAL_ADDRESS, 0x1000L);
        put(textEntries, VIRTUAL_SIZE,0x3f010L);
        put(textEntries, CHARACTERISTICS, 1610612768L);
        put(textEntries, SIZE_OF_RAW_DATA,0x3f200L);
        expectedHeaders.add(new SectionHeader(textEntries, 1, 0, ".text", 0));

        Map<SectionHeaderKey, StandardField> rdataEntries = new HashMap<>();
        expectedHeaders.add(new SectionHeader(rdataEntries, 2, 0, ".rdata", 0));
        put(rdataEntries, POINTER_TO_RAW_DATA, 0x3f600L);
        put(rdataEntries, VIRTUAL_ADDRESS, 0x41000L);
        put(rdataEntries, VIRTUAL_SIZE,0xf9f2L);
        put(rdataEntries, CHARACTERISTICS, 1073741888L);
        put(rdataEntries, SIZE_OF_RAW_DATA,0xfa00L);

        Map<SectionHeaderKey, StandardField> dataEntries = new HashMap<>();
        expectedHeaders.add(new SectionHeader(dataEntries, 3, 0, ".data", 0));
        put(dataEntries, POINTER_TO_RAW_DATA, 0x4f000L);
        put(dataEntries, VIRTUAL_ADDRESS, 0x51000L);
        put(dataEntries, VIRTUAL_SIZE,0x1d3cL);
        put(dataEntries, CHARACTERISTICS, 3221225536L);
        put(dataEntries, SIZE_OF_RAW_DATA,0xc00L);

        Map<SectionHeaderKey, StandardField> rsrcEntries = new HashMap<>();
        expectedHeaders.add(new SectionHeader(rsrcEntries, 4, 0, ".rsrc", 0));
        put(rsrcEntries, POINTER_TO_RAW_DATA, 0x4fc00L);
        put(rsrcEntries, VIRTUAL_ADDRESS, 0x53000L);
        put(rsrcEntries, VIRTUAL_SIZE,0x588L);
        put(rsrcEntries, CHARACTERISTICS, 1073741888L);
        put(rsrcEntries, SIZE_OF_RAW_DATA,0x600L);

        Map<SectionHeaderKey, StandardField> relocEntries = new HashMap<>();
        expectedHeaders.add(new SectionHeader(relocEntries, 5, 0, ".reloc", 0));
        put(relocEntries, POINTER_TO_RAW_DATA, 0x50200L);
        put(relocEntries, VIRTUAL_ADDRESS, 0x54000L);
        put(relocEntries, VIRTUAL_SIZE,0x2524L);
        put(relocEntries, CHARACTERISTICS, 1107296320L);
        put(relocEntries, SIZE_OF_RAW_DATA,0x2600L);

        List<SectionHeader> actualHeaders = data.getSectionTable().getSectionHeaders();

        assertEquals(actualHeaders.size(), expectedHeaders.size());
        assertEquality(actualHeaders, expectedHeaders);
        assertSectionNumbers(actualHeaders);
    }

    private void put(Map<SectionHeaderKey, StandardField> map, SectionHeaderKey key, long value) {
        map.put(key, new StandardField(key, "", value, 0, 0) );
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
