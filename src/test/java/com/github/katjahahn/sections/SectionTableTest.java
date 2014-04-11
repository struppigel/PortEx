package com.github.katjahahn.sections;

import static com.github.katjahahn.sections.SectionTableEntryKey.*;
import static org.testng.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoaderTest;
import com.github.katjahahn.TestreportsReader.TestData;

public class SectionTableTest {

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

	@Test
	public void getPointerToRawData() {
		SectionTable table = pedata.get("strings.exe").getSectionTable();
		for (SectionTableEntry section : table.getSectionEntries()) {
			Long pointer = section.get(POINTER_TO_RAW_DATA);
			assertEquals(table.getPointerToRawData(section.getName()), pointer);
		}
	}

	@Test
	public void getSectionEntries() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			logger.debug("testing file " + testdatum.filename);
			List<SectionTableEntry> list = pedatum.getSectionTable()
					.getSectionEntries();
			assertEquals(list.size(), testdatum.sections.size());
			assertEquality(list, testdatum.sections);
		}
	}

	private void assertEquality(List<SectionTableEntry> actualData,
			List<SectionTableEntry> testData) {
		for (SectionTableEntry section : testData) {
			assertContains(actualData, section);
		}
	}

	private void assertContains(List<SectionTableEntry> list,
			SectionTableEntry section) {
		SectionTableEntryKey[] relevantKeys = { CHARACTERISTICS,
				VIRTUAL_ADDRESS, VIRTUAL_SIZE, POINTER_TO_RAW_DATA,
				SIZE_OF_RAW_DATA }; // key that are tested for equality, other
									// keys are not covered by testdata
		for (SectionTableEntry entry : list) {
			if (entry.getName().equals(section.getName())) {
				for (SectionTableEntryKey key : relevantKeys) {
					Long value1 = entry.get(key);
					Long value2 = section.get(key);
					if (value1 == null || !value1.equals(value2)) {
						logger.warn("comparison failed for key: " + key
								+ " and value1 " + Long.toHexString(value1)
								+ " and value2 " + Long.toHexString(value2));
					}
					assertNotNull(value1);
					assertEquals(value1, value2);
				}
			}
		}
	}

	@Test
	public void getSectionEntry() {
		SectionTable table = pedata.get("strings.exe").getSectionTable();
		for(SectionTableEntry section : table.getSectionEntries()) {
			SectionTableEntry entry = table.getSectionEntry(section.getName());
			assertEquals(entry, section);
		}
	}

	@Test
	public void getSize() {
		SectionTable table = pedata.get("strings.exe").getSectionTable();
		for(SectionTableEntry section : table.getSectionEntries()) {
			Long size = table.getSize(section.getName());
			assertEquals(size, section.get(SIZE_OF_RAW_DATA));
		}
	}

	@Test
	public void getVirtualAddress() {
		SectionTable table = pedata.get("strings.exe").getSectionTable();
		for(SectionTableEntry section : table.getSectionEntries()) {
			Long size = table.getVirtualAddress(section.getName());
			assertEquals(size, section.get(VIRTUAL_ADDRESS));
		}
	}
}
