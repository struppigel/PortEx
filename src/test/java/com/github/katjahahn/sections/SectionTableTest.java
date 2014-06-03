package com.github.katjahahn.sections;

import static com.github.katjahahn.sections.SectionHeaderKey.*;
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
import com.google.common.base.Optional;

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
		for (SectionHeader section : table.getSectionHeaders()) {
			Long pointer = section.getValue(POINTER_TO_RAW_DATA);
			assertEquals(table.getPointerToRawData(section.getName()), pointer);
		}
	}
	
	@Test
	public void getSectionByNumber() {
		for(PEData datum : pedata.values()) {
			SectionTable table = datum.getSectionTable();
			for(SectionHeader header : table.getSectionHeaders()) {
				SectionHeader entryByNum = table.getSectionHeader(header.getNumber());
				assertEquals(entryByNum, header);
			}
		}
	}
	
	@Test
	public void getSectionByName() {
		for(PEData datum : pedata.values()) {
			SectionTable table = datum.getSectionTable();
			for(SectionHeader header : table.getSectionHeaders()) {
				SectionHeader entryByNum = table.getSectionHeader(header.getName());
				assertEquals(entryByNum, header);
			}
		}
	}

	@Test
	public void getSectionEntries() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			logger.debug("testing file " + testdatum.filename);
			List<SectionHeader> list = pedatum.getSectionTable()
					.getSectionHeaders();
			assertEquals(list.size(), testdatum.sections.size());
			assertEquality(list, testdatum.sections);
			assertSectionNumbers(list);
		}
	}
	
	private void assertSectionNumbers(List<SectionHeader> list) {
		for(int i = 0; i < list.size(); i++) {
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

	private void assertContains(List<SectionHeader> list,
			SectionHeader section) {
		SectionHeaderKey[] relevantKeys = { CHARACTERISTICS,
				VIRTUAL_ADDRESS, VIRTUAL_SIZE, POINTER_TO_RAW_DATA,
				SIZE_OF_RAW_DATA }; // key that are tested for equality, other
									// keys are not covered by testdata
		for (SectionHeader entry : list) {
			if (entry.getName().equals(section.getName())) {
				for (SectionHeaderKey key : relevantKeys) {
					Optional<Long> value1 = entry.get(key);
					Optional<Long> value2 = section.get(key);
					if (!value1.isPresent() || !value1.equals(value2)) {
						logger.warn("comparison failed for key: " + key
								+ " and value1 " + value1
								+ " and value2 " + value2);
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
		for(SectionHeader section : table.getSectionHeaders()) {
			SectionHeader entry = table.getSectionHeader(section.getName());
			assertEquals(entry, section);
		}
	}

	@Test
	public void getSize() {
		SectionTable table = pedata.get("strings.exe").getSectionTable();
		for(SectionHeader section : table.getSectionHeaders()) {
			Long size = table.getSize(section.getName());
			assertEquals(size, section.get(SIZE_OF_RAW_DATA).get());
		}
	}

	@Test
	public void getVirtualAddress() {
		SectionTable table = pedata.get("strings.exe").getSectionTable();
		for(SectionHeader section : table.getSectionHeaders()) {
			Long size = table.getVirtualAddress(section.getName());
			assertEquals(size, section.get(VIRTUAL_ADDRESS).get());
		}
	}
}
