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

import com.github.katjahahn.IOUtil.TestData;
import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoaderTest;

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
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getPointerToRawData() {
		throw new RuntimeException("Test not implemented");
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
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getSize() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getSizeOfRawData() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getVirtualAddress() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void read() {
		throw new RuntimeException("Test not implemented");
	}
}
