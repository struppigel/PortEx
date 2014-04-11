package com.github.katjahahn.sections;

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
import com.github.katjahahn.sections.idata.DirectoryTableEntry;
import com.github.katjahahn.sections.idata.ImportSection;

public class SectionLoaderTest {
	
	@SuppressWarnings("unused")
	private static final Logger logger = LogManager
			.getLogger(SectionTableTest.class.getName());
	@SuppressWarnings("unused")
	private List<TestData> testdata;
	private Map<String, PEData> pedata = new HashMap<>();

	@BeforeClass
	public void prepare() throws IOException {
		testdata = PELoaderTest.getTestData();
		pedata = PELoaderTest.getPEData();
	}
	
	@Test
	public void getDataDirEntryForKey() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getSectionByRVA() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void loadImportSection() throws IOException {
		for(PEData pedatum : pedata.values()) {
			System.err.println("testing file " + pedatum.getFile().getName());
			SectionLoader loader = new SectionLoader(pedatum);
			ImportSection idata = loader.loadImportSection();
			List<DirectoryTableEntry> directoryTable = idata.getDirectoryTable();
			assertNotNull(directoryTable);
			assertTrue(directoryTable.size() > 0);
		}
	}

	@Test
	public void loadResourceSection() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void loadSection() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void readBytesFor() {
		throw new RuntimeException("Test not implemented");
	}
}
