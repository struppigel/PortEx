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
import com.github.katjahahn.sections.rsrc.ResourceSection;

public class SectionLoaderTest {

	private static final Logger logger = LogManager
			.getLogger(SectionLoaderTest.class.getName());
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

	@Test //TODO compare to results from pev/other, note the case where no import section is there
	public void loadImportSection() throws IOException {
		for (PEData pedatum : pedata.values()) {
			SectionLoader loader = new SectionLoader(pedatum);
			ImportSection idata = loader.loadImportSection();
			List<DirectoryTableEntry> directoryTable = idata
					.getDirectoryTable();
			assertNotNull(directoryTable);
			assertTrue(directoryTable.size() > 0);
		}
	}

	@Test //TODO compare to results from pev/other; note the case where no rsrc section is there
	public void loadResourceSection() throws IOException {
		for (PEData pedatum : pedata.values()) {
			logger.info("testing file " + pedatum.getFile().getName());
			SectionLoader loader = new SectionLoader(pedatum);
			ResourceSection section = loader.loadResourceSection();
			assertNotNull(section.getResourceTable());
		}
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
