package com.github.katjahahn.sections;

import static org.testng.Assert.*;

import java.io.EOFException;
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
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.sections.edata.ExportSection;
import com.github.katjahahn.sections.idata.ImportSection;
import com.github.katjahahn.sections.rsrc.ResourceSection;

public class SectionLoaderTest {

	@SuppressWarnings("unused")
	private static final Logger logger = LogManager
			.getLogger(SectionLoaderTest.class.getName());
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
	public void loadExportSection() throws IOException {
		for (TestData testdatum : testdata) {
			List<DataDirEntry> testDirs = testdatum.dataDir;
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (DataDirEntry testDir : testDirs) {
				if (testDir.key.equals(DataDirectoryKey.EXPORT_TABLE)) {
					ExportSection edata = new SectionLoader(pedatum)
							.loadExportSection();
					assertNotNull(edata);
				}
			}
		}
	}

	@Test
	public void loadImportSection() throws IOException {
		for (TestData testdatum : testdata) {
			List<DataDirEntry> testDirs = testdatum.dataDir;
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (DataDirEntry testDir : testDirs) {
				if (testDir.key.equals(DataDirectoryKey.IMPORT_TABLE)) {
					ImportSection idata = new SectionLoader(pedatum)
							.loadImportSection();
					assertNotNull(idata);
				}
			}
		}
	}

	@Test
	public void loadResourceSection() throws IOException {
		for (TestData testdatum : testdata) {
			List<DataDirEntry> testDirs = testdatum.dataDir;
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (DataDirEntry testDir : testDirs) {
				if (testDir.key.equals(DataDirectoryKey.RESOURCE_TABLE)) {
					ResourceSection rsrc = new SectionLoader(pedatum)
							.loadResourceSection(false);
					assertNotNull(rsrc);
				}
			}
		}
	}
	
	@Test
	public void loadSectionWithSizePatch() throws IOException {
		PEData datum = pedata.get("Lab05-01.dll");
		PESection section = new SectionLoader(datum).loadSection(".reloc", true);
		long size = datum.getFile().length() - datum.getSectionTable().getPointerToRawData(".reloc");
		assertEquals(section.getDump().length, size);
	}

	@Test(expectedExceptions = EOFException.class)
	public void loadSectionWithSizeAnomaly() throws IOException {
		PEData datum = pedata.get("Lab05-01.dll");
		new SectionLoader(datum).loadSection(".reloc", false);
	}

	@Test
	public void loadSection() throws IOException {
		for (PEData datum : pedata.values()) {
			// exclude file with section size anomaly
			if (datum.getFile().getName().equals("Lab05-01.dll")) {
				continue;
			}
			SectionLoader loader = new SectionLoader(datum);
			SectionTable table = datum.getSectionTable();
			for (SectionTableEntry entry : table.getSectionEntries()) {
				String name = entry.getName();
				PESection section = loader.loadSection(name);
				assertNotNull(section);
				assertEquals(section.getDump().length,
						entry.get(SectionTableEntryKey.SIZE_OF_RAW_DATA)
								.intValue());
			}
		}
	}

	@Test
	public void readBytesFor() {
		throw new RuntimeException("Test not implemented");
	}
}
