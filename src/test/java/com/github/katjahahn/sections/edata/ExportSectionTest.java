package com.github.katjahahn.sections.edata;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoaderTest;
import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.sections.SectionLoader;
import com.github.katjahahn.sections.SectionTableTest;

public class ExportSectionTest {

	@SuppressWarnings("unused")
	private static final Logger logger = LogManager
			.getLogger(SectionTableTest.class.getName());
	private Map<File, List<ExportEntry>> exportEntries;
	private Map<String, PEData> pedata = new HashMap<>();

	@BeforeClass
	public void prepare() throws IOException {
		exportEntries = TestreportsReader.readExportEntries();
		pedata = PELoaderTest.getPEData();
	}

	@Test
	public void getExportEntries() throws IOException {
		for (Entry<File, List<ExportEntry>> set : exportEntries.entrySet()) {
			File file = set.getKey();
			List<ExportEntry> expected = set.getValue();
			String filename = file.getName().replace(".txt", "");
			System.out.println("testing: " + filename);
			System.out.println("exists: " + new File(filename).exists());
			for (Entry<String, PEData> pedatum : pedata.entrySet()) {
				if (pedatum.getKey().contains(filename)) {
					SectionLoader loader = new SectionLoader(
							pedata.get(filename));
					ExportSection edata = loader.loadExportSection();
					if (edata == null) {
						assertTrue(expected.size() == 0);
					} else {
						List<ExportEntry> actual = edata.getExportEntries();
						assertEquals(actual, expected);
					}
					break;
				}
			}
		}
	}
}
