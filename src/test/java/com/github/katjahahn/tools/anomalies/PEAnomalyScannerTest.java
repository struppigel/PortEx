package com.github.katjahahn.tools.anomalies;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.HeaderKey;
import com.github.katjahahn.StandardEntry;
import com.github.katjahahn.coffheader.COFFHeaderKey;
import com.github.katjahahn.optheader.WindowsEntryKey;

public class PEAnomalyScannerTest {

	private static final String FOLDER = "src/main/resources/unusualfiles/";
	private List<Anomaly> tinyAnomalies;

	@BeforeClass
	public void prepare() {
		File file = new File(FOLDER + "tinype/tinyest.exe");
		PEAnomalyScanner scanner = PEAnomalyScanner.getInstance(file);
		tinyAnomalies = scanner.getAnomalies();
	}

	@Test
	public void collapsedOptionalHeader() throws IOException {
		performTest(tinyAnomalies, COFFHeaderKey.SIZE_OF_OPT_HEADER,
				"SizeOfOptionalHeader");
		performTest(tinyAnomalies, AnomalyType.STRUCTURE, "Collapsed Optional Header");
	}

	public void performTest(List<Anomaly> anomalies, HeaderKey key,
			String description) {
		boolean containsKey = false;
		for (Anomaly anomaly : anomalies) {
			StandardEntry entry = anomaly.standardEntry();
			System.out.println("entry: " + entry);
			if (entry != null && key != null) {
				if (key.equals(entry.key)) {
					containsKey = true;
					assertTrue(anomaly.description().contains(description));
					break;
				}
			}
		}
		assertTrue(containsKey);
	}

	public void performTest(List<Anomaly> anomalies, AnomalyType type,
			String description) {
		boolean containsType = false;
		for (Anomaly anomaly : anomalies) {
			System.out.println(anomaly);
			if (anomaly.getType() == type && anomaly.description().contains(description)) {
				containsType = true;
				break;
			}
		}
		assertTrue(containsType);
	}

	@Test
	public void collapsedMSDOSHeader() {
		performTest(tinyAnomalies, AnomalyType.STRUCTURE, "Collapsed MSDOS Header");
	}

	@Test
	public void noDataDirs() {
		performTest(tinyAnomalies, AnomalyType.STRUCTURE, "Data Directory");
	}

	@Test
	public void fileAlignment() {
		performTest(tinyAnomalies, WindowsEntryKey.FILE_ALIGNMENT,
				"File Alignment must be between 512 and 64 K");
	}

	// @Test
	// public void getAnomalies() {
	// throw new RuntimeException("Test not implemented");
	// }
	//
	// @Test
	// public void scan() {
	// throw new RuntimeException("Test not implemented");
	// }
	//
	// @Test
	// public void scanReport() {
	// throw new RuntimeException("Test not implemented");
	// }
}
