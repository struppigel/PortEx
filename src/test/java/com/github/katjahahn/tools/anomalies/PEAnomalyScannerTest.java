package com.github.katjahahn.tools.anomalies;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.List;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.HeaderKey;
import com.github.katjahahn.StandardEntry;
import com.github.katjahahn.coffheader.COFFHeaderKey;
import com.github.katjahahn.optheader.WindowsEntryKey;
import com.github.katjahahn.sections.SectionHeaderKey;

public class PEAnomalyScannerTest {

	private static final String FOLDER = "src/main/resources/unusualfiles/";
	private List<Anomaly> tinyAnomalies;
	private List<Anomaly> maxSecXPAnomalies;
	private List<Anomaly> sectionlessAnomalies;

	@BeforeClass
	public void prepare() {
		File file = new File(FOLDER + "tinype/tinyest.exe");
		PEAnomalyScanner scanner = PEAnomalyScanner.getInstance(file);
		tinyAnomalies = scanner.getAnomalies();
		file = Paths.get(FOLDER, "corkami", "max_secXP.exe").toFile();
		scanner = PEAnomalyScanner.getInstance(file);
		maxSecXPAnomalies = scanner.getAnomalies();
		file = Paths.get(FOLDER, "corkami", "sectionless.exe").toFile();
		scanner = PEAnomalyScanner.getInstance(file);
		sectionlessAnomalies = scanner.getAnomalies();
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
		performTest(tinyAnomalies, AnomalyType.STRUCTURE, "NumberOfRVAAndSizes not given");
	}
	
	@Test
	public void nonZeroSectionHeaderFields() {
		performTest(tinyAnomalies, SectionHeaderKey.POINTER_TO_RELOCATIONS, "POINTER_TO_RELOCATIONS");
		performTest(tinyAnomalies, SectionHeaderKey.NUMBER_OF_RELOCATIONS, "NUMBER_OF_RELOCATIONS");
		performTest(tinyAnomalies, SectionHeaderKey.POINTER_TO_LINE_NUMBERS, "POINTER_TO_LINE_NUMBERS");
	}
	
	
	@Test 
	public void reservedSectionHeaderFields() {
		performTest(tinyAnomalies, AnomalyType.RESERVED, "Reserved characteristic used: RESERVED_4");
	}
	
	@Test
	public void sectionNrAnomaly() {
		File file = Paths.get(FOLDER, "corkami", "max_secW7.exe").toFile();
		PEAnomalyScanner scanner = PEAnomalyScanner.getInstance(file);
		List<Anomaly> anomalies = scanner.getAnomalies();
		performTest(anomalies, AnomalyType.WRONG, "Section Number");
	}
	
	@Test
	public void overlayHeader() {
		performTest(sectionlessAnomalies, AnomalyType.STRUCTURE, "PE Header moved to Overlay");
	}
	
	@Test
	public void deprecated() {
		performTest(maxSecXPAnomalies, AnomalyType.DEPRECATED, "COFF line numbers have been removed");
		performTest(maxSecXPAnomalies, AnomalyType.DEPRECATED, "COFF symbol table entries");
		performTest(sectionlessAnomalies, AnomalyType.DEPRECATED, "COFF symbol table entries");
		performTest(sectionlessAnomalies, AnomalyType.DEPRECATED, "COFF line numbers have been removed");
	}

	@Test
	public void fileAlignment() {
		performTest(tinyAnomalies, WindowsEntryKey.FILE_ALIGNMENT,
				"File Alignment must be between 512 and 64 K");
		performTest(sectionlessAnomalies, WindowsEntryKey.FILE_ALIGNMENT,
				"File Alignment must be between 512 and 64 K");
	}
	
	@Test
	public void sectionAlignment() {
		performTest(maxSecXPAnomalies, AnomalyType.WRONG, "Size of Image");
		performTest(maxSecXPAnomalies, AnomalyType.WRONG, "Size of Headers");
		performTest(sectionlessAnomalies, AnomalyType.WRONG, "Size of Image");
		performTest(sectionlessAnomalies, AnomalyType.WRONG, "Size of Headers");
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
