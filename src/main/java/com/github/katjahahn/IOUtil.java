package com.github.katjahahn;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.github.katjahahn.coffheader.COFFHeaderKey;
import com.github.katjahahn.msdos.MSDOSHeaderKey;
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.sections.SectionTableEntry;
import com.github.katjahahn.sections.rsrc.ResourceDataEntry;

/**
 * Utilities for file IO needed to read maps and arrays from the text files in
 * the data subdirectory of PortEx.
 * 
 * The specification text files are CSV, where the values are separated by
 * semicolon and a new entry begins on a new line.
 * 
 * The report files for testing are done with the tool pev.
 * 
 * @author Katja Hahn
 * 
 */
public class IOUtil {

	public static final String NL = System.getProperty("line.separator");
	// TODO system independend path separators
	private static final String DELIMITER = ";";
	private static final String SPEC_DIR = "/data/";
	private static final String RESOURCE_DIR = "src/main/resources";
	private static final String TEST_FILE_DIR = "/testfiles";
	private static final String TEST_REPORTS_DIR = "/reports";

	/**
	 * Parses all testfile reports (by pev) and creates TestData instances from
	 * it.
	 * 
	 * @return list with all TestData instances
	 */
	public static List<TestData> readTestDataList() {
		List<TestData> data = new LinkedList<>();
		File directory = Paths.get(RESOURCE_DIR, TEST_REPORTS_DIR).toFile();
		for (File file : directory.listFiles()) {
			if (!file.isDirectory()) {
				data.add(readTestData(file.getName()));
			}
		}
		return data;
	}

	/**
	 * Returns a list with all files in the testfile directory.
	 * 
	 * @return all files of the testfile directory
	 */
	public static File[] getTestiles() {
		return Paths.get(RESOURCE_DIR, TEST_FILE_DIR).toFile().listFiles();
	}

	/**
	 * Parses the report (by pev) and creates a TestData instance.
	 * 
	 * TODO implement rest of the data.
	 * 
	 * @param filename
	 * @return
	 */
	public static TestData readTestData(String filename) {
		TestData data = new TestData();
		data.filename = filename;
		Path testfile = Paths.get(RESOURCE_DIR, TEST_REPORTS_DIR, filename);
		try (BufferedReader reader = Files.newBufferedReader(testfile,
				Charset.forName("UTF-8"))) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				if (line.contains("DOS header")) {
					data.dos = readDOS(reader);
				}
				if (line.contains("COFF header")) {
					data.coff = readCOFF(reader);
				}
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
		return data;
	}

	private static Map<MSDOSHeaderKey, String> readDOS(BufferedReader reader)
			throws IOException {
		Map<MSDOSHeaderKey, String> dos = new HashMap<>();
		String line = null;
		while ((line = reader.readLine()) != null) {
			String[] split = line.split(":");
			if (split.length < 2) {
				break;
			}
			MSDOSHeaderKey key = getMSDOSKeyFor(split[0]);
			if (key == null) {
				continue;
			}
			String value = split[1].trim();
			dos.put(key, value);
		}
		return dos;
	}
	
	private static Map<COFFHeaderKey, String> readCOFF(BufferedReader reader)
			throws IOException {
		Map<COFFHeaderKey, String> coff = new HashMap<>();
		String line = null;
		while ((line = reader.readLine()) != null) {
			String[] split = line.split(":");
			if (split.length < 2) {
				break;
			}
			COFFHeaderKey key = getCOFFHeaderKeyFor(split[0]);
			if (key == null) {
				continue;
			}
			String value = split[1].trim().split("\\s")[0]; //remove everything after whitespace
			coff.put(key, value);
		}
		return coff;
	}

	private static COFFHeaderKey getCOFFHeaderKeyFor(String string) {
		if (string.contains("Machine")) {
			return COFFHeaderKey.MACHINE;
		}
		if (string.contains("Number of sections")) {
			return COFFHeaderKey.SECTION_NR;
		}
		if (string.contains("Date/time stamp")) {
			return COFFHeaderKey.TIME_DATE;
		}
		if (string.contains("Symbol table offset")) {
			return null; // TODO ?
		}
		if (string.contains("Number of symbols")) {
			return null; // TODO ?
		}
		if (string.contains("Size of optional header")) {
			return COFFHeaderKey.SIZE_OF_OPT_HEADER;
		}
		if (string.contains("Characteristics")) {
			return COFFHeaderKey.CHARACTERISTICS;
		}
		return null;
	}

	private static MSDOSHeaderKey getMSDOSKeyFor(String string) {
		if (string.contains("Bytes in last page")) {
			return MSDOSHeaderKey.LAST_PAGE_SIZE;
		}
		if (string.contains("Pages in file")) {
			return MSDOSHeaderKey.FILE_PAGES;
		}
		if (string.contains("Relocations")) {
			return MSDOSHeaderKey.RELOCATION_ITEMS;
		}
		if (string.contains("Size of header in paragraphs")) {
			return MSDOSHeaderKey.HEADER_PARAGRAPHS;
		}
		if (string.contains("Minimum extra paragraphs")) {
			return MSDOSHeaderKey.MINALLOC;
		}
		if (string.contains("Maximum extra paragraphs")) {
			return MSDOSHeaderKey.MAXALLOC;
		}
		if (string.contains("SS value")) {
			return MSDOSHeaderKey.INITIAL_SS;
		}
		if (string.contains("IP value")) {
			return MSDOSHeaderKey.INITIAL_IP;
		}
		if (string.contains("SP value")) {
			return MSDOSHeaderKey.INITIAL_SP;
		}
		if (string.contains("CS value")) {
			return MSDOSHeaderKey.PRE_RELOCATED_INITIAL_CS;
		}
		if (string.contains("Address of relocation table")) {
			return MSDOSHeaderKey.RELOCATION_TABLE_OFFSET;
		}
		if (string.contains("Overlay number")) {
			return MSDOSHeaderKey.OVERLAY_NR;
		}
		// TODO: OEM identifier and OEM information missing in MSDOSspec
		// TODO: not covered in testfiles: complemented_checksum and
		// signature_word
		return null;
	}

	/**
	 * Reads the specified file into a map. The first value is used as key. The
	 * rest is put into a list and used as map value. Each entry is one line of
	 * the file.
	 * 
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	public static Map<String, String[]> readMap(String filename)
			throws IOException {
		Map<String, String[]> map = new TreeMap<>();
		try (InputStreamReader isr = new InputStreamReader(
				IOUtil.class.getResourceAsStream(SPEC_DIR + filename));
				BufferedReader reader = new BufferedReader(isr)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] values = line.split(DELIMITER);
				map.put(values[0], Arrays.copyOfRange(values, 1, values.length));
			}
			return map;
		}
	}

	/**
	 * Reads the specified file into a list of arrays. Each array is the entry
	 * of one line in the file.
	 * 
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	public static List<String[]> readArray(String filename) throws IOException {
		List<String[]> list = new LinkedList<>();
		try (InputStreamReader isr = new InputStreamReader(
				IOUtil.class.getResourceAsStream(SPEC_DIR + filename));
				BufferedReader reader = new BufferedReader(isr)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] values = line.split(DELIMITER);
				list.add(values);
			}
			return list;
		}
	}

	public static List<String> getCharacteristicsDescriptions(long value,
			String filename) {
		List<String> characteristics = new LinkedList<>();
		try {
			Map<String, String[]> map = readMap(filename);
			for (String maskStr : map.keySet()) {
				try {
					long mask = Long.parseLong(maskStr, 16);
					if ((value & mask) != 0) {
						characteristics.add(map.get(maskStr)[1]);
					}
				} catch (NumberFormatException e) {
					System.err.println("ERROR. number format mismatch in file "
							+ filename + NL);
					System.err.println("value: " + maskStr + NL);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return characteristics;
	}

	public static String getCharacteristics(long value, String filename) {
		StringBuilder b = new StringBuilder();
		try {
			Map<String, String[]> map = readMap(filename);
			for (String maskStr : map.keySet()) {
				try {
					long mask = Long.parseLong(maskStr, 16);
					if ((value & mask) != 0) {
						b.append("\t* " + map.get(maskStr)[1] + NL);
					}
				} catch (NumberFormatException e) {
					b.append("ERROR. number format mismatch in file "
							+ filename + NL);
					b.append("value: " + maskStr + NL);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (b.length() == 0) {
			b.append("\t**no characteristics**" + NL);
		}
		return b.toString();
	}

	public static class TestData {

		public Map<MSDOSHeaderKey, String> dos;
		public Map<COFFHeaderKey, String> coff;
		public Map<String, String> opt;
		public List<DataDirEntry> datadir;
		public List<SectionTableEntry> sections;
		public List<ResourceDataEntry> resources;
		public String filename;
	}

}
