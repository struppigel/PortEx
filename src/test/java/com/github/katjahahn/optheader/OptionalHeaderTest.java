package com.github.katjahahn.optheader;

import static com.github.katjahahn.optheader.DataDirectoryKey.*;
import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.IOUtil;
import com.github.katjahahn.IOUtil.TestData;
import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoader;
import com.github.katjahahn.StandardEntry;
import com.github.katjahahn.optheader.OptionalHeader.MagicNumber;

public class OptionalHeaderTest {

	private List<TestData> testdata;
	private final Map<String, PEData> pedata = new HashMap<>();

	@BeforeClass
	public void prepare() throws IOException {
		File[] testfiles = IOUtil.getTestiles();
		for (File file : testfiles) {
			pedata.put(file.getName(), PELoader.loadPE(file));
		}
		testdata = IOUtil.readTestDataList();
	}

	@Test
	// TODO read from report
	public void getDataDirEntries() {
		for (PEData pedatum : pedata.values()) {
			List<DataDirEntry> list = pedatum.getOptionalHeader()
					.getDataDirEntries();
			assertNotNull(list);
			assertTrue(list.size() > 0);
		}
	}

	@Test
	public void getDataDirEntry() {
		OptionalHeader header = pedata.get("strings.exe").getOptionalHeader();
		DataDirectoryKey[] existant = { IMPORT_TABLE, RESOURCE_TABLE,
				CERTIFICATE_TABLE, DEBUG, LOAD_CONFIG_TABLE, IAT};
		for(DataDirectoryKey key : DataDirectoryKey.values()) {
			DataDirEntry entry = header.getDataDirEntry(key);
			if(isIn(existant, key)) {
				assertNotNull(entry);
			} else {
				assertNull(entry);
			}
		}
	}

	private <T> boolean isIn(T[] array, T item) {
		for (T t : array) {
			if (t.equals(item)) {
				return true;
			}
		}
		return false;
	}

	@Test
	public void getDataDirInfo() {
		String info = pedata.get("strings.exe").getOptionalHeader()
				.getDataDirInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}

	@Test
	// TODO maybe better
	public void getImageBaseDescription() {
		String info = OptionalHeader.getImageBaseDescription(0x10000000);
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}

	@Test
	public void getInfo() {
		String info = pedata.get("strings.exe").getOptionalHeader().getInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}

	@Test
	public void getMagicNumberAndString() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			OptionalHeader opt = pedatum.getOptionalHeader();
			MagicNumber magic = opt.getMagicNumber();
			String string = OptionalHeader.getMagicNumberString(magic);
			assertNotNull(magic);
			assertNotNull(string);
			assertTrue(string.length() > 0);
		}
	}

	@Test
	public void getStandardFieldEntry() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (Entry<StandardFieldEntryKey, String> entry : testdatum.standardOpt
					.entrySet()) {
				StandardFieldEntryKey key = entry.getKey();
				OptionalHeader opt = pedatum.getOptionalHeader();
				Long actual = opt.getStandardFieldEntry(key).value;
				String value = entry.getValue().trim();
				Long expected = convertToLong(value);
				assertEquals(expected, actual);
			}
		}
	}

	// TODO in Oberklasse auslagern, ebenso prepare
	private long convertToLong(String value) {
		if (value.startsWith("0x")) {
			value = value.replace("0x", "");
			return Long.parseLong(value, 16);
		} else {
			return Long.parseLong(value);
		}
	}

	@Test
	public void getStandardFields() {
		for (PEData pedatum : pedata.values()) {
			List<StandardEntry> list = pedatum.getOptionalHeader()
					.getStandardFields();
			assertNotNull(list);
			assertEquals(list.size(), StandardFieldEntryKey.values().length);
		}
	}

	@Test
	public void getStandardFieldsInfo() {
		String info = pedata.get("strings.exe").getOptionalHeader()
				.getStandardFieldsInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}

	@Test
	// TODO maybe better
	public void getSubsystemDescription() {
		String info = OptionalHeader.getSubsystemDescription(13);
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}

	@Test
	public void getWindowsFieldEntry() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (Entry<WindowsEntryKey, String> entry : testdatum.windowsOpt
					.entrySet()) {
				WindowsEntryKey key = entry.getKey();
				OptionalHeader opt = pedatum.getOptionalHeader();
				long actual = opt.getWindowsFieldEntry(key).value;
				String value = entry.getValue().trim();
				long expected = convertToLong(value);
				assertEquals(actual, expected);
			}
		}
	}

	@Test
	public void getWindowsSpecificFields() {
		for (PEData pedatum : pedata.values()) {
			List<StandardEntry> list = pedatum.getOptionalHeader()
					.getWindowsSpecificFields();
			assertNotNull(list);
			assertEquals(list.size(), WindowsEntryKey.values().length);
		}
	}

	@Test
	public void getWindowsSpecificInfo() {
		String info = pedata.get("strings.exe").getOptionalHeader()
				.getWindowsSpecificInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}
}
