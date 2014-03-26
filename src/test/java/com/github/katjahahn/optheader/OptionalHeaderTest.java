package com.github.katjahahn.optheader;

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
	public void getDataDirEntries() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getDataDirEntry() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getDataDirInfo() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getImageBaseDescription() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getInfo() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getMagicNumber() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getMagicNumberString() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getStandardFieldEntry() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (Entry<StandardFieldEntryKey, String> entry : testdatum.standardOpt.entrySet()) {
				StandardFieldEntryKey key = entry.getKey();
				OptionalHeader opt = pedatum.getOptionalHeader();
				Long actual = opt.getStandardFieldEntry(key).value;
				String value = entry.getValue().trim();
				Long expected = convertToLong(value);
				assertEquals(expected, actual);
			}
		}
	}
	
	//TODO in Oberklasse auslagern, ebenso prepare
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
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getStandardFieldsInfo() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getSubsystemDescription() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getWindowsFieldEntry() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (Entry<WindowsEntryKey, String> entry : testdatum.windowsOpt.entrySet()) {
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
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getWindowsSpecificInfo() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void readMagicNumber() {
		throw new RuntimeException("Test not implemented");
	}
}
