package com.github.katjahahn.msdos;

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

public class MSDOSHeaderTest {

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
	public void get() {
		for(TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (Entry<MSDOSHeaderKey, String> entry : testdatum.dos.entrySet()) {
				MSDOSHeaderKey key = entry.getKey();
				MSDOSHeader dos = pedatum.getMSDOSHeader();
				int actual = dos.get(key).value;
				String value = entry.getValue().trim();
				int expected = convertToInt(value);
				assertEquals(expected, actual);
			}
		}
	}

	private int convertToInt(String value) {
		if (value.startsWith("0x")) {
			value = value.replace("0x", "");
			return Integer.parseInt(value, 16);
		} else {
			return Integer.parseInt(value);
		}
	}

	@Test
	public void getHeaderEntries() {
		throw new RuntimeException("Test not implemented");
	}
}
