package com.github.katjahahn.msdos;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Map.Entry;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.IOUtil;
import com.github.katjahahn.IOUtil.TestData;
import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoader;

public class MSDOSHeaderTest {

	private File testfile;
	private TestData testdata;
	private PEData pedata;

	//TODO test engine that fetches all test files
	
	@BeforeClass
	public void prepare() throws IOException {
		testfile = new File("src/main/java/resources/testfiles/strings.exe");
		testdata = IOUtil.readTestData("strings.exe.txt");
		pedata = PELoader.loadPE(testfile);
	}

	@Test
	public void get() {
		for (Entry<MSDOSHeaderKey, String> entry : testdata.dos.entrySet()) {
			MSDOSHeaderKey key = entry.getKey();
			MSDOSHeader dos = pedata.getMSDOSHeader();
			int actual = dos.get(key).value;
			String value = entry.getValue().trim();
			int expected = convertToInt(value);
			assertEquals(expected, actual);
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
