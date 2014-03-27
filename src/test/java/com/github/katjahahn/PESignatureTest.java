package com.github.katjahahn;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.IOUtil.TestData;

public class PESignatureTest {

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
	public void getInfo() {
		String info = pedata.get("strings.exe").getPESignature().getInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}

	@Test
	public void getPEOffset() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			int actual = pedatum.getPESignature().getPEOffset();
			int expected = testdatum.peoffset;
			assertEquals(actual, expected);
		}
	}
	
	@Test(expectedExceptions=FileFormatException.class)
	public void noPEFile() throws FileFormatException, IOException {
		new PESignature(new File("userdb.txt")).read();
	}
}
