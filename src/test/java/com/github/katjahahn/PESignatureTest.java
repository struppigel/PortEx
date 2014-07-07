/*******************************************************************************
 * Copyright 2014 Katja Hahn
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package com.github.katjahahn;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader.TestData;
import com.github.katjahahn.parser.FileFormatException;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PESignature;

public class PESignatureTest {

	private List<TestData> testdata;
	private Map<String, PEData> pedata = new HashMap<>();

	@BeforeClass
	public void prepare() throws IOException {
		testdata = PELoaderTest.getTestData();
		pedata = PELoaderTest.getPEData();
	}
	
	@Test
	public void getInfo() {
		String info = pedata.get("strings.exe").getPESignature().getInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}

	@Test
	public void getOffset() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			int actual = (int) pedatum.getPESignature().getOffset();
			int expected = testdatum.peoffset;
			assertEquals(actual, expected);
		}
	}
	
	@Test(expectedExceptions=FileFormatException.class)
	public void noPEFile() throws FileFormatException, IOException {
		new PESignature(new File("build.sbt")).read();
	}
	
	@Test(expectedExceptions=IOException.class)
	public void noFile() throws FileFormatException, IOException {
		new PESignature(new File("unknown")).read();
	}
}
