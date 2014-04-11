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
package com.github.katjahahn.coffheader;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoader;
import com.github.katjahahn.PELoaderTest;
import com.github.katjahahn.TestreportsReader.TestData;

public class COFFFileHeaderTest {
	
	private COFFFileHeader winRarCoff;
	private List<TestData> testdata;
	private Map<String, PEData> pedata = new HashMap<>();

	@BeforeClass
	public void prepare() throws IOException {
		testdata = PELoaderTest.getTestData();
		pedata = PELoaderTest.getPEData();
		winRarCoff = PELoader.loadPE(new File("WinRar.exe"))
				.getCOFFFileHeader();
	}

	@Test
	public void get() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (Entry<COFFHeaderKey, String> entry : testdatum.coff.entrySet()) {
				COFFHeaderKey key = entry.getKey();
				COFFFileHeader coff = pedatum.getCOFFFileHeader();
				int actual = coff.get(key);
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
	public void getMachineDescription() {
		assertEquals(winRarCoff.getMachineDescription(),
				"Intel 386 or later processors and compatible processors");
	}

	@Test
	public void getMachineType() {
		assertEquals(winRarCoff.getMachineType(), MachineType.I386);
	}

	@Test
	public void getCharacteristics() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			String value = testdatum.coff.get(COFFHeaderKey.CHARACTERISTICS)
					.trim();
			int expected = convertToInt(value);
			int actual = pedatum.getCOFFFileHeader().getCharacteristics();
			assertEquals(expected, actual);
		}
	}

	@Test
	public void getInfo() {
		String info = winRarCoff.getInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}

	@Test
	public void getCharacteristicsDescription() {
		List<String> description = winRarCoff.getCharacteristicsDescriptions();
		assertEquals(description.size(), 5);
	}

	@Test
	public void getNumberOfSections() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			String value = testdatum.coff.get(COFFHeaderKey.SECTION_NR).trim();
			int expected = convertToInt(value);
			int actual = pedatum.getCOFFFileHeader().getNumberOfSections();
			assertEquals(expected, actual);
		}
		assertEquals(winRarCoff.getNumberOfSections(), 0x04);
	}

	@Test
	public void getSizeOfOptionalHeader() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			String value = testdatum.coff.get(COFFHeaderKey.SIZE_OF_OPT_HEADER)
					.trim();
			int expected = convertToInt(value);
			int actual = pedatum.getCOFFFileHeader().getSizeOfOptionalHeader();
			assertEquals(expected, actual);
		}
		assertEquals(winRarCoff.getSizeOfOptionalHeader(), 0x00e0);
	}

	@Test
	public void getTimeDate() {
		Date date = winRarCoff.getTimeDate();
		Calendar calendar = Calendar.getInstance();
		calendar.clear();
		calendar.set(2007, Calendar.JANUARY, 17, 11, 36, 54);
		assertEquals(calendar.getTime().compareTo(date), 0);
	}
}
