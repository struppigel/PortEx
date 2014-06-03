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

import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoader;
import com.github.katjahahn.PELoaderTest;
import com.github.katjahahn.StandardField;
import com.github.katjahahn.TestreportsReader.TestData;

public class MSDOSHeaderTest {

	private List<TestData> testdata;
	private Map<String, PEData> pedata = new HashMap<>();

	@BeforeClass
	public void prepare() throws IOException {
		testdata = PELoaderTest.getTestData();
		pedata = PELoaderTest.getPEData();
	}

	@Test
	public void get() {
		for (TestData testdatum : testdata) {
			PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
			for (Entry<MSDOSHeaderKey, String> entry : testdatum.dos.entrySet()) {
				MSDOSHeaderKey key = entry.getKey();
				MSDOSHeader dos = pedatum.getMSDOSHeader();
				int actual = (int) dos.getValue(key);
				String value = entry.getValue().trim();
				int expected = convertToInt(value);
				assertEquals(expected, actual);
			}
		}
	}

	@Test(expectedExceptions = IOException.class)
	public void noPEFile() throws IOException {
		PELoader.loadPE(new File("build.sbt"));
	}

	@Test(expectedExceptions = IllegalArgumentException.class, 
			expectedExceptionsMessageRegExp = "not enough headerbytes for MS DOS Header")
	public void headerBytesTooShort() throws IOException {
		byte[] headerbytes = { 1, 2, 3 };
		new MSDOSHeader(headerbytes, 0).read();
	}

	@Test(expectedExceptions = IOException.class, expectedExceptionsMessageRegExp = "No PE Signature found")
	public void invalidHeaderBytes() throws IOException {
		byte[] headerbytes = new byte[28];
		for (int i = 0; i < headerbytes.length; i++) {
			headerbytes[i] = (byte) i;
		}
		new MSDOSHeader(headerbytes, 0).read();
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
	public void getInfo() {
		String info = pedata.get("strings.exe").getMSDOSHeader().getInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
//		String noHeaderBytes = new MSDOSHeader(null).getInfo(); //TODO
//		System.out.println(noHeaderBytes);
//		assertTrue(noHeaderBytes.contains("No MS DOS Header found!"));
	}
	
	@Test
	public void getHeaderSize() throws IOException {
		File file = new File("WinRar.exe");
		long size = PELoader.loadPE(file).getMSDOSHeader().getHeaderSize();
		assertTrue(size > 0 && size < file.length());
	}
	
	@Test
	public void getHeaderEntries() {
		List<StandardField> list = pedata.get("strings.exe").getMSDOSHeader()
				.getHeaderEntries();
		assertNotNull(list);
		assertEquals(list.size(), MSDOSHeaderKey.values().length);
	}
}
