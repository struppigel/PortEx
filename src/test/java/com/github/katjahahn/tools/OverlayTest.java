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
package com.github.katjahahn.tools;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.Test;

public class OverlayTest {
	
	private static final Logger logger = LogManager
			.getLogger(OverlayTest.class.getName());

	@Test(timeOut = 9000)
	public void hasOverlayTest() throws IOException {
		String[] files = { "src/main/resources/testfiles/Lab03-01.exe",
				"src/main/resources/testfiles/Lab03-04.exe",
				"src/main/resources/testfiles/Lab03-03.exe" };
		for (String file : files) {
			File infile = new File(file);
			Overlay overlay = new Overlay(infile);
			assertFalse(overlay.hasOverlay());
		}
		String[] overfiles = { "Holiday_Island.exe", "WinRar.exe", "joined.exe" };
		for (String file : overfiles) {
			File infile = new File(file);
			Overlay overlay = new Overlay(infile);
			assertTrue(overlay.hasOverlay());
		}
	}

	@Test(timeOut = 9000)
	public void eofNoOverlayTest() throws IOException {
		String[] noOverFiles = { "src/main/resources/testfiles/Lab03-01.exe",
				"src/main/resources/testfiles/Lab03-04.exe",
				"src/main/resources/testfiles/Lab03-03.exe" };
		for (String file : noOverFiles) {
			File infile = new File(file);
			Overlay overlay = new Overlay(infile);
			long eof = overlay.getOverlayOffset();
			logger.debug("infile length: " + infile.length());
			logger.debug("EOF: " + eof);
			assertEquals(infile.length(), eof);
		}
	}

	@Test
	public void dumpTo() throws IOException {
		String[] mixedFiles = { "src/main/resources/testfiles/Lab03-01.exe",
				"src/main/resources/testfiles/Lab03-04.exe",
				"src/main/resources/testfiles/Lab03-03.exe",
				"Holiday_Island.exe", "WinRar.exe", "joined.exe" };
		File outfile = new File("out");
		for (String file : mixedFiles) {
			File infile = new File(file);
			Overlay overlay = new Overlay(infile);
			overlay.dumpTo(outfile);
		}
		outfile.delete();
	}

}
