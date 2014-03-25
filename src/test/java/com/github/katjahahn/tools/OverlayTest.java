package com.github.katjahahn.tools;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;

import org.testng.annotations.Test;

public class OverlayTest {

	@Test(timeOut = 9000)
	public void hasOverlayTest() throws IOException {
		String[] files = { "src/main/resources/testfiles/Lab03-01.exe",
				"src/main/resources/testfiles/Lab03-04.exe",
				"src/main/resources/testfiles/Lab03-03.exe" };
		for (String file : files) {
			File infile = new File(file);
			Overlay overlay = new Overlay(infile, new File("out"));
			assertFalse(overlay.hasOverlay());
		}
		String[] overfiles = { "Holiday_Island.exe", "WinRar.exe", "joined.exe" };
		for (String file : overfiles) {
			File infile = new File(file);
			Overlay overlay = new Overlay(infile, new File("out"));
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
			Overlay overlay = new Overlay(infile, new File("out"));
			long eof = overlay.getEndOfPE();
			System.out.println("infile length: " + infile.length());
			System.out.println("EOF: " + eof);
			assertEquals(infile.length(), eof);
		}
	}

	@Test
	public void dump() throws IOException {
		String[] mixedFiles = { "src/main/resources/testfiles/Lab03-01.exe",
				"src/main/resources/testfiles/Lab03-04.exe",
				"src/main/resources/testfiles/Lab03-03.exe",
				"Holiday_Island.exe", "WinRar.exe", "joined.exe" };
		File outfile = new File("out");
		for (String file : mixedFiles) {
			File infile = new File(file);
			Overlay overlay = new Overlay(infile, outfile);
			overlay.dump();
		}
		outfile.delete();
	}

}
