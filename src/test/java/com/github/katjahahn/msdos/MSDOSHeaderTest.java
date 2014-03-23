package com.github.katjahahn.msdos;

import java.io.File;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class MSDOSHeaderTest {

	private File testfile;

	@BeforeClass
	public void prepare() {
		this.testfile = new File("WinRar.exe");
	}

	@Test
	public void get() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getHeaderEntries() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getHeaderSize() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void getInfo() {
		throw new RuntimeException("Test not implemented");
	}

	@Test
	public void hasSignature() {
		throw new RuntimeException("Test not implemented");
	}
}
