package com.github.katjahahn.msdos;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.PELoader;

public class MSDOSLoadModuleTest {
	
	private MSDOSLoadModule module;
	private File file;

	@BeforeClass
	public void prepare() throws IOException {
		file = new File("WinRar.exe");
		MSDOSHeader header = PELoader.loadPE(file).getMSDOSHeader();
		module = new MSDOSLoadModule(header, file);
		module.read();
	}

	@Test
	public void getDump() throws IOException {
		byte[] bytes = module.getDump();
		assertNotNull(bytes);
		assertTrue(bytes.length > 0);
	}

	@Test
	public void getLoadModuleSize() {
		int size = module.getLoadModuleSize();
		assertTrue(size > 0 && size < file.length());
	}

	@Test
	public void getImageSize() {
		int size = module.getImageSize();
		assertTrue(size > 0 && size < file.length());
	}
	
	@Test
	public void getInfo() {
		String info = module.getInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}
}
