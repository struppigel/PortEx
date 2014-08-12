package com.github.katjahahn.parser.sections;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Random;

import org.testng.annotations.Test;

public class PESectionTest {

	@Test
	public void getDump() throws IOException {
		Random rand = new Random();
		byte[] randomBytes = new byte[20];
		rand.nextBytes(randomBytes);
		byte[] dump = new PESection(randomBytes, 0, new DummyHeader(), new File("")).getBytes();
		assertEquals(randomBytes, dump);
	}

	@Test
	public void getInfo() {
		Random rand = new Random();
		byte[] randomBytes = new byte[20];
		rand.nextBytes(randomBytes);
		PESection section = new PESection(randomBytes, 0, new DummyHeader(), new File(""));
		String info = section.toString();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}
	
	public static class DummyHeader extends SectionHeader {

        public DummyHeader() {
            super(null, -1, -1, "DummyHeader", -1);
        }
	    
	}
}
