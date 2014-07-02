package com.github.katjahahn.sections;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.Random;

import org.testng.annotations.Test;

import com.github.katjahahn.parser.sections.PESection;

public class PESectionTest {

	@Test
	public void getDump() throws IOException {
		Random rand = new Random();
		byte[] randomBytes = new byte[20];
		rand.nextBytes(randomBytes);
		byte[] dump = new PESection(randomBytes, 0, null, null).getBytes();
		assertEquals(randomBytes, dump);
	}

	@Test
	public void getInfo() {
		Random rand = new Random();
		byte[] randomBytes = new byte[20];
		rand.nextBytes(randomBytes);
		PESection section = new PESection(randomBytes, 0, null, null);
		String info = section.toString();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}
}
