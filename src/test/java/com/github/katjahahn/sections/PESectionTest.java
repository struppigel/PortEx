package com.github.katjahahn.sections;

import static org.testng.Assert.*;

import java.util.Random;

import org.testng.annotations.Test;

public class PESectionTest {

	@Test
	public void getDump() {
		Random rand = new Random();
		byte[] randomBytes = new byte[20];
		rand.nextBytes(randomBytes);
		byte[] dump = new PESection(randomBytes).getDump();
		assertEquals(randomBytes, dump);
	}

	@Test
	public void getInfo() {
		Random rand = new Random();
		byte[] randomBytes = new byte[20];
		rand.nextBytes(randomBytes);
		PESection section = new PESection(randomBytes);
		String info = section.getInfo();
		assertNotNull(info);
		assertTrue(info.length() > 0);
	}
}
