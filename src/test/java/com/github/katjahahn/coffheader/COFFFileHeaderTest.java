package com.github.katjahahn.coffheader;

import static com.github.katjahahn.coffheader.COFFHeaderKey.*;
import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoader;

public class COFFFileHeaderTest {

	private COFFFileHeader coff;

	@BeforeClass
	public void prepare() throws IOException {
		File testfile = new File("WinRar.exe");
		PEData data = PELoader.loadPE(testfile);
		this.coff = data.getCOFFFileHeader();
	}

	@Test
	public void get() {
		int timeDate = coff.get(TIME_DATE);
		assertEquals(timeDate, 0x45adfc46);
		assertEquals(coff.get(MACHINE), 0x014c);
	}

	@Test
	public void getMachineDescription() {
		assertEquals(coff.getMachineDescription(), "Intel 386 or later processors and compatible processors");
	}

	@Test
	public void getMachineType() {
		assertEquals(coff.getMachineType(), MachineType.I386);
	}

	@Test
	public void getNumberOfSections() {
		assertEquals(coff.getNumberOfSections(), 0x04);
	}

	@Test
	public void getSizeOfOptionalHeader() {
		assertEquals(coff.getSizeOfOptionalHeader(), 0x00e0);
	}

	@Test
	public void getTimeDate() {
		Date date = coff.getTimeDate();
		Calendar calendar = Calendar.getInstance();
		calendar.clear();
		calendar.set(2007, Calendar.JANUARY, 17, 11, 36, 54);
		assertEquals(calendar.getTime().compareTo(date), 0);
	}
}
