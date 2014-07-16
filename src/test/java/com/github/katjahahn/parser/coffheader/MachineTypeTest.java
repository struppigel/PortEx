package com.github.katjahahn.parser.coffheader;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.coffheader.MachineType;

public class MachineTypeTest {
	@Test
	public void coherence() throws IOException {
		List<String[]> list = IOUtil.readArray("machinetype");
		assertEquals(list.size(), MachineType.values().length);
		for (String[] array : list) {
			assertNotNull(MachineType.valueOf(array[1].replace("IMAGE_FILE_MACHINE_", "")));
		}
	}
}
