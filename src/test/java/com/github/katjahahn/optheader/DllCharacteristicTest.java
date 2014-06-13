package com.github.katjahahn.optheader;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.optheader.DllCharacteristic;

public class DllCharacteristicTest {
	@Test
	public void coherence() throws IOException {
		List<String[]> list = IOUtil.readArray("dllcharacteristics");
		assertEquals(list.size(), DllCharacteristic.values().length);
		for (String[] array : list) {
			assertNotNull(DllCharacteristic.valueOf(array[1]));
		}
	}
}
