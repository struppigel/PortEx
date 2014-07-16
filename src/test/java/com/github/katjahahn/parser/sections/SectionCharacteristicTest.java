package com.github.katjahahn.parser.sections;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.sections.SectionCharacteristic;

public class SectionCharacteristicTest {
	@Test
	public void coherence() throws IOException {
		List<String[]> list = IOUtil.readArray("sectioncharacteristics");
		assertEquals(list.size(), SectionCharacteristic.values().length);
		for (String[] array : list) {
			assertNotNull(SectionCharacteristic.valueOf(array[1]));
		}
	}
}
