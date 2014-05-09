package com.github.katjahahn.optheader;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

import com.github.katjahahn.IOUtil;

public class SubsystemTest {
	 @Test
	  public void coherence() throws IOException {
		 List<String[]> list = IOUtil.readArray("subsystem");
		 assertEquals(list.size(), Subsystem.values().length);
		 for(String[] array : list) {
			 assertNotNull(Subsystem.valueOf(array[1]));
		 }
	  }
}
