package com.github.katjahahn.coffheader;

import static org.testng.Assert.*;

import java.io.IOException;
import java.util.List;

import org.testng.annotations.Test;

import com.github.katjahahn.IOUtil;

public class FileCharacteristicTest {
  @Test
  public void coherence() throws IOException {
	 List<String[]> list = IOUtil.readArray("characteristics");
	 assertEquals(list.size(), FileCharacteristic.values().length);
	 for(String[] array : list) {
		 assertNotNull(FileCharacteristic.valueOf(array[1]));
	 }
  }
}
