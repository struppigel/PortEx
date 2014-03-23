package com.github.katjahahn;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.testng.annotations.Test;

public class IOUtilTest {

	@Test
	public void readArray() throws IOException {
		List<String[]> spec = IOUtil.readArray("msdosheaderspec");
	}

	@Test
	public void readMap() throws IOException {
		Map<String, String[]> map = IOUtil.readMap("msdosheaderspec");
	}
}
