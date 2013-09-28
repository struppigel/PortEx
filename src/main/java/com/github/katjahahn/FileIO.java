package com.github.katjahahn;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class FileIO {

	private static final String DELIMITER = ";";
	private static final String SPEC_DIR = "/data/";

	public static Map<String, String[]> readMap(String filename)
			throws IOException {
		Map<String, String[]> map = new TreeMap<>();
		try (InputStreamReader isr = new InputStreamReader(
				FileIO.class.getResourceAsStream(SPEC_DIR + filename));
				BufferedReader reader = new BufferedReader(isr)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] values = line.split(DELIMITER);
				map.put(values[0], Arrays.copyOfRange(values, 1, values.length));
			}
			return map;
		}
	}

	public static List<String[]> readArray(String filename) throws IOException {
		List<String[]> list = new LinkedList<>();
		try (InputStreamReader isr = new InputStreamReader(
				FileIO.class.getResourceAsStream(SPEC_DIR + filename));
				BufferedReader reader = new BufferedReader(isr)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] values = line.split(DELIMITER);
				list.add(values);
			}
			return list;
		}
	}
}
