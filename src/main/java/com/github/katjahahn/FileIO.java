package com.github.katjahahn;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class FileIO {
	
	private static final String DELIMITER = ";";
	private static final String SPEC_DIR = "data/";

	/**
	 * @param file
	 *            file to get the bytes from
	 * @return byte array that represents the given file
	 * @throws IOException
	 */
	public static byte[] getBytesFromFile(File file) throws IOException {
		byte[] data = null;
		try (FileInputStream fileInputStream = new FileInputStream(file)) {
			data = new byte[(int) file.length()];
			fileInputStream.read(data);
		}
		return data;
	}

	public static List<String> readFile(String filename) throws IOException {
		List<String> lines = new LinkedList<>();
		try (BufferedReader reader = Files.newBufferedReader(
				new File(filename).toPath(), StandardCharsets.UTF_8)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				lines.add(line);
			}
			return lines;
		}
	}

	public static Map<String, String[]> readMap(String filename)
			throws IOException {
		Map<String, String[]> map = new TreeMap<>();
		try (BufferedReader reader = Files.newBufferedReader(
				new File(SPEC_DIR + filename).toPath(), StandardCharsets.UTF_8)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] values = line.split(DELIMITER);
				map.put(values[0], Arrays.copyOfRange(values, 1, values.length));
			}
			return map;
		}
	}
	
	public static List<String[]> readArray(String filename)
			throws IOException {
		List<String[]> list = new LinkedList<>();
		try (BufferedReader reader = Files.newBufferedReader(
				new File(SPEC_DIR + filename).toPath(), StandardCharsets.UTF_8)) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] values = line.split(DELIMITER);
				list.add(values);
			}
			return list;
		}
	}
}
