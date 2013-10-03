package com.github.katjahahn.pemodules;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.github.katjahahn.FileIO;

public abstract class PEModule {

	public static final String NL = System.getProperty("line.separator");

	public abstract String getInfo();
	
	protected static List<String> getCharacteristicsDescriptions(long value, String filename) {
		List<String> characteristics = new LinkedList<>();
		try { 
			Map<String, String[]> map = FileIO.readMap(filename);
			for (String maskStr : map.keySet()) {
				try {
					long mask = Long.parseLong(maskStr, 16);
					if ((value & mask) != 0) {
						characteristics.add(map.get(maskStr)[1]);
					}
				} catch (NumberFormatException e) {
					System.err.println("ERROR. number format mismatch in file "
							+ filename + NL);
					System.err.println("value: " + maskStr + NL);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return characteristics;
	}

	protected static String getCharacteristics(long value, String filename) {
		StringBuilder b = new StringBuilder();
		try {
			Map<String, String[]> map = FileIO.readMap(filename);
			for (String maskStr : map.keySet()) {
				try {
					long mask = Long.parseLong(maskStr, 16);
					if ((value & mask) != 0) {
						b.append("\t* " + map.get(maskStr)[1] + NL);
					}
				} catch (NumberFormatException e) {
					b.append("ERROR. number format mismatch in file "
							+ filename + NL);
					b.append("value: " + maskStr + NL);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (b.length() == 0) {
			b.append("\t**no characteristics**" + NL);
		}
		return b.toString();
	}

	/**
	 * Gets the integer value of a subarray of bytes. The values are considered
	 * little endian. The subarray is determined by offset and length.
	 * 
	 * @param bytes
	 * @param offset
	 * @param length
	 * @return
	 */
	protected static int getBytesIntValue(byte[] bytes, int offset, int length) {
		byte[] value = Arrays.copyOfRange(bytes, offset, offset + length);
		return bytesToInt(value);
	}

	/**
	 * Gets the long value of a subarray of bytes. The values are considered
	 * little endian. The subarray is determined by offset and length.
	 * 
	 * @param bytes
	 * @param offset
	 * @param length
	 * @return
	 */
	protected static long getBytesLongValue(byte[] bytes, int offset, int length) {
		byte[] value = Arrays.copyOfRange(bytes, offset, offset + length);
		return bytesToLong(value);
	}

	/**
	 * Helping method to convert a byte array to a hex String
	 * 
	 * @param array
	 * @return
	 */
	protected static String convertByteToHex(byte array[]) {
		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < array.length; i++) {
			if ((array[i] & 0xff) < 0x10) {
				buffer.append("0");
			}
			buffer.append(Integer.toString(array[i] & 0xff, 16) + " ");
		}
		return buffer.toString().trim();
	}

	/**
	 * Helping method to convert a byte array to an int. The bytes are
	 * considered unsigned and little endian (first byte is the least
	 * significant).
	 * 
	 * @param bytes
	 * @return
	 */
	public static int bytesToInt(byte[] bytes) {
		int value = 0;
		for (int i = 0; i < bytes.length; i++) {
			int shift = 8 * i;
			value += (bytes[i] & 0xFF) << shift;
		}
		return value;
	}

	/**
	 * Helping method to convert a byte array to a long. The bytes are
	 * considered unsigned and little endian (first byte is the least
	 * significant).
	 * 
	 * @param bytes
	 * @return
	 */
	protected static long bytesToLong(byte[] bytes) {
		long value = 0;
		for (int i = 0; i < bytes.length; i++) {
			int shift = 8 * i;
			value += (bytes[i] & 0xFF) << shift;
		}
		return value;
	}
}
