package com.github.katjahahn;

import java.util.Arrays;

/**
 * Utilities to convert from and to byte arrays. 
 *
 * Supports hex string conversion and long/int conversion.
 * 
 * @author Katja Hahn
 *
 */
public class ByteArrayUtil {
	
	/**
	 * Gets the integer value of a subarray of bytes. The values are considered
	 * little endian. The subarray is determined by offset and length.
	 * 
	 * @param bytes
	 * @param offset
	 * @param length
	 * @return
	 */
	public static int getBytesIntValue(byte[] bytes, int offset, int length) {
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
	public static long getBytesLongValue(byte[] bytes, int offset, int length) {
		byte[] value = Arrays.copyOfRange(bytes, offset, offset + length);
		return bytesToLong(value);
	}

	/**
	 * Helping method to convert a byte array to a hex String
	 * 
	 * @param array
	 * @return
	 */
	public static String convertByteToHex(byte array[]) {
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
	public static long bytesToLong(byte[] bytes) {
		long value = 0;
		for (int i = 0; i < bytes.length; i++) {
			int shift = 8 * i;
			value += (long)(bytes[i] & 0xFF) << shift;
		}
		return value;
	}
}
