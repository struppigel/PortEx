/*******************************************************************************
 * Copyright 2014 Katja Hahn
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package com.github.katjahahn;

import java.nio.BufferUnderflowException;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utilities to convert from and to byte arrays.
 * 
 * Supports hex string conversion and long/int conversion.
 * 
 * Differences to methods of {@link java.nio.ByteBuffer}:
 * {@link #bytesToInt(byte[])} and {@link #bytesToLong(byte[])} conversion
 * methods don't care about the proper minimum length of the given byte array:
 * No {@link BufferUnderflowException} is thrown. Thus they are more robust.
 * {@link #byteToHex(byte[])} delimits bytes with spaces and every single byte
 * value is converted, also prepended zero bytes in the array.
 * 
 * @author Katja Hahn
 * 
 */
public class ByteArrayUtil {

	private static final Logger logger = LogManager
			.getLogger(ByteArrayUtil.class.getName());

	/**
	 * Retrieves the integer value of a subarray of bytes. The values are
	 * considered little endian. The subarray is determined by offset and
	 * length.
	 * 
	 * @param bytes
	 * @param offset
	 * @param length
	 * @return int value
	 */
	public static int getBytesIntValue(byte[] bytes, int offset, int length) {
		byte[] value = Arrays.copyOfRange(bytes, offset, offset + length);
		return bytesToInt(value);
	}

	/**
	 * Retrieves the long value of a subarray of bytes. The values are
	 * considered little endian. The subarray is determined by offset and
	 * length.
	 * 
	 * @param bytes
	 * @param offset
	 * @param length
	 * @return long value
	 */
	public static long getBytesLongValue(byte[] bytes, int offset, int length) {
		byte[] value = new byte[length];
		value = Arrays.copyOfRange(bytes, offset, offset + length);
		return bytesToLong(value);
	}

	/**
	 * Retrieves the long value of a subarray of bytes. The values are
	 * considered little endian. The subarray is determined by offset and
	 * length. If bytes length is not large enough for given offset and length
	 * the values are considered 0. 
	 * 
	 * This may be used for file format fields, where part of the value has been cut.
	 * Example: TinyPE
	 * 
	 * @param bytes
	 * @param offset
	 * @param length
	 * @return long value
	 */
	public static long getBytesLongValueSafely(byte[] bytes, int offset,
			int length) {
		byte[] value = new byte[length];
		if (offset + length > bytes.length) {
			logger.warn("byte array not large enough for given offset + length");
		}
		for (int i = 0; offset + i < bytes.length && i < length; i++) {
			value[i] = bytes[offset + i];

		}
		return bytesToLong(value);
	}

	/**
	 * Converts a byte array to a hex string.
	 * 
	 * Every single byte is shown in the string, also prepended zero bytes.
	 * Single bytes are delimited with a space character.
	 * 
	 * @param array
	 * @return hexadecimal string representation of the byte array
	 */
	public static String byteToHex(byte array[]) {
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
	 * Converts a byte array to an int. The bytes are considered unsigned and
	 * little endian (first byte is the least significant).
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
	 * Converts a byte array to a long. The bytes are considered unsigned and
	 * little endian (first byte is the least significant).
	 * 
	 * @param bytes
	 * @return
	 */
	public static long bytesToLong(byte[] bytes) {
		long value = 0;
		for (int i = 0; i < bytes.length; i++) {
			int shift = 8 * i;
			value += (long) (bytes[i] & 0xFF) << shift;
		}
		return value;
	}
}
