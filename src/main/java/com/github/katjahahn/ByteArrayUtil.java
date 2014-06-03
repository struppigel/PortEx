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

import static com.google.common.base.Preconditions.*;

import java.nio.BufferUnderflowException;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utilities to convert from and to byte arrays.
 * <p>
 * Supports hex string conversion and long/int conversion. So far little endian
 * only.
 * <p>
 * Differences to methods of {@link java.nio.ByteBuffer}:
 * <p>
 * {@link #bytesToInt(byte[])} and {@link #bytesToLong(byte[])} don't care about
 * the proper minimum length of the given byte array: No
 * {@link BufferUnderflowException} is thrown. Thus they are more robust.
 * <p>
 * {@link #byteToHex(byte[])} delimits bytes with spaces and every single byte
 * value is converted including prepended zero bytes in the array.
 * <p>
 * {@link #getBytesLongValueSafely(byte[], int, int)} will also convert arrays
 * that are too short for the offset and the length given. It will assume the
 * missing values to be zero.
 * <p>
 * 
 * @author Katja Hahn
 * 
 */
public class ByteArrayUtil {

	private static final Logger logger = LogManager
			.getLogger(ByteArrayUtil.class.getName());
	
	private ByteArrayUtil() {}

	/**
	 * Retrieves the integer value of a subarray of bytes. The values are
	 * considered little endian. The subarray is determined by offset and
	 * length.
	 * <p>
	 * Presumes the byte array to be not null and the length must be between 1
	 * and 4 inclusive.
	 * 
	 * @param bytes
	 *            the little endian byte array that shall be converted to int
	 * @param offset
	 *            the index to start reading the integer value from
	 * @param length
	 *            the number of bytes used to convert to int
	 * @return int value
	 * @throws IllegalArgumentException
	 *             if length is larger than 4 or smaller than 1
	 */
	public static int getBytesIntValue(byte[] bytes, int offset, int length) {
		checkNotNull(bytes);
		checkArgument(length <= 4, "integer can not contain more than 4 bytes");
		checkArgument(length > 0, "length should be greater than 0");
		byte[] value = Arrays.copyOfRange(bytes, offset, offset + length);
		return bytesToInt(value);
	}

	/**
	 * Retrieves the long value of a subarray of bytes.
	 * <p>
	 * The values are considered little endian. The subarray is determined by
	 * offset and length.
	 * <p>
	 * Presumes the byte array to be not null and its length should be between 1
	 * and 4 inclusive.
	 * 
	 * @param bytes
	 *            the little endian byte array that shall be converted to long
	 * @param offset
	 *            the index to start reading the long value from
	 * @param length
	 *            the number of bytes used to convert to long
	 * @return long value
	 * @throws IllegalArgumentException
	 *             if length is larger than 8 or smaller than 1
	 */
	public static long getBytesLongValue(byte[] bytes, int offset, int length) {
		checkNotNull(bytes);
		checkArgument(length <= 8, "integer can not contain more than 8 bytes",
				length);
		checkArgument(length > 0, "length must be greater than 0");
		byte[] value = new byte[length];
		value = Arrays.copyOfRange(bytes, offset, offset + length);
		return bytesToLong(value);
	}

	/**
	 * Retrieves the long value of a subarray of bytes.
	 * <p>
	 * The values are considered little endian. The subarray is determined by
	 * offset and length. If bytes length is not large enough for given offset
	 * and length the values are considered 0.
	 * <p>
	 * This should be used for file format fields, where part of the value has been
	 * cut. Example: TinyPE
	 * <p>
	 * Presumes the byte array to be not null and its length should be between 0
	 * and 4 inclusive.
	 * 
	 * @param bytes
	 *            the little endian byte array that shall be converted to long
	 * @param offset
	 *            the index to start reading the long value from
	 * @param length
	 *            the number of bytes used to convert to long
	 * @return long value
	 * @throws IllegalArgumentException
	 *             if length is larger than 8 or smaller than 0
	 */
	public static long getBytesLongValueSafely(byte[] bytes, int offset,
			int length) {
		checkNotNull(bytes);
		checkArgument(length <= 8, "long can not contain more than 8 bytes",
				length);
		checkArgument(length >= 0, "length must be greater than 0");
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
	 * <p>
	 * Every single byte is shown in the string, also prepended zero bytes.
	 * Single bytes are delimited with a space character.
	 * 
	 * @param array
	 *            byte array to convert
	 * @return hexadecimal string representation of the byte array
	 */
	public static String byteToHex(byte array[]) {
		checkNotNull(array);
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
	 *            the little endian byte array that shall be converted to int
	 * @return int value
	 * @throws IllegalArgumentException
	 *             if byte array contains more than 4 bytes
	 */
	public static int bytesToInt(byte[] bytes) {
		checkNotNull(bytes);
		checkArgument(bytes.length <= 4,
				"byte array is too long to fit into an int", bytes.length);
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
	 *            the little endian byte array that shall be converted to int
	 * @return long value
	 * @throws IllegalArgumentException
	 *             if byte array contains more than 8 bytes
	 */
	public static long bytesToLong(byte[] bytes) {
		checkNotNull(bytes);
		checkArgument(bytes.length <= 8,
				"byte array is too long to fit into a long", bytes.length);
		long value = 0;
		for (int i = 0; i < bytes.length; i++) {
			int shift = 8 * i;
			value += (long) (bytes[i] & 0xFF) << shift;
		}
		return value;
	}
}
