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
package com.github.katjahahn.parser;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utilities to convert from and to byte arrays.
 * <p>
 * Supports hex string conversion and long/int conversion. Little endian only.
 * <p>
 * Differences to methods of {@link java.nio.ByteBuffer}:
 * <p>
 * {@link #bytesToInt(byte[])} and {@link #bytesToLong(byte[])} don't care about
 * the proper minimum length of the given byte array: No
 * {@link java.nio.BufferUnderflowException} is thrown. Thus they are more
 * robust.
 * <p>
 * {@link #byteToHex(byte[])} delimits bytes with spaces and every single byte
 * value is converted including prepended zero bytes in the array.
 * <p>
 * {@link #getBytesLongValueSafely(byte[], int, int)} will also convert arrays
 * that are too short for the offset and the length given. It will assume the
 * missing values to be zero.
 * <p>
 * This class is not meant to be used by library users.
 * 
 * @author Katja Hahn
 * 
 */
public class ByteArrayUtil {

    private static final Logger logger = LogManager
            .getLogger(ByteArrayUtil.class.getName());

    /**
     * Utility class. Not intended to be used as object.
     */
    private ByteArrayUtil() {
    }

    /**
     * Retrieves the integer value of a subarray of bytes. The values are
     * considered little endian. The subarray is determined by offset and
     * length.
     * <p>
     * Presumes the bytes to be not null and the length must be between 1 and 4
     * inclusive. The length of bytes must be larger than or equal to length +
     * offset.
     * 
     * @param bytes
     *            the little endian byte array that shall be converted to int
     * @param offset
     *            the index to start reading the integer value from
     * @param length
     *            the number of bytes used to convert to int
     * @return int value
     */
    public static int getBytesIntValue(byte[] bytes, int offset, int length) {
        assert length <= 4 && length > 0;
        assert bytes != null && bytes.length >= length + offset;
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
     * and 8 inclusive. The length of bytes must be larger than or equal to
     * length + offset.
     * 
     * @param bytes
     *            the little endian byte array that shall be converted to long
     * @param offset
     *            the index to start reading the long value from
     * @param length
     *            the number of bytes used to convert to long
     * @return long value
     */
    public static long getBytesLongValue(byte[] bytes, int offset, int length) {
        assert length <= 8 && length > 0;
        assert bytes != null && bytes.length >= length + offset;
        byte[] value = Arrays.copyOfRange(bytes, offset, offset + length);
        return bytesToLong(value);
    }

    /**
     * Retrieves the long value of a subarray of bytes.
     * <p>
     * The values are considered little endian. The subarray is determined by
     * offset and length. If bytes length is not large enough for given offset
     * and length the values are considered 0.
     * <p>
     * This should be used for file format fields, where part of the value has
     * been cut. Example: TinyPE
     * <p>
     * Presumes the byte array to be not null and its length should be between 0
     * and 8 inclusive.
     * 
     * @param bytes
     *            the little endian byte array that shall be converted to long
     * @param offset
     *            the index to start reading the long value from
     * @param length
     *            the number of bytes used to convert to long
     * @return long value
     */
    public static long getBytesLongValueSafely(byte[] bytes, int offset,
            int length) {
        assert length <= 8 && length >= 0 && bytes != null;
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
    public static String byteToHex(byte[] array) {
        assert array != null;
        return byteToHex(array, " ");
    }

    /**
     * Converts a byte array to a hex string.
     * <p>
     * Every single byte is shown in the string, also prepended zero bytes.
     * Single bytes are delimited with the separator.
     * 
     * @param array
     *            byte array to convert
     * @param separator
     *            the delimiter of the bytes
     * @return hexadecimal string representation of the byte array
     */
    public static String byteToHex(byte[] array, String separator) {
        assert array != null;
        StringBuilder buffer = new StringBuilder();
        for (int i = 0; i < array.length; i++) {
            // add separator in between, not before the first byte
            if (i != 0) {
                buffer.append(separator);
            }
            // (b & 0xff) treats b as unsigned byte
            // first nibble is 0 if byte is less than 0x10
            if ((array[i] & 0xff) < 0x10) {
                buffer.append("0");
            }
            // use java's hex conversion for the rest
            buffer.append(Integer.toString(array[i] & 0xff, 16));
        }
        return buffer.toString();
    }

    /**
     * Converts a byte array to an int. The bytes are considered unsigned and
     * little endian (first byte is the least significant).
     * <p>
     * Presumes the array bytes to be not null and its length smaller than or
     * equal to 4
     * 
     * @param bytes
     *            the little endian byte array that shall be converted to int
     * @return int value
     */
    public static int bytesToInt(byte[] bytes) {
        assert bytes != null && bytes.length <= 4;
        final int BYTE_SIZE = 8;
        int value = 0;
        for (int i = 0; i < bytes.length; i++) {
            // shift byte i times, so it gets the correct significance
            int shift = BYTE_SIZE * i;
            // (b & 0xff) treats b as unsigned byte
            // calculate the value to add by performing the shift
            value += (bytes[i] & 0xff) << shift;
        }
        return value;
    }
    
  //TODO create decent (flexible) version
    public static byte[] intToWord(int a) {
    	byte[] ret = new byte[2];
        ret[0] = (byte) (a & 0xFF);   
        ret[1] = (byte) ((a >> 8) & 0xFF);   
        return ret;
    }

    /**
     * Converts a byte array to a long. The bytes are considered unsigned and
     * little endian (first byte is the least significant).
     * <p>
     * Presumes the array bytes to be not null and its length smaller than or
     * equal to 8
     * 
     * @param bytes
     *            the little endian byte array that shall be converted to int
     * @return long value
     */
    public static long bytesToLong(byte[] bytes) {
        assert bytes != null && bytes.length <= 8;
        final int BYTE_SIZE = 8;
        long value = 0;
        for (int i = 0; i < bytes.length; i++) {
            // shift byte i times, so it gets the correct significance
            int shift = BYTE_SIZE * i;
            // (b & 0xff) treats b as unsigned byte
            // calculate the value to add by performing the shift
            value += (long) (bytes[i] & 0xff) << shift;
        }
        return value;
    }
    
    //TODO create decent version
    public static byte[] longToDWord(long a) {
    	byte[] ret = new byte[4];
        ret[0] = (byte) (a & 0xFF);   
        ret[1] = (byte) ((a >> 8) & 0xFF);   
        ret[2] = (byte) ((a >> 16) & 0xFF);   
        ret[3] = (byte) ((a >> 24) & 0xFF);
        return ret;
    }
}
