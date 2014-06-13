package com.github.katjahahn;

import static org.testng.Assert.*;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.parser.ByteArrayUtil;

/**
 * Random based testclass
 * 
 * @author Katja Hahn
 *
 */
public class ByteArrayUtilTest {

	private Random rand;

	@BeforeClass
	public void prepare() {
		rand = new Random();
	}

	@Test(invocationCount=100, successPercentage=100)
	public void byteToHex() {
		int randInt = rand.nextInt();
		byte[] bytes = ByteBuffer.allocate(4).putInt(randInt).array();
		String actual = ByteArrayUtil.byteToHex(bytes).replace(" ", ""); //array util adds space for nicer looks
		String expected = Integer.toHexString(randInt);
		while(actual.length() > expected.length()) {
			expected = "0" + expected; //prepend 0
		}
		assertEquals(actual, expected);
	}

	@Test(invocationCount=100, successPercentage=100)
	public void bytesToInt() {
		byte[] bytes = new byte[4];
		rand.nextBytes(bytes);
		int actual = ByteArrayUtil.bytesToInt(bytes);
		int expected = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
		assertEquals(actual, expected);
	}

	@Test(invocationCount=100, successPercentage=100)
	public void bytesToLong() {
		byte[] bytes = new byte[8];
		rand.nextBytes(bytes);
		long actual = ByteArrayUtil.bytesToLong(bytes);
		long expected = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
		assertEquals(actual, expected);
	}

	@Test(invocationCount=100, successPercentage=100)
	public void getBytesIntValue() {
		final int INT_SIZE = 4;
		final int BYTE_NR = 20;
		byte[] bytes = new byte[BYTE_NR];
		rand.nextBytes(bytes);
		int offset = rand.nextInt(BYTE_NR - INT_SIZE);
		byte[] subBytes = Arrays.copyOfRange(bytes, offset, offset + INT_SIZE);
		int actual = ByteArrayUtil.getBytesIntValue(bytes, offset, INT_SIZE);
		int expected = java.nio.ByteBuffer.wrap(subBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
		assertEquals(actual, expected);
	}

	@Test(invocationCount=100, successPercentage=100)
	public void getBytesLongValue() {
		final int LONG_SIZE = 8;
		final int BYTE_NR = 20;
		byte[] bytes = new byte[BYTE_NR];
		rand.nextBytes(bytes);
		int offset = rand.nextInt(BYTE_NR - LONG_SIZE);
		byte[] subBytes = Arrays.copyOfRange(bytes, offset, offset + LONG_SIZE);
		long actual = ByteArrayUtil.getBytesLongValue(bytes, offset, LONG_SIZE);
		long expected = java.nio.ByteBuffer.wrap(subBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong();
		assertEquals(actual, expected);
	}
}
