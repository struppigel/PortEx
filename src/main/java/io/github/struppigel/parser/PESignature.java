/* ******************************************************************************
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
package io.github.struppigel.parser;

import com.google.common.base.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Reads the offset of the PE signature and the signature itself.
 * <p>
 * Can be used to verify that the file is indeed a PE file.
 * 
 * @author Katja Hahn
 * 
 */
public class PESignature {

	private static final Logger logger = LogManager.getLogger(PESignature.class
			.getName());

	/**
	 * The file offset that contains the PE Signature offset is {@value} .
	 */
	public static final int PE_OFFSET_LOCATION = 0x3c;

	/**
	 * The number of bytes that define the PE Signature offset
	 */
	public static final int PE_OFFSET_LOCATION_SIZE = 4;

	/**
	 * The signature bytes of the string PE\0\0.
	 */
	public static final byte[] PE_SIG = "PE\0\0".getBytes();

	/**
	 * The file offset for the PE signature read at PE_OFFSET_LOCATION Absent,
	 * if not yet read.
	 */
	private Optional<Long> peOffset = Optional.absent();
	private final File file;

	/**
	 * Creates a PESignature instance with the input file.
	 * 
	 * @param file
	 *            the PE file that should be checked for the signature
	 */
	public PESignature(File file) {
		this.file = file;
	}

	/**
	 * Reads the PE signature and sets the peOffset.
	 * 
	 * @throws FileFormatException
	 *             if file is not a PE file
	 * @throws IOException
	 *             if something went wrong while trying to read the file
	 */
	public void read() throws IOException {
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			// check that offset location is within the file
			throwIf(file.length() < PE_OFFSET_LOCATION);
			/* read pe signature offset at offset location */
			byte[] offsetBytes = IOUtil.loadBytesSafely(PE_OFFSET_LOCATION,
					PE_OFFSET_LOCATION_SIZE, raf);
			// save signature offset
			peOffset = Optional.of((long) ByteArrayUtil.bytesToInt(offsetBytes));
			// check if supposed pe signature is within the file
			// a truncated signature has to be taken into account and allowed
			// see d_nonnull.dll
			throwIf(file.length() < peOffset.get() || peOffset.get() < 0);
			/* read PE signature at offset and verify */
			byte[] peSigVal = IOUtil.loadBytesSafely(peOffset.get(), PE_SIG.length,
					raf);
			for (int i = 0; i < PE_SIG.length; i++) {
				throwIf(peSigVal[i] != PE_SIG[i]);
			}
		}
	}

	public void repair(File outFile) throws IOException {
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			// check that offset location is within the file
			if (file.length() < PE_OFFSET_LOCATION) {
				System.out.println("repair not possible, file is too small");
			} else {
				/* read pe signature offset at offset location */
				byte[] offsetBytes = IOUtil.loadBytesSafely(PE_OFFSET_LOCATION,
						PE_OFFSET_LOCATION_SIZE, raf);
				// save signature offset
				peOffset = Optional.of((long) ByteArrayUtil.bytesToInt(offsetBytes));
				// check if supposed pe signature is within the file
				if (file.length() < peOffset.get() || peOffset.get() <= 1) {
					fixElfanew(outFile, raf);
				} else {
					/* read PE signature at offset and verify */
					byte[] peSigVal = IOUtil.loadBytesSafely(peOffset.get(),
							PE_SIG.length, raf);
					if (!arrayHasPESignature(peSigVal, 0, false)) {
						System.out.println("Writing PE signature to offset " + ScalaIOUtil.hex(peOffset.get()));
						writeFix(outFile, peOffset.get(), PE_SIG);
					}
				}
			}
		}
	}

	private void fixElfanew(File outFile, RandomAccessFile raf)
			throws IOException {
		// search maximum for 'PE\0\0'
		final int PESIG_SEARCH_MAX = 0x1000;
		System.out.println("Attempting to fix e_lfanew ...");
		// search for 'PE\0\0' and fix offset
		byte[] chunk = IOUtil.loadBytesSafely(0, PESIG_SEARCH_MAX, raf);
		for (int i = 0; i < PESIG_SEARCH_MAX; i++) {
			if (arrayHasPESignature(chunk, i, false)) {
				System.out.println("PE signature found at " + ScalaIOUtil.hex(i));
				long peOffset = i;
				byte[] fixedOffsetBytes = ByteArrayUtil.longToDWord(peOffset);
				writeFix(outFile, PE_OFFSET_LOCATION, fixedOffsetBytes);
				System.out.println("Replaced e_lfanew value with " + ScalaIOUtil.hex(peOffset));
				return;
			}
		}
		// search for nocase "pe\0\0" and fix offset and signature
		for (int i = 0; i < PESIG_SEARCH_MAX; i++) {
			if (arrayHasPESignature(chunk, i, true)) {
				System.out.println("Broken PE signature found at " + ScalaIOUtil.hex(i));
				long peOffset = i;
				byte[] fixedOffsetBytes = ByteArrayUtil.longToDWord(peOffset);
				writeFix(outFile, PE_OFFSET_LOCATION, fixedOffsetBytes);
				writeFix(outFile, peOffset, PE_SIG);
				System.out.println("Replaced e_lfanew value with " + ScalaIOUtil.hex(peOffset));
				System.out.println("Writing PE signature to offset " + ScalaIOUtil.hex(peOffset));
				return;
			}
		}
	}

	private void writeFix(File file, long offset, byte[] bytes) throws IOException {
		try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
			raf.seek(offset);
			for(int i = 0; i < bytes.length; i++){
				raf.writeByte(bytes[i]);
			}
		}
	}

	private boolean arrayHasPESignature(byte[] array, int index, boolean nocase) {
		final byte[] PE_SIG_LOWERCASE = "pe\0\0".getBytes();
		for (int i = 0; i < PE_SIG.length; i++) {
			if (array[index + i] != PE_SIG[i]) {
				if(nocase && array[index + i] == PE_SIG_LOWERCASE[i]) {
					continue;
				} 
				return false;
			}
		}
		return true;
	}

	/**
	 * Tries to read the PE signature of the current file and returns true, iff
	 * it was successfull.
	 * 
	 * @return true if the file has the PE signature, false otherwise.
	 */
	public boolean exists() {
		try {
			read();
			return true;
		} catch (FileFormatException e) {
			return false;
		} catch (IOException e) {
			logger.error(e);
			return false;
		}
	}

	/**
	 * Throws FileFormatException and sets peOffset to absent iff b is true.
	 * 
	 * @param b expression
	 * @throws FileFormatException if expression is true
	 */
	private void throwIf(boolean b) throws FileFormatException {
		if (b) {
			peOffset = Optional.absent();
			throw new FileFormatException("given file is no PE file");
		}
	}

	/**
	 * Returns the offset of the PE signature.
	 * 
	 * @return optional offset of PE signature
	 * @throws IllegalStateException
	 *             if file hasn't been read yet or the read file was no PE file.
	 */
	public long getOffset() {
		assert peOffset.get() > 0;
		return peOffset.get();
	}

	/**
	 * Returns a description string.
	 * 
	 * @return description string of the pe signature
	 */
	public String getInfo() {
		if (!peOffset.isPresent()) {
			return "No PE signature found";
		}
		return "-------------" + IOUtil.NL + "PE Signature" + IOUtil.NL + "-------------"
				+ IOUtil.NL + "pe offset: " + peOffset.get() + IOUtil.NL;
	}

}
