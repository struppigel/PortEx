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

import static com.google.common.base.Preconditions.*;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Paths;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.msdos.MSDOSHeader;
import com.github.katjahahn.parser.optheader.OptionalHeader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.google.java.contract.Ensures;
import com.google.java.contract.Requires;

/**
 * Loads PEData of a file. Spares the user of the library to collect every
 * information necessary.
 * 
 * @author Katja Hahn
 * 
 */
public final class PELoader {

	private static final Logger logger = LogManager.getLogger(PELoader.class
			.getName());

	private final File file;

	private PELoader(File file) {
		this.file = file;
	}

	/**
	 * Loads the basic header data for the given PE file.
	 * 
	 * @param peFile
	 *            the file to load the data from
	 * @return data header data of the PE file
	 * @throws IOException
	 *             if unable to load the file
	 * @throws IllegalStateException
	 *             if no valid PE file
	 */
	@Ensures("result != null")
	public static PEData loadPE(File peFile) throws IOException {
		return new PELoader(peFile).loadData();
	}

	/**
	 * Loads the PE file header data into a PEData instance.
	 * 
	 * @return header data
	 * @throws IOException
	 *             if file can not be read
	 * @throws IllegalStateException
	 *             if no valid PE file
	 */
	private PEData loadData() throws IOException {
		PESignature pesig = new PESignature(file);
		pesig.read();
		checkState(pesig.hasSignature(),
				"no valid pe file, signature not found");
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			MSDOSHeader msdos = loadMSDOSHeader(raf);
			COFFFileHeader coff = loadCOFFFileHeader(pesig, raf);
			OptionalHeader opt = loadOptionalHeader(pesig, coff, raf);
			SectionTable table = loadSectionTable(pesig, coff, raf);
			table.read();
			return new PEData(msdos, pesig, coff, opt, table, file);
		}
	}

	/**
	 * Loads the MSDOS header.
	 * 
	 * @param raf
	 *            the random access file instance
	 * @return msdos header
	 * @throws IOException
	 *             if unable to read header
	 */
	private MSDOSHeader loadMSDOSHeader(RandomAccessFile raf)
			throws IOException {
		byte[] headerbytes = loadBytes(0, MSDOSHeader.FORMATTED_HEADER_SIZE,
				raf);
		return MSDOSHeader.newInstance(headerbytes);
	}

	/**
	 * Loads the section table. Presumes a valid PE file.
	 * 
	 * @param pesig
	 *            pe signature
	 * @param coff
	 *            coff file header
	 * @param raf
	 *            the random access file instance
	 * @return section table
	 * @throws IOException
	 *             if unable to read header
	 */
	private SectionTable loadSectionTable(PESignature pesig,
			COFFFileHeader coff, RandomAccessFile raf) throws IOException {
		long offset = pesig.getOffset().get() + PESignature.PE_SIG_LENGTH
				+ COFFFileHeader.HEADER_SIZE + coff.getSizeOfOptionalHeader();
		logger.info("SectionTable offset" + offset);
		int numberOfEntries = (int) coff.getNumberOfSections();
		byte[] tableBytes = loadBytes(offset, SectionTable.ENTRY_SIZE
				* numberOfEntries, raf);
		return new SectionTable(tableBytes, numberOfEntries, offset);
	}

	/**
	 * Loads the coff file header. Presumes a valid PE file.
	 * 
	 * @param pesig
	 *            pe signature
	 * @param raf
	 *            the random access file instance
	 * @return coff file header
	 * @throws IOException
	 *             if unable to read header
	 */
	private COFFFileHeader loadCOFFFileHeader(PESignature pesig,
			RandomAccessFile raf) throws IOException {
		long offset = pesig.getOffset().get() + PESignature.PE_SIG_LENGTH;
		logger.info("COFF Header offset: " + offset);
		byte[] headerbytes = loadBytes(offset, COFFFileHeader.HEADER_SIZE, raf);
		return COFFFileHeader.newInstance(headerbytes, offset);
	}

	/**
	 * Loads the optional header. Presumes a valid PE file.
	 * 
	 * @param pesig
	 *            pe signature
	 * @param coff
	 *            coff file header
	 * @param raf
	 *            the random access file instance
	 * @return optional header
	 * @throws IOException
	 *             if unable to read header
	 */
	private OptionalHeader loadOptionalHeader(PESignature pesig,
			COFFFileHeader coff, RandomAccessFile raf) throws IOException {
		long offset = pesig.getOffset().get() + PESignature.PE_SIG_LENGTH
				+ COFFFileHeader.HEADER_SIZE;
		logger.info("Optional Header offset: " + offset);
		int size = OptionalHeader.MAX_SIZE;
		if (size + offset > file.length()) {
			size = (int) (file.length() - offset);
		}
		byte[] headerbytes = loadBytes(offset, size, raf);
		return OptionalHeader.newInstance(headerbytes, offset);
	}

	/**
	 * Loads the bytes at the offset into a byte array with the given length
	 * using the raf.
	 * 
	 * @param offset
	 *            to seek
	 * @param length
	 *            of the byte array, equals number of bytes read
	 * @param raf
	 *            the random access file
	 * @return byte array
	 * @throws IOException
	 *             if unable to read the bytes
	 */
	@Requires({ "length >= 0" })
	private static byte[] loadBytes(long offset, int length,
			RandomAccessFile raf) throws IOException {
		raf.seek(offset);
		byte[] bytes = new byte[length];
		raf.readFully(bytes);
		return bytes;
	}

	public static void main(String[] args) throws IOException {
		logger.entry(); 
		File file = Paths.get("C:", "Windows", "Boot", "PCAT", "memtest.exe")
				.toFile();
		PEData data = PELoader.loadPE(file);
		System.out.println(data);
	}

}
