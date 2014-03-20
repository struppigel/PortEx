package com.github.katjahahn;

import static com.github.katjahahn.ByteArrayUtil.*;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Reads the offset of the PE signature and the signature itself. Can be used to
 * verify that the file is indeed a PE file.
 * 
 * @author Katja Hahn
 * 
 */
public class PESignature extends PEModule {

	private static final int PE_OFFSET_LOCATION = 0x3c;
	private static final byte[] PE_SIG = "PE\0\0".getBytes();
	public static final int PE_SIG_LENGTH = PE_SIG.length;
	private int peOffset = -1;
	private final File file;

	/**
	 * @constructor Creates a PESignature instance with the input file specified
	 * @param file
	 *            the PE file that should be checked for the signature
	 */
	public PESignature(File file) {
		this.file = file;
	}

	/**
	 * 
	 * 
	 * @throws FileFormatException
	 *             if file is not a PE file
	 * @throws IOException
	 *             if something went wrong while trying to read the file
	 */
	@Override
	public void read() throws FileFormatException, IOException {
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(PE_OFFSET_LOCATION);
			byte[] offsetBytes = new byte[2];
			raf.readFully(offsetBytes);
			peOffset = bytesToInt(offsetBytes);
			raf.seek(peOffset);
			byte[] peSigVal = new byte[4];
			raf.readFully(peSigVal);
			for (int i = 0; i < PE_SIG.length; i++) {
				if (peSigVal[i] != PE_SIG[i]) {
					peOffset = -1;
					throw new FileFormatException("given file is no PE file");
				}
			}
		}
	}

	/**
	 * Returns the offset of the PE signature. Returns -1 if file hasn't been
	 * read yet or the read file was no PE file.
	 * 
	 * @return offset of PE signature, -1 if file not read or file is no PE
	 */
	public int getPEOffset() {
		return peOffset;
	}

	@Override
	public String getInfo() {
		return "-------------" + NL + "PE Signature" + NL + "-------------"
				+ NL + "pe offset: " + peOffset + NL;
	}

}
