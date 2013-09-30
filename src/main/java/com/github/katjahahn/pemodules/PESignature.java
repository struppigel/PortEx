package com.github.katjahahn.pemodules;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.FileFormatException;

public class PESignature extends PEModule {

	private static final int PE_OFFSET_LOCATION = 0x3c;
	private static final byte[] PE_SIG = "PE\0\0".getBytes();
	public static final int PE_SIG_LENGTH = PE_SIG.length;
	private int peOffset;

	public PESignature(File file) throws IOException {
		extractInfo(file);
	}

	private void extractInfo(File file) throws IOException {
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(PE_OFFSET_LOCATION);
			peOffset = raf.read();
			raf.seek(peOffset);
			byte[] peSigVal = new byte[4];
			raf.readFully(peSigVal);
			for (int i = 0; i < PE_SIG.length; i++) {
				if (peSigVal[i] != PE_SIG[i]) {
					throw new FileFormatException("given file is no PE file");
				}
			}
		}
	}

	public int getPEOffset() {
		return peOffset;
	}

	@Override
	public String getInfo() {
		return "-------------" + NL + "MS DOS Header" + NL + "-------------"
				+ NL + "pe offset: " + peOffset + NL;
	}

}
