package com.github.katjahahn;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class PESignature extends PEModule {

	private static final int PE_OFFSET_LOCATION = 0x3c;
	private static final byte[] PE_SIG = "PE\0\0".getBytes();
	public static final int PE_SIG_LENGTH = PE_SIG.length;
	private int peOffset;
	private final File file;

	public PESignature(File file) {
		this.file = file;
	}

	@Override
	public void read() throws IOException {
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(PE_OFFSET_LOCATION);
			byte[] offsetBytes = new byte[2];
			raf.readFully(offsetBytes);
			peOffset = PEModule.bytesToInt(offsetBytes);
			raf.seek(peOffset);
			byte[] peSigVal = new byte[4];
			raf.readFully(peSigVal);
			for (int i = 0; i < PE_SIG.length; i++) {
				if (peSigVal[i] != PE_SIG[i]) {
					System.out.println("");
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
		return "-------------" + NL + "PE Signature" + NL + "-------------"
				+ NL + "pe offset: " + peOffset + NL;
	}

}
