package com.github.katjahahn.msdos;

import static com.github.katjahahn.msdos.MSDOSHeaderKey.*;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.PEModule;

public class MSDOSLoadModule extends PEModule {

	private static final int PAGE_SIZE = 512; // in Byte

	private final MSDOSHeader header;
	private final File file;
	private byte[] loadModuleBytes;

	public MSDOSLoadModule(MSDOSHeader header, File file) {
		this.header = header;
		this.file = file;
	}

	@Override
	public void read() throws IOException {
		int headerSize = header.getHeaderSize();
		int loadModuleSize = getLoadModuleSize();

		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(headerSize);
			loadModuleBytes = new byte[loadModuleSize];
			raf.readFully(loadModuleBytes);
		}
	}

	public int getLoadModuleSize() {
		return getImageSize() - header.getHeaderSize();
	}

	public int getImageSize() {
		int filePages = header.get(FILE_PAGES);
		int lastPageSize = header.get(LAST_PAGE_SIZE);

		int imageSize = (filePages - 1) * PAGE_SIZE + lastPageSize;
		if (lastPageSize == 0) {
			imageSize += PAGE_SIZE;
		}
		return imageSize;
	}

	public byte[] getDump() throws IOException {
		if (loadModuleBytes == null) {
			read();
		}
		return loadModuleBytes;
	}

	@Override
	public String getInfo() {
		return "----------------" + NL + "MSDOS Load Module" + NL
				+ "----------------" + NL + NL + "image size:" + getImageSize()
				+ NL + "load module size: " + getLoadModuleSize() + NL;
	}

}
