package com.github.katjahahn.pemodules;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class MSDOSLoadModule extends PEModule {

	private final MSDOSHeader header;
	private final File file;
	private byte[] loadModuleBytes;
	private static final int PAGE_SIZE = 512;

	public MSDOSLoadModule(MSDOSHeader header, File file) {
		this.header = header;
		this.file = file;
	}

	public void load() throws IOException {
		int headerSize = header.getHeaderSize();
		int filePages = header.get("FILE_PAGES").value;
		int lastPageSize = header.get("LAST_PAGE_SIZE").value;
		int imageSize = computeImageSize(filePages, lastPageSize);
		//TODO seems to be too much
		@SuppressWarnings("unused")
		int loadModuleSize = imageSize - headerSize;
		
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(headerSize);
			//XXX intermediate solution uses PE signature as stop
//			loadModuleBytes = new byte[loadModuleSize];
			int peOffset = new PESignature(file).getPEOffset();
			loadModuleBytes = new byte[peOffset - headerSize];
			raf.readFully(loadModuleBytes);
		}
	}

	private int computeImageSize(int filePages, int lastPageSize) {
		int imageSize = (filePages - 1) * PAGE_SIZE + lastPageSize;				
		if(lastPageSize == 0) {
			imageSize += PAGE_SIZE;
		}
		return imageSize;
	}

	public byte[] getDump() throws IOException {
		if (loadModuleBytes == null) {
			load();
		}
		return loadModuleBytes;
	}

	@Override
	public String getInfo() {
		return null;
	}

}
