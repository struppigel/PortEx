package com.github.katjahahn;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.pemodules.COFFFileHeader;
import com.github.katjahahn.pemodules.MSDOSHeader;
import com.github.katjahahn.pemodules.OptionalHeader;
import com.github.katjahahn.pemodules.PEData;
import com.github.katjahahn.pemodules.SectionTable;

public class PELoader {

	private final File file;

	private PELoader(File file) {
		this.file = file;
	}

	public static PEData loadPE(File file) throws IOException {
		return new PELoader(file).loadData();
	}

	private PEData loadData() throws IOException {
		MSDOSHeader msdos = new MSDOSHeader(file);
		COFFFileHeader coff = null;
		OptionalHeader opt = null;
		SectionTable table = null;
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			coff = loadCOFFFileHeader(msdos, raf);
			opt = loadOptionalHeader(msdos, coff, raf);
			table = loadSectionTable(msdos, coff, raf);
		}
		return new PEData(msdos, coff, opt, table);
	}

	private SectionTable loadSectionTable(MSDOSHeader msdos,
			COFFFileHeader coff, RandomAccessFile raf) throws IOException {
		long offset = msdos.getPEOffset() + MSDOSHeader.PE_SIG_LENGTH
				+ COFFFileHeader.HEADER_SIZE + coff.getSizeOfOptionalHeader();
		int numberOfEntries = coff.getNumberOfSections();
		byte[] tableBytes = loadBytes(offset, SectionTable.ENTRY_SIZE
				* numberOfEntries, raf);
		return new SectionTable(tableBytes, numberOfEntries);
	}

	private COFFFileHeader loadCOFFFileHeader(MSDOSHeader msdos,
			RandomAccessFile raf) throws IOException {
		long offset = msdos.getPEOffset() + MSDOSHeader.PE_SIG_LENGTH;
		byte[] headerbytes = loadBytes(offset, COFFFileHeader.HEADER_SIZE, raf);
		return new COFFFileHeader(headerbytes);
	}

	private OptionalHeader loadOptionalHeader(MSDOSHeader msdos,
			COFFFileHeader coff, RandomAccessFile raf) throws IOException {
		long offset = msdos.getPEOffset() + MSDOSHeader.PE_SIG_LENGTH
				+ COFFFileHeader.HEADER_SIZE;
		byte[] headerbytes = loadBytes(offset, coff.getSizeOfOptionalHeader(),
				raf);
		return new OptionalHeader(headerbytes);
	}

	private byte[] loadBytes(long offset, int length, RandomAccessFile raf)
			throws IOException {
		raf.seek(offset);
		byte[] bytes = new byte[length];
		raf.readFully(bytes);
		return bytes;
	}

	public static void main(String[] args) {
		try {
			PEData data = loadPE(new File(args[0]));
			System.out.println("PE offset: "
					+ data.getMSDOSHeader().getPEOffset());
			System.out.println("PE signature found: yes");
			System.out.println(data.getSectionTable().getInfo());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

}