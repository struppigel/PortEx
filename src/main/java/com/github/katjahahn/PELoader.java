package com.github.katjahahn;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import com.github.katjahahn.coffheader.COFFFileHeader;
import com.github.katjahahn.msdos.MSDOSHeader;
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.OptionalHeader;
import com.github.katjahahn.sections.SectionLoader;
import com.github.katjahahn.sections.SectionTable;
import com.github.katjahahn.sections.idata.ImportSection;

public class PELoader {

	private final File file;

	private PELoader(File file) {
		this.file = file;
	}

	/**
	 * Loads the basic data for the given PE file.
	 * 
	 * @param peFile
	 * @return data of the PE file
	 * @throws IOException
	 */
	public static PEData loadPE(File peFile) throws IOException {
		return new PELoader(peFile).loadData();
	}

	private PEData loadData() throws IOException {
		PESignature pesig = new PESignature(file);
		pesig.read();
		MSDOSHeader msdos = null;
		COFFFileHeader coff = null;
		OptionalHeader opt = null;
		SectionTable table = null;
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			msdos = loadMSDOSHeader(raf);
			msdos.read();
			coff = loadCOFFFileHeader(pesig, raf);
			coff.read();
			opt = loadOptionalHeader(pesig, coff, raf);
			opt.read();
			table = loadSectionTable(pesig, coff, raf);
			table.read();
		}
		return new PEData(msdos, pesig, coff, opt, table);
	}

	private MSDOSHeader loadMSDOSHeader(RandomAccessFile raf)
			throws IOException {
		byte[] headerbytes = loadBytes(0, MSDOSHeader.FORMATTED_HEADER_SIZE,
				raf);
		return new MSDOSHeader(headerbytes);
	}

	private SectionTable loadSectionTable(PESignature pesig,
			COFFFileHeader coff, RandomAccessFile raf) throws IOException {
		long offset = pesig.getPEOffset() + PESignature.PE_SIG_LENGTH
				+ COFFFileHeader.HEADER_SIZE + coff.getSizeOfOptionalHeader();
		int numberOfEntries = coff.getNumberOfSections();
		byte[] tableBytes = loadBytes(offset, SectionTable.ENTRY_SIZE
				* numberOfEntries, raf);
		return new SectionTable(tableBytes, numberOfEntries);
	}

	private COFFFileHeader loadCOFFFileHeader(PESignature pesig,
			RandomAccessFile raf) throws IOException {
		long offset = pesig.getPEOffset() + PESignature.PE_SIG_LENGTH;
		byte[] headerbytes = loadBytes(offset, COFFFileHeader.HEADER_SIZE, raf);
		return new COFFFileHeader(headerbytes);
	}

	private OptionalHeader loadOptionalHeader(PESignature pesig,
			COFFFileHeader coff, RandomAccessFile raf) throws IOException {
		long offset = pesig.getPEOffset() + PESignature.PE_SIG_LENGTH
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

	public static void main(String[] args) throws IOException {
		File file = new File(args[0]);
		PEData data = PELoader.loadPE(file);

		SectionTable table = data.getSectionTable();
		List<DataDirEntry> dataDirEntries = data.getOptionalHeader()
				.getDataDirEntries();
		for (DataDirEntry entry : dataDirEntries) {
			System.out.println(entry);
			System.out.println("calculated file offset: "
					+ entry.getFileOffset(table));
			System.out.println("section name: "
					+ entry.getSectionTableEntry(table).getName());
			System.out.println();
		}
	
		SectionLoader loader = new SectionLoader(table, data.getOptionalHeader(), file);
		
//		System.out.println(data.getCOFFFileHeader().getInfo());
//		System.out.println(data.getOptionalHeader().getInfo());
		System.out.println(table.getInfo());
//		System.out.println(data.getMSDOSHeader().getInfo());
//		System.out.println(data.getPESignature().getInfo());
		ImportSection idata = loader.loadImportSection();
//		System.out.println(loader.loadRsrcSection().getInfo());
		System.out.println(idata.getInfo());
	}

}