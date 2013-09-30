package com.github.katjahahn;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.pemodules.COFFFileHeader;
import com.github.katjahahn.pemodules.MSDOSHeader;
import com.github.katjahahn.pemodules.MSDOSLoadModule;
import com.github.katjahahn.pemodules.OptionalHeader;
import com.github.katjahahn.pemodules.PEData;
import com.github.katjahahn.pemodules.PESignature;
import com.github.katjahahn.pemodules.SectionTable;

public class PELoader {

	private final File file;

	private PELoader(File file) {
		this.file = file;
	}

	/**
	 * Loads the basic data for the given PE file
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
		MSDOSHeader msdos = null;
		COFFFileHeader coff = null;
		OptionalHeader opt = null;
		SectionTable table = null;
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			msdos = loadMSDOSHeader(raf);
			coff = loadCOFFFileHeader(pesig, raf);
			opt = loadOptionalHeader(pesig, coff, raf);
			table = loadSectionTable(pesig, coff, raf);
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
		// load the PE file data
		PEData data = PELoader.loadPE(file);

		// get various data from coff file header
		COFFFileHeader coff = data.getCOFFFileHeader();
		// MachineType machine = coff.getMachineType();
		// Date date = coff.getTimeDate();
		// int numberOfSections = coff.getNumberOfSections();
		// int optionalHeaderSize = coff.getSizeOfOptionalHeader();
		// System.out.println("machine type: " +
		// COFFFileHeader.getDescription(machine));
		// System.out.println("number of sections: " +
		// coff.getNumberOfSections());
		// System.out.println("size of optional header: " +
		// coff.getSizeOfOptionalHeader());
		// System.out.println("time date stamp: " + date);
		//
		// List<String> characteristics = coff.getCharacteristicsDescriptions();
		// System.out.println("characteristics: ");
		// for(String characteristic : characteristics) {
		// System.out.println("\t* " + characteristic);
		// }

		// print all available information of the coff file header
		System.out.println(data.getMSDOSHeader().getInfo());
		System.out.println(coff.getInfo());
		System.out.println(data.getOptionalHeader().getInfo());
		MSDOSLoadModule loadModule = new MSDOSLoadModule(data.getMSDOSHeader(),
				file);
		String dump = new String(loadModule.getDump(), "UTF-8");
		System.out.println(dump);

	}

}