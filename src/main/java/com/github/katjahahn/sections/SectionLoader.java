package com.github.katjahahn.sections;

import static com.github.katjahahn.sections.SectionTableEntryKey.*;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.optheader.OptionalHeader;
import com.github.katjahahn.sections.idata.ImportSection;
import com.github.katjahahn.sections.rsrc.RSRCSection;

public class SectionLoader {

	private final SectionTable table;
	private final File file;
	private final OptionalHeader optHeader;

	/**
	 * Constructor that takes a file and the corresponding section table (loaded
	 * by PELoader).
	 * 
	 * @param table
	 * @param file
	 */
	public SectionLoader(SectionTable table, OptionalHeader optHeader, File file) {
		this.table = table;
		this.file = file;
		this.optHeader = optHeader;
	}

	/**
	 * Loads the section with the given name. If the file doesn't have a section
	 * by this name, it returns null.
	 * 
	 * @param name
	 *            the section's name
	 * @return PESection of the given name, null if section isn't contained in
	 *         file
	 * @throws IOException
	 */
	public PESection loadSection(String name) throws IOException {
		// TODO recognize i.e. .rsrc section and create correct subclass
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			Integer pointer = table.getPointerToRawData(name);
			if (pointer != null) {
				raf.seek(pointer);
				byte[] sectionbytes = new byte[table.getSize(name)];
				raf.readFully(sectionbytes);
				return new PESection(sectionbytes);
			}
		}
		return null;
	}

	/**
	 * Loads all bytes and information of the .rsrc section.
	 * 
	 * @return RSRCSection of the given file, null if file doesn't have this
	 *         section
	 * @throws IOException
	 */
	public RSRCSection loadRsrcSection() throws IOException {
		DataDirEntry resourceTable = getDataDirEntry(
				optHeader.getDataDirEntries(), DataDirectoryKey.RESOURCE_TABLE);
		if (resourceTable != null) {
			SectionTableEntry rsrcEntry = resourceTable
					.getSectionTableEntry(table);
			Integer virtualAddress = rsrcEntry.get(VIRTUAL_ADDRESS) != null ? rsrcEntry
					.get(VIRTUAL_ADDRESS).intValue() : null; // va is always 4
																// bytes

			if (virtualAddress != null) {
				try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
					raf.seek(rsrcEntry.get(POINTER_TO_RAW_DATA));
					byte[] rsrcbytes = new byte[rsrcEntry.get(SIZE_OF_RAW_DATA)
							.intValue()]; // rawsize is always 4 bytes
					raf.readFully(rsrcbytes);
					RSRCSection rsrc = new RSRCSection(rsrcbytes,
							virtualAddress);
					rsrc.read();
					return rsrc;
				}
			}
		}
		return null;
	}

	public static SectionTableEntry getSectionByRVA(SectionTable table, int rva) {
		List<SectionTableEntry> sections = table.getSectionEntries();
		for (SectionTableEntry section : sections) {
			int vSize = section.get(VIRTUAL_SIZE).intValue(); // both values are
																// always 4
																// Bytes
			int vAddress = section.get(VIRTUAL_ADDRESS).intValue();
			if (rvaIsWithin(vAddress, vSize, rva)) {
				return section;
			}
		}
		return null;
	}

	private static boolean rvaIsWithin(int address, int size, int rva) {
		int endpoint = address + size;
		return rva >= address && rva < endpoint;
	}

	// TODO almost same code as RSRCSection
	/**
	 * Loads all bytes and information of the import section
	 * 
	 * @param dataDirEntries
	 * @return
	 * @throws IOException
	 */
	public ImportSection loadImportSection() throws IOException {
		DataDirEntry resourceTable = getDataDirEntry(
				optHeader.getDataDirEntries(), DataDirectoryKey.IMPORT_TABLE);
		if (resourceTable != null) {
			SectionTableEntry idataEntry = resourceTable
					.getSectionTableEntry(table);
			Integer virtualAddress = idataEntry.get(VIRTUAL_ADDRESS) != null ? idataEntry
					.get(VIRTUAL_ADDRESS).intValue() : null; //always 4 Bytes
			if (virtualAddress != null) {
				try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
					raf.seek(idataEntry.get(POINTER_TO_RAW_DATA));
					byte[] idatabytes = new byte[idataEntry
							.get(SIZE_OF_RAW_DATA).intValue()]; //always 4 Bytes
					raf.readFully(idatabytes);
					ImportSection idata = new ImportSection(idatabytes,
							virtualAddress, optHeader);
					idata.read();
					return idata;
				}
			}
		}
		return null;
	}

	private DataDirEntry getDataDirEntry(List<DataDirEntry> dataDirEntries,
			DataDirectoryKey key) {
		for (DataDirEntry entry : dataDirEntries) {
			if (entry.key.equals(key)) {
				return entry;
			}
		}
		return null;
	}
}
