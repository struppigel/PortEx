package com.github.katjahahn.sections;
import static com.github.katjahahn.sections.SectionTableEntryKey.*;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.sections.rsrc.RSRCSection;

public class SectionLoader {

	private final SectionTable table;
	private final File file;

	/**
	 * Constructor that takes a file and the corresponding section table (loaded
	 * by PELoader).
	 * 
	 * @param table
	 * @param file
	 */
	public SectionLoader(SectionTable table, File file) {
		this.table = table;
		this.file = file;
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
	public RSRCSection loadRsrcSection(List<DataDirEntry> dataDirEntries)
			throws IOException {
		DataDirEntry resourceTable = getResourceEntry(dataDirEntries);
		if (resourceTable != null) {
			SectionTableEntry rsrcEntry = resourceTable.getSectionTableEntry(table);
			Integer virtualAddress = rsrcEntry.get(VIRTUAL_ADDRESS);

			if (virtualAddress != null) {
				try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
					raf.seek(rsrcEntry.get(POINTER_TO_RAW_DATA));
					byte[] rsrcbytes = new byte[rsrcEntry.get(SIZE_OF_RAW_DATA)];
					raf.readFully(rsrcbytes);
					RSRCSection rsrc = new RSRCSection(rsrcbytes, virtualAddress);
					rsrc.read();
					return rsrc;
				}
			}
		}
		return null;
	}

	private DataDirEntry getResourceEntry(List<DataDirEntry> dataDirEntries) {
		for (DataDirEntry entry : dataDirEntries) {
			if (entry.key.equals(DataDirectoryKey.RESOURCE_TABLE)) {
				return entry;
			}
		}
		return null;
	}
}
