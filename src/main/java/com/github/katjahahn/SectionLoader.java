package com.github.katjahahn;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.pemodules.SectionTable;
import com.github.katjahahn.pemodules.sections.PESection;
import com.github.katjahahn.pemodules.sections.RSRCSection;

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
	public RSRCSection getRsrcSection() throws IOException {
		// TODO don't use the sectionname, the name is just a convention
		Integer virtualAddress = table.getVirtualAddress(".rsrc");
		if (virtualAddress != null) {
			long pointer = table.getPointerToRawData(".rsrc");
			try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {

				raf.seek(pointer);
				byte[] rsrcbytes = new byte[table.getSize(".rsrc")];
				raf.readFully(rsrcbytes);
				return new RSRCSection(rsrcbytes, virtualAddress);
			}
		}
		return null;
	}
}
