package com.github.katjahahn.optheader;

import static com.github.katjahahn.PEModule.*;
import static com.github.katjahahn.sections.SectionTableEntryKey.*;

import java.util.List;

import com.github.katjahahn.sections.SectionTable;
import com.github.katjahahn.sections.SectionTableEntry;

public class DataDirEntry {

	public DataDirectoryKey key;
	public int virtualAddress; // RVA actually, but called like this in spec
	public int size;

	public DataDirEntry(String fieldName, int virtualAddress, int size) {
		for(DataDirectoryKey key: DataDirectoryKey.values()) {
			if(key.toString().equals(fieldName)) {
				this.key = key;
			}
		}
		if(key == null) throw new IllegalArgumentException("no enum constant for given field name");
		this.virtualAddress = virtualAddress;
		this.size = size;
	}

	public DataDirEntry(DataDirectoryKey key, int virtualAddress, int size) {
		this.key = key;
		this.virtualAddress = virtualAddress;
		this.size = size;
	}

	/**
	 * Calculates the file offset of the the data directory based on the virtual
	 * address and the entries in the section table.
	 * 
	 * @param table
	 * @return file offset of data directory
	 */
	public int getFileOffset(SectionTable table) {
		SectionTableEntry section = getSectionTableEntry(table);
		int sectionRVA = section.get(VIRTUAL_ADDRESS);
		int sectionOffset = section.get(POINTER_TO_RAW_DATA);
		return (virtualAddress - sectionRVA) + sectionOffset;
	}

	/**
	 * Returns the section table entry of the section that the data directory
	 * entry is pointing to.
	 * 
	 * @param table
	 * @return the section table entry of the section that the data directory
	 *         entry is pointing to
	 */
	public SectionTableEntry getSectionTableEntry(SectionTable table) {
		List<SectionTableEntry> sections = table.getSectionEntries();
		for (SectionTableEntry section : sections) {
			int vSize = section.get(VIRTUAL_SIZE);
			int vAddress = section.get(VIRTUAL_ADDRESS);
			if (rvaIsWithin(vAddress, vSize)) {
				return section;
			}
		}
		return null;
	}

	private boolean rvaIsWithin(int address, int size) {
		int endpoint = address + size;
		return virtualAddress >= address && virtualAddress < endpoint;
	}

	@Override
	public String toString() {
		return "field name: " + key + NL + "virtual address: "
				+ virtualAddress + NL + "size: " + size;
	}
}
