/*******************************************************************************
 * Copyright 2014 Katja Hahn
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package com.github.katjahahn.optheader;

import static com.github.katjahahn.PEModule.*;
import static com.github.katjahahn.sections.SectionTableEntryKey.*;

import java.util.List;

import com.github.katjahahn.sections.SectionTable;
import com.github.katjahahn.sections.SectionTableEntry;

public class DataDirEntry {

	public DataDirectoryKey key;
	public long virtualAddress; // RVA actually, but called like this in spec
	public long size;

	public DataDirEntry(String fieldName, long virtualAddress, long size) {
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
	public long getFileOffset(SectionTable table) {
		SectionTableEntry section = getSectionTableEntry(table);
		long sectionRVA = section.get(VIRTUAL_ADDRESS);
		long sectionOffset = section.get(POINTER_TO_RAW_DATA);
		return (virtualAddress - sectionRVA) + sectionOffset;
	}

	/**
	 * Returns the section table entry of the section that the data directory
	 * entry is pointing to.
	 * 
	 *TODO duplicate to Sectionloader getSectionByRVA
	 * 
	 * @param table
	 * @return the section table entry of the section that the data directory
	 *         entry is pointing to
	 */
	public SectionTableEntry getSectionTableEntry(SectionTable table) {
		List<SectionTableEntry> sections = table.getSectionEntries();
		for (SectionTableEntry section : sections) {
			int vSize = section.get(VIRTUAL_SIZE).intValue();
			int vAddress = section.get(VIRTUAL_ADDRESS).intValue();
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

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DataDirEntry other = (DataDirEntry) obj;
		if (key != other.key)
			return false;
		if (size != other.size)
			return false;
		if (virtualAddress != other.virtualAddress)
			return false;
		return true;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((key == null) ? 0 : key.hashCode());
		result = prime * result + (int) (size ^ (size >>> 32));
		result = prime * result
				+ (int) (virtualAddress ^ (virtualAddress >>> 32));
		return result;
	}
}
