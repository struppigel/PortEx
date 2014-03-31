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
package com.github.katjahahn.sections;

import static com.github.katjahahn.sections.SectionTableEntryKey.*;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import com.github.katjahahn.PEData;
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.optheader.OptionalHeader;
import com.github.katjahahn.sections.idata.ImportSection;
import com.github.katjahahn.sections.rsrc.ResourceSection;

/**
 * Responsible for computing section related values and loading sections with
 * the given {@link SectionTable} information.
 * 
 * @author Katja Hahn
 * 
 */
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
	
	public SectionLoader(PEData data) {
		this.table = data.getSectionTable();
		this.optHeader = data.getOptionalHeader();
		this.file = data.getFile();
	}

	/**
	 * Loads the section with the given name. If the file doesn't have a section
	 * by this name, it returns null.
	 * 
	 * This does not instantiate subclasses of PESection. Use methods like
	 * {@link #loadImportSection()} or {@link #loadResourceSection()} instead.
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
			Long pointer = table.getPointerToRawData(name);
			if (pointer != null) {
				raf.seek(pointer);
				//TODO cast to int is insecure. actual int is unsigned, java int is signed
				byte[] sectionbytes = new byte[table.getSize(name).intValue()]; 
				raf.readFully(sectionbytes);
				return new PESection(sectionbytes);
			}
		}
		return null;
	}

	/**
	 * Loads all bytes and information of the resource section.
	 * 
	 * @return RSRCSection of the given file, null if file doesn't have this
	 *         section
	 * @throws IOException
	 */
	public ResourceSection loadResourceSection() throws IOException {
		DataDirEntry resourceTable = getDataDirEntry(
				optHeader.getDataDirEntries(), DataDirectoryKey.RESOURCE_TABLE);
		if (resourceTable != null) {
			SectionTableEntry rsrcEntry = resourceTable
					.getSectionTableEntry(table);
			Long virtualAddress = rsrcEntry.get(VIRTUAL_ADDRESS); // va is always 4
																// bytes

			if (virtualAddress != null) {
				try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
					raf.seek(rsrcEntry.get(POINTER_TO_RAW_DATA));
					//TODO cast to int is insecure. actual int is unsigned, java int is signed
					byte[] rsrcbytes = new byte[rsrcEntry.get(SIZE_OF_RAW_DATA)
							.intValue()]; 
					raf.readFully(rsrcbytes);
					ResourceSection rsrc = new ResourceSection(rsrcbytes,
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
			//TODO cast to int is insecure. actual int is unsigned, java int is signed
		    long vSize = section.get(VIRTUAL_SIZE);
			long vAddress = section.get(VIRTUAL_ADDRESS);
			if (rvaIsWithin(vAddress, vSize, rva)) {
				return section;
			}
		}
		return null;
	}

	private static boolean rvaIsWithin(long address, long size, long rva) {
		long endpoint = address + size;
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
			Long virtualAddress = idataEntry.get(VIRTUAL_ADDRESS); 
			if (virtualAddress != null) {
				try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
					raf.seek(idataEntry.get(POINTER_TO_RAW_DATA));
					//TODO cast to int is insecure. actual int is unsigned, java int is signed
					byte[] idatabytes = new byte[idataEntry.get(
							SIZE_OF_RAW_DATA).intValue()];
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
