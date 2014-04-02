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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.PEData;
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.optheader.OptionalHeader;
import com.github.katjahahn.sections.idata.ImportSection;
import com.github.katjahahn.sections.rsrc.ResourceSection;

/**
 * Responsible for computing section related values and loading sections with
 * the given section header information.
 * 
 * @author Katja Hahn
 * 
 */
public class SectionLoader {

	private static final Logger logger = LogManager
			.getLogger(SectionLoader.class.getName());

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
	 * This does not instantiate subclasses of {@link PESection}. Use methods like
	 * {@link #loadImportSection()} or {@link #loadResourceSection()} instead.
	 * 
	 * The file on disk is read to fetch the information
	 * 
	 * @param name
	 *            the section's name
	 * @return PESection of the given name, null if section isn't contained in
	 *         file
	 * @throws IOException if unable to read the file
	 */
	public PESection loadSection(String name) throws IOException {
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			Long pointer = table.getPointerToRawData(name);
			if (pointer != null) {
				raf.seek(pointer);
				// TODO cast to int is insecure. actual int is unsigned, java
				// int is signed
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
	 * The file on disk is read to fetch the information.
	 * 
	 * @return {@link ResourceSection} of the given file, null if file doesn't have this
	 *         section
	 * @throws IOException if unable to read the file
	 */
	public ResourceSection loadResourceSection() throws IOException {
		DataDirEntry resourceTable = getDataDirEntryForKey(
				optHeader.getDataDirEntries(), DataDirectoryKey.RESOURCE_TABLE);
		if (resourceTable != null) {
			SectionTableEntry rsrcEntry = resourceTable
					.getSectionTableEntry(table);
			Long virtualAddress = rsrcEntry.get(VIRTUAL_ADDRESS);
			if (virtualAddress != null) {
				try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
					raf.seek(rsrcEntry.get(POINTER_TO_RAW_DATA));
					// TODO cast to int is insecure. actual int is unsigned,
					// java int is signed
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

	/**
	 * Returns the section entry of the section table the rva is pointing into.
	 * 
	 * @param table the section table of the file
	 * @param rva the relative virtual address
	 * @return the {@link SectionTableEntry} of the section the rva is pointing into
	 */
	public static SectionTableEntry getSectionByRVA(SectionTable table, long rva) {
		List<SectionTableEntry> sections = table.getSectionEntries();
		for (SectionTableEntry section : sections) {
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

	/**
	 * Loads all bytes and information of the import section.
	 * The file on disk is read to fetch the information.
	 * 
	 * @return the import section, null if file doesn't have an import section
	 * @throws IOException if unable to read the file
	 */
	public ImportSection loadImportSection() throws IOException {
		DataDirEntry importTable = getDataDirEntryForKey(
				optHeader.getDataDirEntries(), DataDirectoryKey.IMPORT_TABLE);
		if (importTable != null) {
			long virtualAddress = importTable.virtualAddress;
			byte[] idatabytes = readBytesFor(DataDirectoryKey.IMPORT_TABLE);
			ImportSection idata = new ImportSection(idatabytes, virtualAddress,
					optHeader);
			idata.read();
			return idata;
		}
		return null;
	}

	/**
	 * Reads and returns the bytes that belong to the given data directory
	 * entry.
	 * 
	 * The data directory entry rva points into section. This section is
	 * determined and the file offset for the rva calculated. This file offset
	 * is different from the beginning of the determined section, as the section
	 * may contain more than the data directory. The returned bytes start at
	 * that file offset and end at the end of the section the data directory is
	 * in.
	 * 
	 * @param dataDirKey
	 *            the key of the data directory entry you want the bytes for
	 * @return byte array that contains the bytes the data directory entry rva
	 *         is pointing to
	 * @throws IOException
	 *             if unable to read the file
	 */
	public byte[] readBytesFor(DataDirectoryKey dataDirKey) throws IOException {
		DataDirEntry dataDir = getDataDirEntryForKey(optHeader.getDataDirEntries(),
				dataDirKey);
		if (dataDir != null) {
			SectionTableEntry section = dataDir.getSectionTableEntry(table);
			logger.debug("fetching file offset for section: "
					+ section.getName());
			Long virtualAddress = section.get(VIRTUAL_ADDRESS);
			if (virtualAddress != null) {
				long pointerToRawData = section.get(POINTER_TO_RAW_DATA);
				logger.debug("pointer to raw data: " + pointerToRawData + " 0x"
						+ Long.toHexString(pointerToRawData));
				long rva = dataDir.virtualAddress;
				long offset = rva - (virtualAddress - pointerToRawData);
				Long sizeOfRawData = section.get(SIZE_OF_RAW_DATA)
						- (rva - virtualAddress);
				try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
					raf.seek(offset);
					virtualAddress = rva;
					// TODO cast to int is insecure. actual int is unsigned
					byte[] bytes = new byte[sizeOfRawData.intValue()];
					raf.readFully(bytes);
					return bytes;
				}
			} else {
				logger.warn("virtual address not found!");
			}
		} else {
			logger.warn("invalid dataDirKey");
		}
		return null;
	}

	private DataDirEntry getDataDirEntryForKey(List<DataDirEntry> dataDirEntries,
			DataDirectoryKey key) {
		for (DataDirEntry entry : dataDirEntries) {
			if (entry.key.equals(key)) {
				return entry;
			}
		}
		return null;
	}
}
