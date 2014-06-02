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

import static com.github.katjahahn.ByteArrayUtil.*;
import static com.github.katjahahn.IOUtil.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.IOUtil;
import com.github.katjahahn.StandardField;

/**
 * Represents the section table of a PE. Is usually constructed by the PELoader.
 * 
 * @author Katja Hahn
 * 
 */
public class SectionTable {

	@SuppressWarnings("unused")
	private static final Logger logger = LogManager
			.getLogger(SectionTable.class.getName());

	private final static String SECTION_TABLE_SPEC = "sectiontablespec";

	/**
	 * Size of one entry is {@value}
	 */
	public final static int ENTRY_SIZE = 40;

	private List<SectionHeader> headers;
	private final byte[] sectionTableBytes;
	private final int numberOfEntries;
	private Map<String, String[]> specification;

	private final long offset;

	/**
	 * @constructor creates the SectionTable with the bytes of the table and the
	 *              number of entries
	 * @param sectionTableBytes
	 * @param numberOfEntries
	 */
	public SectionTable(byte[] sectionTableBytes, int numberOfEntries,
			long offset) {
		this.sectionTableBytes = sectionTableBytes.clone();
		this.numberOfEntries = numberOfEntries;
		this.offset = offset;
		try {
			specification = IOUtil.readMap(SECTION_TABLE_SPEC);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void read() throws IOException {
		headers = new LinkedList<>();

		for (int i = 0; i < numberOfEntries; i++) {
			int sectionNumber = i + 1;
			int sectionOffset = i * ENTRY_SIZE;
			SectionHeader sectionEntry = new SectionHeader(sectionNumber,
					sectionOffset);
			byte[] section = Arrays.copyOfRange(sectionTableBytes,
					sectionOffset, sectionOffset + ENTRY_SIZE);

			for (Entry<String, String[]> entry : specification.entrySet()) {

				String[] specs = entry.getValue();
				long value = getBytesLongValue(section,
						Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
				SectionHeaderKey key = SectionHeaderKey.valueOf(entry.getKey());

				if (key.equals(SectionHeaderKey.NAME)) {
					sectionEntry.setName(getUTF8String(section));
					continue;
				}

				sectionEntry.add(new StandardField(key, specs[0], value));
			}
			headers.add(sectionEntry);
		}
	}

	/**
	 * Returns all entries of the section table as a list. They are in the same
	 * order as they are within the Section Table.
	 * 
	 * @return ordered section table entries
	 */
	public List<SectionHeader> getSectionHeaders() {
		return new LinkedList<>(headers);
	}

	/**
	 * Returns the section entry that has the given number or null if there is
	 * no section with that number.
	 * 
	 * @param number
	 * @return the section table entry that has the given number
	 */
	public SectionHeader getSectionHeader(int number) {
		for (SectionHeader header : headers) {
			if (header.getNumber() == number) {
				return header;
			}
		}
		return null;
	}

	/**
	 * Returns the section entry that has the given name or null if there is no
	 * section with that name. If there are several sections with the same name,
	 * the first one will be returned.
	 * 
	 * TODO there might be several sections with the same name. Provide a better
	 * way to fetch them.
	 * 
	 * @param sectionName
	 * @return the section table entry that has the given sectionName
	 */
	public SectionHeader getSectionHeader(String sectionName) {
		for (SectionHeader entry : headers) {
			if (entry.getName().equals(sectionName)) {
				return entry;
			}
		}
		return null;
	}

	/**
	 * Returns the value for the PointerToRawData entry of a given section name.
	 * 
	 * @param sectionName
	 * @return
	 */
	// TODO use the sections list
	public Long getPointerToRawData(String sectionName) {
		for (int i = 0; i < numberOfEntries; i++) {
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			if (isSection(sectionName, section)) {
				return getPointerToRawData(section);
			}
		}

		return null;
	}

	private Long getPointerToRawData(byte[] section) {
		for (Entry<String, String[]> entry : specification.entrySet()) {
			if (entry.getKey().equals("POINTER_TO_RAW_DATA")) {
				String[] specs = entry.getValue();
				long value = getBytesLongValue(section,
						Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
				return value;
			}
		}
		return null;
	}

	private boolean isSection(String sectionName, byte[] section) {
		for (String key : specification.keySet()) {
			if (key.equals("NAME")
					&& getUTF8String(section).equals(sectionName)) {
				return true;
			}
		}
		return false;
	}

	public String getInfo() {
		StringBuilder b = new StringBuilder();
		b.append("-----------------" + NL + "Section Table" + NL
				+ "-----------------" + NL + NL);
		for (int i = 0; i < numberOfEntries; i++) {
			b.append("entry number " + (i + 1) + ": " + NL + "..............."
					+ NL + NL);
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			b.append(getNextEntryInfo(section) + NL);
		}

		return b.toString();
	}

	private String getNextEntryInfo(byte[] section) {
		StringBuilder b = new StringBuilder();
		for (Entry<String, String[]> entry : specification.entrySet()) {

			String[] specs = entry.getValue();
			long value = getBytesLongValue(section, Integer.parseInt(specs[1]),
					Integer.parseInt(specs[2]));
			String key = entry.getKey();
			if (key.equals("CHARACTERISTICS")) {
				b.append(specs[0]
						+ ": "
						+ NL
						+ IOUtil.getCharacteristics(value,
								"sectioncharacteristics") + NL);
			} else if (key.equals("NAME")) {
				b.append(specs[0] + ": " + getUTF8String(section) + NL);

			} else {
				b.append(specs[0] + ": " + value + " (0x"
						+ Long.toHexString(value) + ")" + NL);
			}
		}
		return b.toString();
	}

	private String getUTF8String(byte[] section) {
		String[] values = specification.get("NAME");
		int from = Integer.parseInt(values[1]);
		int to = from + Integer.parseInt(values[2]);
		byte[] bytes = Arrays.copyOfRange(section, from, to);
		try {
			return new String(bytes, "UTF8").trim();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Computes the virtual address for a given section name.
	 * 
	 * @param sectionName
	 * @return virtual address of a section
	 */
	public Long getVirtualAddress(String sectionName) {
		for (int i = 0; i < numberOfEntries; i++) {
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			if (isSection(sectionName, section)) {
				return getVirtualAddress(section);
			}
		}
		return null;
	}

	private Long getVirtualAddress(byte[] section) {
		for (Entry<String, String[]> entry : specification.entrySet()) {
			if (entry.getKey().equals("VIRTUAL_ADDRESS")) {
				String[] specs = entry.getValue();
				long value = getBytesLongValue(section,
						Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
				return value;
			}
		}
		return null;
	}

	// TODO this is nuts, why read it again? Same code as getPointerToRawData
	/**
	 * Returns the raw size of the section with the given section name. TODO use
	 * entry number instead. the name is not enough to identify a section
	 * uniquely.
	 * 
	 * @param sectionName
	 * @return
	 */
	public Long getSize(String sectionName) {
		for (int i = 0; i < numberOfEntries; i++) {
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			if (isSection(sectionName, section)) {
				return getSizeOfRawData(section);
			}
		}

		return null;
	}

	private Long getSizeOfRawData(byte[] section) {
		for (Entry<String, String[]> entry : specification.entrySet()) {
			if (entry.getKey().equals("SIZE_OF_RAW_DATA")) {
				String[] specs = entry.getValue();
				long value = getBytesLongValue(section,
						Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
				return value;
			}
		}
		return null;
	}

	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the first section that has the given name.
	 * 
	 * @param name
	 * @return first section with the given name
	 */
	public SectionHeader getSectionHeaderByName(String name) {
		for (SectionHeader header : headers) {
			if (header.getName().equals(name)) {
				return header;
			}
		}
		return null;
	}

	public int getSize() {
		return ENTRY_SIZE * numberOfEntries;
	}
}
