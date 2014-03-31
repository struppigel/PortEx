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
import com.github.katjahahn.PEModule;
import com.github.katjahahn.StandardEntry;

/**
 * Represents the section table of a PE. Is usually constructed by the PELoader.
 * 
 * @author Katja Hahn
 * 
 */
public class SectionTable extends PEModule {

	private static final Logger logger = LogManager
			.getLogger(SectionTable.class.getName());

	private final static String SECTION_TABLE_SPEC = "sectiontablespec";

	/**
	 * Size of one entry is {@value}
	 */
	public final static int ENTRY_SIZE = 40;

	private List<SectionTableEntry> sections;
	private final byte[] sectionTableBytes;
	private final int numberOfEntries;
	private Map<String, String[]> specification;

	/**
	 * @constructor creates the SectionTable with the bytes of the table and the
	 *              number of entries
	 * @param sectionTableBytes
	 * @param numberOfEntries
	 */
	public SectionTable(byte[] sectionTableBytes, int numberOfEntries) {
		this.sectionTableBytes = sectionTableBytes.clone();
		this.numberOfEntries = numberOfEntries;
		try {
			specification = IOUtil.readMap(SECTION_TABLE_SPEC);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void read() throws IOException {
		sections = new LinkedList<>();

		for (int i = 0; i < numberOfEntries; i++) {
			SectionTableEntry sectionEntry = new SectionTableEntry();
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);

			for (Entry<String, String[]> entry : specification.entrySet()) {

				String[] specs = entry.getValue();
				long value = getBytesLongValue(section,
						Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
				SectionTableEntryKey key = SectionTableEntryKey.valueOf(entry
						.getKey());

				if (key.equals(SectionTableEntryKey.NAME)) {
					sectionEntry.setName(getUTF8String(section));
					continue;
				}

				sectionEntry.add(new StandardEntry(key, specs[0], value));
			}
			sections.add(sectionEntry);
		}
	}

	/**
	 * Returns all entries of the section table as a list
	 * 
	 * @return
	 */
	public List<SectionTableEntry> getSectionEntries() {
		return new LinkedList<>(sections);
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
	public SectionTableEntry getSectionEntry(String sectionName) {
		for (SectionTableEntry entry : sections) {
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

	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder();

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
	public Integer getVirtualAddress(String sectionName) {
		for (int i = 0; i < numberOfEntries; i++) {
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			if (isSection(sectionName, section)) {
				return getVirtualAddress(section);
			}
		}
		return null;
	}

	private Integer getVirtualAddress(byte[] section) {
		for (Entry<String, String[]> entry : specification.entrySet()) {
			if (entry.getKey().equals("VIRTUAL_ADDRESS")) {
				String[] specs = entry.getValue();
				int value = getBytesIntValue(section,
						Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
				return value;
			}
		}
		return null;
	}

	// TODO not tested and it is almost the same code as getPointerToRawData
	public Integer getSize(String sectionName) {
		for (int i = 0; i < numberOfEntries; i++) {
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			if (isSection(sectionName, section)) {
				return getSizeOfRawData(section);
			}
		}

		return null;
	}

	public Integer getSizeOfRawData(byte[] section) {
		for (Entry<String, String[]> entry : specification.entrySet()) {
			if (entry.getKey().equals("SIZE_OF_RAW_DATA")) {
				String[] specs = entry.getValue();
				int value = getBytesIntValue(section,
						Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
				return value;
			}
		}
		return null;
	}
}
