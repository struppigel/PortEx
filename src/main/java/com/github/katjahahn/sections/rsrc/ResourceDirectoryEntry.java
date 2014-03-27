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
package com.github.katjahahn.sections.rsrc;

import static com.github.katjahahn.ByteArrayUtil.*;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.IOUtil;
import com.github.katjahahn.PEModule;

public class ResourceDirectoryEntry extends PEModule {

	private final Map<String, String[]> resourceDirEntrySpec;
	private final static String RSRC_DIR_ENTRY_SPEC = "resourcedirentryspec";

	private final boolean isNameEntry;
	private Integer nameRVA;
	private Integer dataEntryRVA;
	private Integer subDirRVA;
	private Integer integerId;
	private final byte[] entryBytes;
	private final int entryNr;
	private final int parentId;
	
	public ResourceDirectoryEntry(boolean isNameEntry, byte[] entryBytes,
			int entryNr, int parentId) throws IOException {
		this.isNameEntry = isNameEntry;
		this.entryBytes = entryBytes;
		this.entryNr = entryNr;
		this.parentId = parentId;
		resourceDirEntrySpec = IOUtil.readMap(RSRC_DIR_ENTRY_SPEC);
	}

	@Override
	public void read() throws IOException {
		int valueOffset = 2;
		int valueSize = 3;

		for (Entry<String, String[]> entry : resourceDirEntrySpec.entrySet()) {
			String[] specs = entry.getValue();
			int value = getBytesIntValue(entryBytes,
					Integer.parseInt(specs[valueOffset]),
					Integer.parseInt(specs[valueSize]));
			String key = entry.getKey();
			switch (key) {
			case "DATA_ENTRY_RVA_OR_SUBDIR_RVA":
				if (isDataEntryRVA(value)) {
					dataEntryRVA = value;
				} else {
					subDirRVA = removeHighestBit(value);
				}
				break;
			case "NAME_RVA_OR_INTEGER_ID":
				if (isNameEntry()) {
					nameRVA = value;
				} else {
					integerId = value;
				}
				break;
			default:
				throw new IllegalArgumentException("no valid key " + key);
			}
		}
	}

	public boolean isNameEntry() {
		return isNameEntry;
	}

	private boolean isDataEntryRVA(long value) {
		int mask = 1 << 31;
		return (value & mask) == 0;
	}

	private int removeHighestBit(int value) {
		int mask = 0x7FFFFFFF;
		return (value & mask);
	}

	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder();
		final int description = isNameEntry ? 0 : 1;
		int dataEntryRvaDescription = 0;
		int idEntryDescription = 1;
		int valueOffset = 2;
		int valueSize = 3;
		String entryDescr = "id entry";
		if (isNameEntry) {
			entryDescr = "name entry";
		}
		b.append(NL + "table " + parentId + ", " + entryDescr + " " + entryNr
				+ NL);
		b.append("........................" + NL + NL);

		for (Entry<String, String[]> entry : resourceDirEntrySpec.entrySet()) {
			String[] specs = entry.getValue();
			int value = getBytesIntValue(entryBytes,
					Integer.parseInt(specs[valueOffset]),
					Integer.parseInt(specs[valueSize]));
			String key = entry.getKey();
			if (key.equals("DATA_ENTRY_RVA_OR_SUBDIR_RVA")) {
				appendSubDirOrDataEntryRvaInfo(b, dataEntryRvaDescription,
						idEntryDescription, specs, value);
			} else {
				b.append(specs[description] + ": " + value + NL);
			}
		}
		b.append(NL);
		return b.toString();
	}

	private void appendSubDirOrDataEntryRvaInfo(StringBuilder b,
			int dataEntryRvaDescription, int idEntryDescription,
			String[] specs, int value) {

		if (isDataEntryRVA(value)) {
			b.append(specs[dataEntryRvaDescription] + ": " + value + " (0x"
					+ Integer.toHexString(value) + ")" + NL);
		} else {
			value = removeHighestBit(value);
			b.append(specs[idEntryDescription] + ": " + value + " (0x"
					+ Long.toHexString(value) + ")" + NL);
		}
	}

	/**
	 * @return the nameRVA
	 */
	public Integer getNameRVA() {
		return nameRVA;
	}

	/**
	 * @return the dataEntryRVA
	 */
	public Integer getDataEntryRVA() {
		return dataEntryRVA;
	}

	/**
	 * @return the subDirRVA
	 */
	public Integer getSubDirRVA() {
		return subDirRVA;
	}

	/**
	 * @return the integerId
	 */
	public Integer getIntegerId() {
		return integerId;
	}

	@Override
	public String toString() {
		return "entry " + entryNr + " from table " + parentId;
	}
}
