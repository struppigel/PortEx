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

public class JResourceDirectoryEntry extends PEModule {

	private final Map<String, String[]> resourceDirEntrySpec;
	private final static String RSRC_DIR_ENTRY_SPEC = "resourcedirentryspec";

	private final boolean isNameEntry;
	private Long nameRVA;
	private Long dataEntryRVA;
	private Long subDirRVA;
	private Long integerId;
	private final byte[] entryBytes;
	private final int entryNr;
	private final int parentId;

	public JResourceDirectoryEntry(boolean isNameEntry, byte[] entryBytes,
			int entryNr, int parentId) throws IOException {
		this.isNameEntry = isNameEntry;
		this.entryBytes = entryBytes.clone();
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
			long value = getBytesLongValue(entryBytes,
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

	// TODO test for long
	private long removeHighestBit(long value) {
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
			long value = getBytesLongValue(entryBytes,
					Integer.parseInt(specs[valueOffset]),
					Integer.parseInt(specs[valueSize]));
			String key = entry.getKey();
			if (key.equals("DATA_ENTRY_RVA_OR_SUBDIR_RVA")) {
				appendSubDirOrDataEntryRvaInfo(b, dataEntryRvaDescription,
						idEntryDescription, specs, (int) value); // TODO use
																	// always
																	// long
			} else {
				b.append(specs[description] + ": " + value + NL);
				b.append("resource type by id: "
						+ getResourceTypeByID((int) value));
				// TODO this is just for testing
			}
		}
		b.append(NL);
		return b.toString();
	}

	//TODO create file with info. see here for more: 
	// http://msdn.microsoft.com/en-us/library/windows/desktop/ms648009%28v=vs.85%29.aspx
	private String getResourceTypeByID(int id) {
		switch (id) {
		case 1:
			return "RT_CURSOR";
		case 10:
			return "RT_RCDATA";
		default:
			return "unknown";
		}
	}

	private void appendSubDirOrDataEntryRvaInfo(StringBuilder b,
			int dataEntryRvaDescription, int idEntryDescription,
			String[] specs, long value) {

		if (isDataEntryRVA(value)) {
			b.append(specs[dataEntryRvaDescription] + ": " + value + " (0x"
					+ Long.toHexString(value) + ")" + NL);
		} else {
			value = removeHighestBit(value);
			b.append(specs[idEntryDescription] + ": " + value + " (0x"
					+ Long.toHexString(value) + ")" + NL);
		}
	}

	/**
	 * @return the nameRVA
	 */
	public Long getNameRVA() {
		return nameRVA;
	}

	/**
	 * @return the dataEntryRVA
	 */
	public Long getDataEntryRVA() {
		return dataEntryRVA;
	}

	/**
	 * @return the subDirRVA
	 */
	public Long getSubDirRVA() {
		return subDirRVA;
	}

	/**
	 * @return the integerId
	 */
	public Long getIntegerId() {
		return integerId;
	}

	@Override
	public String toString() {
		return "entry " + entryNr + " from table " + parentId;
	}
}
