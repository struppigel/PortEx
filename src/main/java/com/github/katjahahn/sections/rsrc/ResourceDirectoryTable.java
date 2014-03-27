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
import static com.github.katjahahn.sections.rsrc.ResourceDirectoryTableKey.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.HeaderKey;
import com.github.katjahahn.PEModule;
import com.github.katjahahn.StandardEntry;

public class ResourceDirectoryTable extends PEModule {

	private final static int ENTRY_SIZE = 8;
	private final static int RESOURCE_DIR_OFFSET = 16;
	private Map<ResourceDirectoryTableKey, StandardEntry> data;
	private final Map<String, String[]> rsrcDirSpec;
	private final byte[] tableBytes;

	// TODO put children and dataEntries to DirectoryEntries
	// XXX this is a mess!
	private final List<ResourceDirectoryEntry> dirEntries = new ArrayList<>();
	private final List<ResourceDirectoryTable> children = new ArrayList<>();
	private final List<ResourceDataEntry> dataEntries = new ArrayList<>();

	private int nameEntries;
	private int idEntries;
	private Date stamp;
	private final int id;
	private final int offset;

	public ResourceDirectoryTable(Map<String, String[]> rsrcDirSpec,
			byte[] tableBytes, int id, int offset) throws IOException {
		this.rsrcDirSpec = rsrcDirSpec;
		this.tableBytes = tableBytes.clone();
		this.id = id;
		this.offset = offset;
	}

	@Override
	public void read() throws IOException {
		data = new HashMap<>();
		for (Entry<String, String[]> entry : rsrcDirSpec.entrySet()) {

			String[] specs = entry.getValue();
			int value = getBytesIntValue(tableBytes,
					Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
			ResourceDirectoryTableKey key = ResourceDirectoryTableKey.valueOf(entry.getKey());

			if (key.equals(TIME_DATE_STAMP)) {
				stamp = getTimeDate(value);
			}

			if (key.equals(NR_OF_NAME_ENTRIES)) {
				nameEntries = value;
			} else if (key.equals(NR_OF_ID_ENTRIES)) {
				idEntries = value;
			}

			data.put(key, new StandardEntry(
					key, specs[0], value));
		}
		if (nameEntries != 0 || idEntries != 0) {
			loadResourceDirEntries();
			loadDataEntries();
			loadChildren();
		}
	}

	private void loadChildren() throws IOException {
		int childId = id;
		for (ResourceDirectoryEntry entry : dirEntries) {
			Integer address = entry.getSubDirRVA();

			if (address != null) {
				childId++;
				try {
					byte[] resourceBytes = Arrays.copyOfRange(tableBytes,
							address - offset, tableBytes.length);
					ResourceDirectoryTable table = new ResourceDirectoryTable(
							rsrcDirSpec, resourceBytes, childId, address);
					table.read();
					children.add(table);
				} catch (IllegalArgumentException e) {
					e.printStackTrace();
				}
			}

		}
	}

	private void loadResourceDirEntries() throws IOException {
		for (int i = 0; i < nameEntries + idEntries; i++) {
			int offset = RESOURCE_DIR_OFFSET + i * ENTRY_SIZE;
			int endpoint = offset + ENTRY_SIZE;
			int entryNr = i + 1;
			byte[] entryBytes = Arrays
					.copyOfRange(tableBytes, offset, endpoint);
			if (i < nameEntries) {
				dirEntries.add(new ResourceDirectoryEntry(true, entryBytes,
						entryNr, id));
			} else {
				dirEntries.add(new ResourceDirectoryEntry(false, entryBytes,
						entryNr, id));
			}
		}
	}

	private void loadDataEntries() {
		for (ResourceDirectoryEntry dirEntry : dirEntries) {
			Integer rva = dirEntry.getDataEntryRVA();
			if (rva != null) {
				byte[] entryBytes = Arrays.copyOfRange(tableBytes,
						rva - offset, (rva - offset) + ResourceDataEntry.SIZE);
				dataEntries.add(new ResourceDataEntry(entryBytes));
			}
		}
	}

	private Date getTimeDate(int seconds) {
		long millis = (long) seconds * 1000;
		return new Date(millis);
	}

	// XXX This is a mess too! Display a nice tree structure or something like
	// that.
	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder();
		b.append("** table header " + id + " **" + NL + NL);

		for (StandardEntry entry : data.values()) {

			long value = entry.value;
			HeaderKey key = entry.key;
			String description = entry.description;

			if (key.equals(TIME_DATE_STAMP)) {
				b.append(description + ": ");
				b.append(getTimeDate((int) value) + NL);
			} else {
				b.append(description + ": " + value + NL);
			}
		}
		for (ResourceDirectoryEntry entry : dirEntries) {
			b.append(entry.getInfo());
		}
		for (ResourceDataEntry entry : dataEntries) {
			b.append(entry.getInfo());
		}
		for (ResourceDirectoryTable child : children) {
			b.append(child.getInfo());
		}
		return b.toString();
	}

	public Date getStamp() {
		return (Date) stamp.clone();
	}

}
