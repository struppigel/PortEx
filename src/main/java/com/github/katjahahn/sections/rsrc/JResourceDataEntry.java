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
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.IOUtil;
import com.github.katjahahn.PEModule;
import com.github.katjahahn.StandardEntry;

public class JResourceDataEntry extends PEModule {

	public static final int SIZE = 16;
	private final static String RSRC_DATA_ENTRY_SPEC = "resourcedataentryspec";
	private Map<String, String[]> resourceDataEntrySpec;
	private Map<ResourceDataEntryKey, StandardEntry> data;
	private byte[] entryBytes;

	public JResourceDataEntry(byte[] entryBytes) {
		try {
			this.entryBytes = entryBytes.clone();
			resourceDataEntrySpec = IOUtil.readMap(RSRC_DATA_ENTRY_SPEC);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void read() throws IOException {
		data = new HashMap<>();
		for (Entry<String, String[]> entry : resourceDataEntrySpec.entrySet()) {
			String[] specs = entry.getValue();
			ResourceDataEntryKey key = ResourceDataEntryKey.valueOf(entry.getKey());
			long value = getBytesLongValue(entryBytes,
					Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
			String description = specs[0];
			data.put(key, new StandardEntry(key, description, value));
		}
	}
	
	public StandardEntry get(ResourceDataEntryKey key) {
		return data.get(key);
	}
	
	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder();
		b.append(NL + "** resource data **" + NL + NL);
		for (StandardEntry entry : data.values()) {
			long value = entry.value;

			b.append(entry.description + ": " + value + " (0x"
					+ Long.toHexString(value) + ")" + NL);
		}
		return b.toString();
	}

}
