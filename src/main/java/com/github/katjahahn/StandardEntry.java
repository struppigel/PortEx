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
package com.github.katjahahn;

import com.github.katjahahn.coffheader.COFFHeaderKey;
import com.github.katjahahn.msdos.MSDOSHeaderKey;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.optheader.StandardFieldEntryKey;
import com.github.katjahahn.optheader.WindowsEntryKey;
import com.github.katjahahn.sections.SectionTableEntryKey;
import com.github.katjahahn.sections.idata.ImportDirEntryKey;
import com.github.katjahahn.sections.rsrc.ResourceDataEntryKey;

/**
 * A data class for a typical entry of PE Headers
 * 
 * @author Katja Hahn
 * 
 */
public class StandardEntry {

	public HeaderKey key;
	public String description;
	public long value;

	/**
	 * @constructor Creates a standard entry with the values specified.
	 * 
	 * @param key
	 * @param description
	 * @param value
	 */
	public StandardEntry(HeaderKey key, String description, long value) {
		this.key = key;
		this.description = description;
		this.value = value;
	}

	/**
	 * @constructor Creates a standard entry with the values specified.
	 * 
	 * @param key
	 * @param description
	 * @param value
	 */
	public StandardEntry(String key, String description, long value) {
		this.key = getKeyForString(key);
		if (key == null) {
			throw new IllegalArgumentException("illegal key string");
		}
		this.description = description;
		this.value = value;
	}

	//XXX: This is not maintainable, nor accurate (some keys have the same string). Get rid of it!
	private HeaderKey getKeyForString(String str) {
		HeaderKey[][] keyList = { COFFHeaderKey.values(),
				MSDOSHeaderKey.values(), StandardFieldEntryKey.values(),
				WindowsEntryKey.values(), DataDirectoryKey.values(),
				SectionTableEntryKey.values(), ResourceDataEntryKey.values(), ImportDirEntryKey.values()};
		for(HeaderKey[] keyArray : keyList) {
			for(HeaderKey key : keyArray) {
				if(key.toString().equalsIgnoreCase(str)) {
					return key;
				}
			}
		}
		return null;
	}

	@Override
	public String toString() {
		return description + ": " + value + " (0x" + Long.toHexString(value)
				+ ")";
	}
}
