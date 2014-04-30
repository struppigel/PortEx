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

import java.util.HashMap;
import java.util.Map;

import com.github.katjahahn.StandardEntry;

public class SectionTableEntry {

	private final HashMap<SectionTableEntryKey, StandardEntry> entries = new HashMap<>();
	private String name;

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public Long get(SectionTableEntryKey key) {
		return entries.get(key).value;
	}
	
	public StandardEntry getEntry(SectionTableEntryKey key) {
		return entries.get(key);
	}
	
	public Map<SectionTableEntryKey, StandardEntry> getEntryMap() {
		return new HashMap<>(entries);
	}

	public void add(StandardEntry entry) {
		if(entry.key instanceof SectionTableEntryKey) {
			entries.put((SectionTableEntryKey) entry.key, entry);
		} else {
			throw new IllegalArgumentException("invalid key");
		}
	}

}
