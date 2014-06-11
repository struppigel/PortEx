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
package com.github.katjahahn.sections.idata;

public class OrdinalImport implements Import {

	public int ordinal;
	public long rva;
	private final DirectoryEntry parent;
	
	public OrdinalImport(int ordinal, long rva, DirectoryEntry parent) {
		this.ordinal = ordinal;
		this.rva = rva;
		this.parent = parent;
	}
	
	public Long getDirEntry(DirectoryEntryKey key) {
		return parent.get(key);
	}
	@Override
	public String toString() {
		return "ordinal: " + ordinal + ", RVA: " + rva;
	}
}
