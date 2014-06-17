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
package com.github.katjahahn.parser.sections.idata;

public class NameImport implements Import {

	public long rva;
	public long nameRVA;
	public String name;
	public int hint;
	private final DirectoryEntry parent;

	public NameImport(long rva, String name, int hint, long nameRVA,
			DirectoryEntry parent) {
		this.rva = rva;
		this.hint = hint;
		this.name = name;
		this.nameRVA = nameRVA;
		this.parent = parent;
	}

	public Long getDirEntry(DirectoryEntryKey key) {
		return parent.get(key);
	}

	@Override
	public String toString() {
		return "rva: " + rva + " (0x" + Long.toHexString(rva) + "), name: " + name + ", hint: " + hint;
	}
}
