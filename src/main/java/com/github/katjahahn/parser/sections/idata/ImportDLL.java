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

import java.util.ArrayList;
import java.util.List;

import com.github.katjahahn.parser.IOUtil;

public class ImportDLL {
	
	private final String name;
	
	private final List<NameImport> nameImports;
	private final List<OrdinalImport> ordinalImports;
	
	public ImportDLL(String name, List<NameImport> nameImports, List<OrdinalImport> ordinalImports) {
		this.name = name;
		this.nameImports = new ArrayList<>(nameImports);
		this.ordinalImports = new ArrayList<>(ordinalImports);
	}
	
	public ImportDLL(String name) {
		this.name = name;
		this.nameImports = new ArrayList<>();
		this.ordinalImports = new ArrayList<>();
	}
	
	public void add(NameImport nameImport) {
		this.nameImports.add(nameImport);
	}
	
	public void add(OrdinalImport ordImport) {
		this.ordinalImports.add(ordImport);
	}
	
	public String getName() {
		return name;
	}
	
	public List<NameImport> getNameImports() {
		return new ArrayList<>(nameImports);
	}
	
	public List<OrdinalImport> getOrdinalImports() {
		return new ArrayList<>(ordinalImports);
	}
	
	@Override
	public String toString() {
		StringBuilder buffer = new StringBuilder();
		buffer.append(name + IOUtil.NL);
		for(Import nameImport : nameImports) {
			buffer.append(nameImport.toString() + IOUtil.NL);
		}
		for(Import ordImport : ordinalImports) {
			buffer.append(ordImport.toString() + IOUtil.NL);
		}
		return buffer.toString();
	}

}
