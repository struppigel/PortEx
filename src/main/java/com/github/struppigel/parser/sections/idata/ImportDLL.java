/* ******************************************************************************
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
package com.github.struppigel.parser.sections.idata;

import com.github.struppigel.parser.IOUtil;
import com.github.struppigel.parser.PhysicalLocation;
import com.github.struppigel.parser.IOUtil;
import com.github.struppigel.parser.PhysicalLocation;
import com.google.common.base.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.*;

/**
 * Represents all imports from a single DLL.
 * 
 * @author Katja Hahn
 *
 */
public class ImportDLL {

	private static final Logger logger = LogManager.getLogger(ImportDLL.class
			.getName());
	/**
	 * The name of the DLL
	 */
	private final String name;

	/**
	 * Imports by name
	 */
	private final List<NameImport> nameImports;

	/**
	 * Imports by ordinal
	 */
	private final List<OrdinalImport> ordinalImports;

	/**
	 * Imports
	 */
	private final List<Import> allImports;

	private final long timedateStamp;

	/**
	 * Creates an ImportDLL instance
	 * 
	 * @param name
	 *            the DLL's name
	 * @param nameImports
	 *            the imports by name
	 * @param ordinalImports
	 *            the imports by ordinal
	 */
	public ImportDLL(String name, List<NameImport> nameImports,
			List<OrdinalImport> ordinalImports, List<Import> allImports, long timedateStamp) {
		this.name = name;
		this.nameImports = new ArrayList<>(nameImports);
		this.ordinalImports = new ArrayList<>(ordinalImports);
		this.allImports = new ArrayList<>(allImports);
		this.timedateStamp = timedateStamp;
	}

	/**
	 * Creates an ImportDLL instance
	 *
	 * @param name
	 *            the DLL's name
	 * @param nameImports
	 *            the imports by name
	 * @param ordinalImports
	 *            the imports by ordinal
	 */
	public ImportDLL(String name, List<NameImport> nameImports,
					 List<OrdinalImport> ordinalImports, long timedateStamp) {
		this(name, nameImports, ordinalImports, new ArrayList<>(), timedateStamp);
	}

	public List<PhysicalLocation> getLocations() {
		List<PhysicalLocation> locs = new ArrayList<>();
		for (NameImport i : nameImports) {
			locs.addAll(i.getLocations());
		}
		for (OrdinalImport i : ordinalImports) {
			locs.addAll(i.getLocations());
		}
		return locs;
	}

	public long getTimeDateStamp() {
		return timedateStamp;
	}

	/**
	 * Creates an empty ImportDLL instance (without symbol imports)
	 * 
	 * @param name
	 *            the DLL's name
	 */
	public ImportDLL(String name, long timedateStamp) {
		this.name = name;
		this.nameImports = new ArrayList<>();
		this.ordinalImports = new ArrayList<>();
		this.allImports = new ArrayList<>();
		this.timedateStamp = timedateStamp;
	}

	/**
	 * Adds an import by name to the list
	 * 
	 * @param nameImport
	 *            the import by name
	 */
	public void add(NameImport nameImport) {
		this.nameImports.add(nameImport);
	}

	/**
	 * Adds an import by ordinal to the list
	 * 
	 * @param ordImport
	 *            the import by ordinal
	 */
	public void add(OrdinalImport ordImport) {
		this.ordinalImports.add(ordImport);
	}

	/**
	 * Returns the name of the DLL
	 * 
	 * @return the name of the DLL
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns a copied list of all imports by name.
	 * 
	 * @return imports by name
	 */
	public List<NameImport> getNameImports() {
		return new ArrayList<>(nameImports);
	}

	/**
	 * Returns a copied list of all imports by ordinal.
	 * 
	 * @return imports by ordinal
	 */
	public List<OrdinalImport> getOrdinalImports() {
		return new ArrayList<>(ordinalImports);
	}

	/**
	 * Returns a copied list of all imports, ordinals and by name.
	 *
	 * @return all imports, ordinal and by name
	 */
	public List<Import> getAllImports() {
		return new ArrayList<>(allImports);
	}

	/**
	 * Retreive SymbolDescription for the named import by searching the name.
	 * @param importName
	 * @return None if not available, otherwise Some SymbolDescription
	 */
	public static Optional<SymbolDescription> getSymbolDescriptionForName(String importName) {
		List<SymbolDescription> symbolDescriptions = new ArrayList<>();
		try {
			symbolDescriptions = IOUtil.readSymbolDescriptions();
		} catch (IOException e) {
			logger.error(e);
			e.printStackTrace();
		}
		return findSymbolByName(symbolDescriptions, importName);
	}

	private static Optional<SymbolDescription> findSymbolByName(
			List<SymbolDescription> list, String name) {
		for (SymbolDescription symbol : list) {
			if (symbol.getSymbolName().equals(name)) {
				return Optional.of(symbol);
			}
		}
		if (name.endsWith("W") || name.endsWith("A")) {
			return findSymbolByName(list, name.substring(0, name.length() - 1));
		}
		return Optional.absent();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		List<SymbolDescription> symbolDescriptions = null;
		Map<String, List<NameImport>> categories = new HashMap<>();
		categories.put("[Other]", new ArrayList<NameImport>());
		try {
			symbolDescriptions = IOUtil.readSymbolDescriptions();
		} catch (IOException e) {
			e.printStackTrace();
		}
		StringBuilder buffer = new StringBuilder();
		buffer.append(name + IOUtil.NL);
		for(int i = 0; i < name.length(); i++){
			buffer.append("-");
		}
		String timedateStampString = "0x" + Long.toHexString(timedateStamp);
		if(timedateStamp != 0) {
			timedateStampString += " " + (new Date(timedateStamp * 1000)).toLocaleString();
		}
		buffer.append(IOUtil.NL + "Time date stamp: " + timedateStampString + IOUtil.NL + IOUtil.NL);

		for (NameImport nameImport : nameImports) {
			if (symbolDescriptions != null) {
				Optional<SymbolDescription> symbol = findSymbolByName(
						symbolDescriptions, nameImport.getName());
				if (symbol.isPresent()) {
					String category = symbol.get().getCategory() + " " + symbol.get().getSubCategory().or("");
					if (categories.containsKey(category)) {
						categories.get(category).add(nameImport);
					} else {
						List<NameImport> nameImportList = new ArrayList<>();
						nameImportList.add(nameImport);
						categories.put(category, nameImportList);
					}
				} else {
					categories.get("[Other]").add(nameImport);
				}
			} else {
				categories.get("[Other]").add(nameImport);
			}
		}

		for (Map.Entry<String, List<NameImport>> entry : categories.entrySet()) {
			if (entry.getValue().isEmpty()) {
				continue;
			}
			buffer.append(entry.getKey() + IOUtil.NL);
			for (NameImport nameImport : entry.getValue()) {
				buffer.append(nameImport.toString());
				Optional<SymbolDescription> symbol = findSymbolByName(
						symbolDescriptions, nameImport.getName());
				if (symbol.isPresent()) {
					buffer.append(" -> "
							+ symbol.get().getDescription()
									.or("no description"));
				}
				buffer.append(IOUtil.NL);
			}
			buffer.append(IOUtil.NL);
		}
		for (Import ordImport : ordinalImports) {
			buffer.append(ordImport.toString() + IOUtil.NL);
		}
		return buffer.toString();
	}

}
