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

import com.github.katjahahn.parser.PhysicalLocation;

/**
 * Represents an import by name.
 * 
 * @author Katja Hahn
 * 
 */
public class NameImport implements Import {

    /**
     * The relative virtual address to the symbol
     */
    private long rva;
    
    /**
     * The virtual address to the symbol
     */
    private long va;

    /**
     * The relative virtual address to the name
     */
    private long nameRVA;

    /**
     * The name of the import
     */
    private String name;

    /**
     * The import's hint
     */
    private int hint;

    /**
     * The directory entry this import belongs to
     */
    private final DirectoryEntry parent;

    private final List<PhysicalLocation> locations;

    /**
     * 
     * @param rva
     *            relative virtual address to the symbol
     * @param name
     *            the name of the import
     * @param hint
     *            the import's hint
     * @param nameRVA
     *            the relative virtual address to the name
     * @param parent
     *            the directory entry this import belongs to
     * @param locations
     *            list of file locations the import is in
     */
    public NameImport(long rva, long va, String name, int hint, long nameRVA,
            DirectoryEntry parent, List<PhysicalLocation> locations) {
        this.rva = rva;
        this.va = va;
        this.hint = hint;
        this.name = name;
        this.nameRVA = nameRVA;
        this.parent = parent;
        this.locations = locations;
    }

    /**
     * Returns the value of the data directory field
     */
    public Long getDirEntryValue(DirectoryEntryKey key) {
        return parent.get(key);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "rva: 0x" + Long.toHexString(rva) + ", va: 0x" + 
        		Long.toHexString(va) + ", hint: " + hint + ", name: " + 
        		name;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PhysicalLocation> getLocations() {
        return new ArrayList<PhysicalLocation>(locations);
    }

    /**
     * Returns the relative virtual address to the symbol
     * 
     * @return relative virtual address to the symbol
     */
    public long getRVA() {
        return rva;
    }

    /**
     * Returns the name rva of the import
     * 
     * @return the name rva of the import
     */
    public long getNameRVA() {
        return nameRVA;
    }

    /**
     * Returns the name of the import
     * 
     * @return the name of the import
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the import's hint
     * 
     * @return the import's hint
     */
    public int getHint() {
        return hint;
    }
}
