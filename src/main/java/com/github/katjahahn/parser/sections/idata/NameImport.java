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

import com.github.katjahahn.parser.Location;

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
    public long rva;

    /**
     * The relative virtual address to the name
     */
    public long nameRVA;

    /**
     * The name of the import
     */
    public String name;

    /**
     * The import's hint
     */
    public int hint;

    /**
     * The directory entry this import belongs to
     */
    private final DirectoryEntry parent;
    
    private final List<Location> locations;

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
    public NameImport(long rva, String name, int hint, long nameRVA,
            DirectoryEntry parent, List<Location> locations) {
        this.rva = rva;
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
        return "rva: " + rva + " (0x" + Long.toHexString(rva) + "), name: "
                + name + ", hint: " + hint;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Location> getLocations() {
        return new ArrayList<Location>(locations);
    }
}
