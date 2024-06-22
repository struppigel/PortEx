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
package com.github.struppigel.parser.sections.idata;

import com.github.struppigel.parser.PhysicalLocation;
import com.github.struppigel.parser.PhysicalLocation;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents an import by ordinal.
 * 
 * @author Katja Hahn
 * 
 */
public class OrdinalImport implements Import {

    /**
     * The ordinal number of the import
     */
    private int ordinal;

    /**
     * The relative virtual address of the symbol
     */
    private long rva;
    
    /**
     * The virtual address of the symbol
     */
    private long va;

    /**
     * The directory entry this import belongs to
     */
    private final DirectoryEntry parent;

    private final List<PhysicalLocation> locations;

    /**
     * 
     * @param ordinal
     *            the ordinal number of the import
     * @param rva
     *            the rva of the symbol
     * @param parent
     *            the directory entry this import belongs to
     * @param locations
     *            list of file locations the import is in
     */
    public OrdinalImport(int ordinal, long rva, long va, DirectoryEntry parent,
            List<PhysicalLocation> locations) {
        this.ordinal = ordinal;
        this.rva = rva;
        this.va = va;
        this.parent = parent;
        this.locations = locations;
    }

    /**
     * Returns the ordinal number of the import
     * 
     * @return the ordinal number of the import
     */
    public int getOrdinal() {
        return ordinal;
    }

    /**
     * Returns the rva of the symbol
     * 
     * @return the rva of the symbol
     */
    public long getRVA() {
        return rva;
    }

    /**
     * Returns the value of the directory entry field
     */
    public Long getDirEntryValue(DirectoryEntryKey key) {
        return parent.get(key);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        String offsetStr = "";
        if(locations.size() > 0){
            offsetStr = ", offset: 0x" + Long.toHexString(locations.get(0).from());
        }
        return "ordinal: " + ordinal + ", rva: 0x"
                + Long.toHexString(rva) + ", va: 0x" + Long.toHexString(va) + offsetStr;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<PhysicalLocation> getLocations() {
        return new ArrayList<PhysicalLocation>(locations);
    }
}
