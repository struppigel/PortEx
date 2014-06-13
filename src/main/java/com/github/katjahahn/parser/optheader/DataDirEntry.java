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
package com.github.katjahahn.parser.optheader;

import static com.github.katjahahn.parser.Header.*;
import static com.github.katjahahn.parser.sections.SectionHeaderKey.*;
import static com.google.common.base.Preconditions.*;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.sections.SectionHeader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.google.common.base.Optional;
import com.google.java.contract.Invariant;

/**
 * Represents an entry of the data directory table. It is used like a struct.
 * 
 * @author Katja Hahn
 * 
 */
@Invariant("key != null")
public class DataDirEntry {

    private static final Logger logger = LogManager
            .getLogger(DataDirEntry.class.getName());

    /**
     * The key of the entry
     */
    public DataDirectoryKey key;

    /**
     * The virtual address of the entry
     */
    public long virtualAddress; // RVA actually, but called like this in spec

    /**
     * The size of the entry
     */
    public long size;

    /**
     * Creates a data dir entry with the fieldName, which is used to retrieve
     * the corresponding {@link DataDirectoryKey}, and the virtualAddress and
     * the size
     * 
     * @throws IllegalArgumentException
     *             if fieldName doesn't match a valid key
     * @param fieldName
     * @param virtualAddress
     * @param size
     */
    public DataDirEntry(String fieldName, long virtualAddress, long size) {
        for (DataDirectoryKey key : DataDirectoryKey.values()) {
            if (key.toString().equals(fieldName)) {
                this.key = key;
            }
        }
        if (key == null)
            throw new IllegalArgumentException(
                    "no enum constant for given field name: " + fieldName);
        this.virtualAddress = virtualAddress;
        this.size = size;
    }

    /**
     * Creates a data dir entry based on key, virtualAddress and size
     * 
     * @param key
     * @param virtualAddress
     * @param size
     */
    public DataDirEntry(DataDirectoryKey key, int virtualAddress, int size) {
        checkArgument(key != null, "key must not be null");
        this.key = key;
        this.virtualAddress = virtualAddress;
        this.size = size;
    }

    /**
     * Calculates the file offset of the data directory based on the virtual
     * address and the entries in the section table.
     * 
     * @param table
     * @return file offset of data directory
     */
    public long getFileOffset(SectionTable table) { // TODO not in use?
        checkArgument(table != null, "table must not be null");
        Optional<SectionHeader> section = maybeGetSectionTableEntry(table);
        if (section.isPresent()) {
            long sectionRVA = section.get().get(VIRTUAL_ADDRESS);
            long sectionOffset = section.get().getAlignedPointerToRaw();
            return (virtualAddress - sectionRVA) + sectionOffset;
        }
        return virtualAddress; // TODO should be smaller than file length!
    }

    /**
     * Returns the section table entry of the section that the data directory
     * entry is pointing to.
     * 
     * @param table
     * @return the section table entry of the section that the data directory
     *         entry is pointing to
     * @throws {@link IllegalStateException} if data dir entry is not in a
     *         section
     */
    public SectionHeader getSectionTableEntry(SectionTable table) {
        Optional<SectionHeader> entry = maybeGetSectionTableEntry(table);
        if (entry.isPresent()) {
            return entry.get();
        }
        throw new IllegalStateException(
                "there is no section for this data directory entry");
    }

    /**
     * Returns the section table entry of the section that the data directory
     * entry is pointing to.
     * 
     * @param table
     * @return the section table entry of the section that the data directory
     *         entry is pointing to, or absent if data dir entry doesn't point
     *         to a section
     */
    // this is a duplicate to Sectionloader getSectionByRVA, but intentional for
    // better use of the API
    public Optional<SectionHeader> maybeGetSectionTableEntry(SectionTable table) {
        checkArgument(table != null, "table must not be null");
        List<SectionHeader> sections = table.getSectionHeaders();
        for (SectionHeader section : sections) {
            long vSize = section.getAlignedVirtualSize();
            //corkami: "a section can have a null VirtualSize: in this case, only the SizeOfRawData is taken into consideration. "
            //see: https://code.google.com/p/corkami/wiki/PE#section_table
            if(vSize == 0) {
                vSize = section.getAlignedSizeOfRaw();
            }
            long vAddress = section.get(VIRTUAL_ADDRESS);
            logger.debug("check if rva is within " + vAddress + " and "
                    + (vAddress + vSize));
            if (rvaIsWithin(vAddress, vSize)) {
                return Optional.of(section);
            }
        }
        logger.warn("there is no entry that matches data dir entry RVA "
                + virtualAddress);
        return Optional.absent();
    }

    private boolean rvaIsWithin(long address, long size) {
        long endpoint = address + size;
        return virtualAddress >= address && virtualAddress < endpoint;
    }

    @Override
    public String toString() {
        return "field name: " + key + NL + "virtual address: " + virtualAddress
                + NL + "size: " + size;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        DataDirEntry other = (DataDirEntry) obj;
        if (key != other.key)
            return false;
        if (size != other.size)
            return false;
        if (virtualAddress != other.virtualAddress)
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((key == null) ? 0 : key.hashCode());
        result = prime * result + (int) (size ^ (size >>> 32));
        result = prime * result
                + (int) (virtualAddress ^ (virtualAddress >>> 32));
        return result;
    }
}
