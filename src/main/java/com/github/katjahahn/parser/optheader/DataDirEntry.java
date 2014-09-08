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

import static com.github.katjahahn.parser.IOUtil.*;
import static com.google.common.base.Preconditions.*;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.VirtualLocation;
import com.github.katjahahn.parser.sections.SectionHeader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.google.common.base.Optional;

/**
 * Represents an entry of the data directory table. It is used like a struct.
 * 
 * @author Katja Hahn
 * 
 */
public class DataDirEntry {

    private static final Logger logger = LogManager
            .getLogger(DataDirEntry.class.getName());

    /**
     * The key of the entry
     */
    private DataDirectoryKey key;

    /**
     * The virtual address of the entry
     */
    private final long virtualAddress;

    /**
     * The size of the entry
     */
    private final long directorySize;

    /**
     * Physical offset of the entry in the data directory table
     */
    private final long tableEntryOffset;

    /**
     * Size of the entry in the table in bytes
     */
    private final long tableEntrySize = 8;

    /**
     * Creates a data dir entry with the fieldName, which is used to retrieve
     * the corresponding {@link DataDirectoryKey}, and the virtualAddress and
     * the size
     * 
     * @param fieldName
     *            the name of the data directory that corresponds to a
     *            {@link DataDirectoryKey}
     * @param virtualAddress
     *            the virtual address of the entry
     * @param directorySize
     *            the size of the entry
     * @param tableEntryOffset
     *            Physical offset of the entry in the data directory table
     * @throws IllegalArgumentException
     *             if fieldName doesn't match a valid key
     */
    public DataDirEntry(String fieldName, long virtualAddress,
            long directorySize, long tableEntryOffset) {
        for (DataDirectoryKey key : DataDirectoryKey.values()) {
            if (key.toString().equals(fieldName)) {
                this.key = key;
            }
        }
        checkNotNull(key, "no enum constant for given field name: " + fieldName);
        this.virtualAddress = virtualAddress;
        this.directorySize = directorySize;
        this.tableEntryOffset = tableEntryOffset;
    }

    /**
     * Creates a data dir entry based on key, virtualAddress and size
     * 
     * @param key
     *            the key of the entry
     * @param virtualAddress
     *            the virtual address of the entry
     * @param directorySize
     *            the size of the entry
     * @param tableEntryOffset
     *            Physical offset of the entry in the data directory table
     */
    public DataDirEntry(DataDirectoryKey key, int virtualAddress,
            int directorySize, long tableEntryOffset) {
        checkArgument(key != null, "key must not be null");
        this.key = key;
        this.virtualAddress = virtualAddress;
        this.directorySize = directorySize;
        this.tableEntryOffset = tableEntryOffset;
    }

    /**
     * Calculates the file offset of the data directory based on the virtual
     * address and the entries in the section table.
     * 
     * @param table
     * @return file offset of data directory
     */
    public long getFileOffset(SectionTable table) { // TODO not in use?
        checkArgument(table != null, "section table must not be null");
        Optional<SectionHeader> section = maybeGetSectionTableEntry(table);
        if (section.isPresent()) {
            long sectionRVA = section.get().getAlignedVirtualAddress();
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
     * @throws IllegalStateException
     *             if data dir entry is not in a section
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
        // loop through all section headers to check if entry is within section
        for (SectionHeader header : sections) {
            long vSize = header.getAlignedVirtualSize();
            // corkami: "a section can have a null VirtualSize: in this case,
            // only the SizeOfRawData is taken into consideration. "
            // see: https://code.google.com/p/corkami/wiki/PE#section_table
            if (vSize == 0) {
                vSize = header.getAlignedSizeOfRaw();
            }
            long vAddress = header.getAlignedVirtualAddress();
            logger.debug("check if rva is within " + vAddress + " and "
                    + (vAddress + vSize));
            // return header if data entry va points into it
            if (rvaIsWithin(new VirtualLocation(vAddress, vSize))) {
                return Optional.of(header);
            }
        }
        logger.warn("there is no entry that matches data dir entry RVA "
                + virtualAddress);
        return Optional.absent();
    }

    /**
     * Returns whether the data entry va is within the given location. (location
     * start inclusive, location end exclusive)
     * 
     * @param loc
     *            the virtual location to check
     * @return true iff data entry va is equal to or larger than location start
     *         and smaller than location end
     */
    private boolean rvaIsWithin(VirtualLocation loc) {
        long endpoint = loc.from() + loc.size();
        return virtualAddress >= loc.from() && virtualAddress < endpoint;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "field name: " + key + NL + "virtual address: " + virtualAddress
                + NL + "size: " + directorySize;
    }

    /**
     * {@inheritDoc}
     */
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
        if (directorySize != other.directorySize)
            return false;
        if (virtualAddress != other.virtualAddress)
            return false;
        return true;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((key == null) ? 0 : key.hashCode());
        result = prime * result
                + (int) (directorySize ^ (directorySize >>> 32));
        result = prime * result
                + (int) (virtualAddress ^ (virtualAddress >>> 32));
        return result;
    }

    /**
     * Returns the data directory's key.
     * 
     * @return the key of the entry
     */
    public DataDirectoryKey getKey() {
        return key;
    }

    /**
     * Returns the virtual address of the entry.
     * 
     * @return the virtual address to the data directory (relative to the image
     *         base)
     */
    public long getVirtualAddress() {
        return virtualAddress;
    }

    /**
     * Returns the size of the entry in bytes as it is given in the directory
     * table.
     * 
     * @return the size of the entry in bytes
     */
    public long getDirectorySize() {
        return directorySize;
    }

    /**
     * Returns the physical offset of the entry in the data directory table.
     * 
     * @return the physical offset of the entry in the data directory table
     */
    public long getTableEntryOffset() {
        return tableEntryOffset;
    }

    /**
     * Size of the entry in the table in bytes.
     * 
     * @return size of the entry in the table in bytes
     */
    public long getTableEntrySize() {
        return tableEntrySize;
    }
}
