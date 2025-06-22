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
package io.github.struppigel.parser.sections;

import io.github.struppigel.parser.Header;
import io.github.struppigel.parser.IOUtil;
import io.github.struppigel.parser.ScalaIOUtil;
import io.github.struppigel.parser.StandardField;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static io.github.struppigel.parser.sections.SectionHeaderKey.*;

/**
 * Represents an entry of the {@link SectionTable}.
 * <p>
 * The instance is usually created by the {@link SectionTable}.
 * 
 * @author Katja Hahn
 * 
 */
public class SectionHeader extends Header<SectionHeaderKey> {

    private final Map<SectionHeaderKey, StandardField> entries;
    private String name;
    private final int number;
    private final long offset;
    private final long nameOffset;

    /**
     * Creates a Section Table Entry instance.
     * 
     * @param entries
     * 
     * @param number
     *            the number of the entry, beginning by 1 with the first entry
     *            in the Section Headers
     * @param offset
     *            the file offset for the start of the section
     * @param name
     *            the section name
     * @param nameOffset
     *            fileoffset to the section name
     */
    public SectionHeader(Map<SectionHeaderKey, StandardField> entries,
            int number, long offset, String name, long nameOffset) {
        this.number = number;
        this.offset = offset;
        this.entries = entries;
        this.name = name;
        this.nameOffset = nameOffset;
    }

    /**
     * Returns the file offset to the section name
     * 
     * @return file offset to section name
     */
    public long getNameOffset() {
        return nameOffset;
    }

    /**
     * Returns the size of the name in bytes
     * 
     * @return size of the name in bytes
     */
    public int getNameSize() {
        return name.length();
    }

    /**
     * Returns the PointerToRawData rounded down to a multiple of 512.
     * 
     * @return aligned PointerToRawData
     */
    public long getAlignedPointerToRaw(Boolean isLowAlignmentMode) {
        if(isLowAlignmentMode){
            return get(POINTER_TO_RAW_DATA);
        }
        long result = get(POINTER_TO_RAW_DATA) & ~0x1ff;
        assert result % 512 == 0;
        return result;
    }

    /**
     * Returns the SizeOfRawData rounded up to a multiple of 4kb.
     * 
     * @return aligned SizeOfRawData
     */
    public long getAlignedSizeOfRaw(Boolean isLowAlignmentMode) {
        long sizeOfRaw = get(SIZE_OF_RAW_DATA);
        if(isLowAlignmentMode) return sizeOfRaw;
        if (sizeOfRaw == (sizeOfRaw & ~0xfff)) {
            return sizeOfRaw;
        }
        long result = (sizeOfRaw + 0xfff) & ~0xfff;
        assert result % 4096 == 0;
        return result;
    }

    /**
     * Returns the VirtualSize rounded up to a multiple of 4kb.
     * 
     * @return aligned VirtualSize
     */
    public long getAlignedVirtualSize(Boolean isLowAlignmentMode) {
        long virtSize = get(VIRTUAL_SIZE);
        if(isLowAlignmentMode) return virtSize;
        if (virtSize == (virtSize & ~0xfff)) {
            return virtSize;
        }
        long result = (virtSize + 0xfff) & ~0xfff;
        assert result % 4096 == 0;
        return result;
    }

    /**
     * Returns the VirtualAddress rounded up to a multiple of 4kb.
     * 
     * @return aligned VirtualAddress
     */
    public long getAlignedVirtualAddress(Boolean isLowAlignmentMode) {
        long virtAddr = get(VIRTUAL_ADDRESS);
        if(isLowAlignmentMode) return virtAddr;
        if (virtAddr == (virtAddr & ~0xfff)) {
            return virtAddr;
        }
        long result = (virtAddr + 0xfff) & ~0xfff;
        assert result % 4096 == 0;
        return result;
    }

    /**
     * Returns the filtered name of the section table entry
     * 
     * @return filtered name
     */
    public String getName() {
        return ScalaIOUtil.filteredString(name);
    }
    
    /**
     * Returns the unfiltered name of the section table entry
     * 
     * @return section name
     */
    public String getUnfilteredName() {
    	return name;
    }

    /**
     * Returns the number of the section table entry
     * 
     * @return number
     */
    public int getNumber() {
        assert number >= 0;
        return number;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long get(SectionHeaderKey key) {
        return getField(key).getValue();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StandardField getField(SectionHeaderKey key) {
        StandardField field = entries.get(key);
        assert field != null;
        return field;
    }

    /**
     * Returns a map that contains all entries and their
     * {@link SectionHeaderKey} as key
     * 
     * @return a map of all entries
     */
    public Map<SectionHeaderKey, StandardField> getEntryMap() {
        return new HashMap<>(entries);
    }

    /**
     * Returns a list of all characteristics of that section.
     * 
     * @return list of all characteristics
     */
    public List<SectionCharacteristic> getCharacteristics() {
        long value = get(SectionHeaderKey.CHARACTERISTICS);
        List<SectionCharacteristic> list = SectionCharacteristic.getAllFor(value);
        assert list != null;
        return list;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("Name: " + getName() + IOUtil.NL);
        final int descrLength = "pointer to line numbers:".length();

        for (Entry<SectionHeaderKey, StandardField> entry : entries.entrySet()) {
            Long value = entry.getValue().getValue();
            SectionHeaderKey key = entry.getKey();
            String description = pad(entry.getValue().getDescription() + ": ",
                    descrLength);

            if (key == SectionHeaderKey.CHARACTERISTICS) {
                b.append(description
                        + IOUtil.NL
                        + getCharacteristicsInfo(value) + IOUtil.NL);
            } else {
                b.append(description + value + " (0x" + Long.toHexString(value)
                        + ")" + IOUtil.NL);
            }
        }
        return b.toString();
    }
    
    private static String getCharacteristicsInfo(long value) {
        StringBuilder b = new StringBuilder();
        List<SectionCharacteristic> characs = SectionCharacteristic.getAllFor(value);
        for (SectionCharacteristic ch : characs) {
            b.append("\t* " + ch.getDescription() + IOUtil.NL);
        }
        if (characs.isEmpty()) {
            b.append("\t**no characteristics**" + IOUtil.NL);
        }
        return b.toString();
    }

    private String pad(String string, int length) {
        for (int i = string.length(); i < length; i++) {
            string += " ";
        }
        return string;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getOffset() {
        return offset;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getInfo() {
        return this.toString();
    }

}
