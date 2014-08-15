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
package com.github.katjahahn.parser.sections;

import static com.github.katjahahn.parser.sections.SectionHeaderKey.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.parser.Header;
import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.StandardField;

/**
 * Represents an entry of the {@link SectionTable}.
 * <p>
 * The instance is usually created by the {@link SectionTable}.
 * 
 * @author Katja Hahn
 * 
 */
public class SectionHeader extends Header<SectionHeaderKey> {

    private static final String SECTIONCHARACTERISTICS_SPEC = "sectioncharacteristics";
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
     * Returns the file offset of the NAME entry
     * 
     * @return
     */
    public long getNameOffset() {
        return nameOffset;
    }

    public int getNameSize() {
        return name.length();
    }

    /**
     * Returns the PointerToRawData rounded down to a multiple of 512.
     * 
     * @return aligned PointerToRawData
     */
    public long getAlignedPointerToRaw() {
        long result = get(POINTER_TO_RAW_DATA) & ~0x1ff;
        assert result % 512 == 0;
        return result;
    }

    /**
     * Returns the SizeOfRawData rounded up to a multiple of 4kb.
     * 
     * @return aligned SizeOfRawData
     */
    public long getAlignedSizeOfRaw() {
        long sizeOfRaw = get(SIZE_OF_RAW_DATA);
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
    public long getAlignedVirtualSize() {
        long virtSize = get(VIRTUAL_SIZE);
        if (virtSize == (virtSize & ~0xfff)) {
            return virtSize;
        }
        // TODO: corkami: "a section can have a null VirtualSize: in this case,
        // only the SizeOfRawData is taken into consideration" --> maybe create
        // another method to get the real virtual size
        long result = (virtSize + 0xfff) & ~0xfff;
        assert result % 4096 == 0;
        return result;
    }

    /**
     * Returns the VirtualAddress rounded up to a multiple of 4kb.
     * 
     * @return aligned VirtualAddress
     */
    public long getAlignedVirtualAddress() {
        long virtAddr = get(VIRTUAL_ADDRESS);
        if (virtAddr == (virtAddr & ~0xfff)) {
            return virtAddr;
        }
        long result = (virtAddr + 0xfff) & ~0xfff;
        assert result % 4096 == 0;
        return result;
    }

    /**
     * Returns the name of the section table entry
     * 
     * @return name
     */
    public String getName() {
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
        return getField(key).value;
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
        List<SectionCharacteristic> list = new ArrayList<>();
        List<String> keys = IOUtil.getCharacteristicKeys(
                get(SectionHeaderKey.CHARACTERISTICS),
                SECTIONCHARACTERISTICS_SPEC);
        for (String key : keys) {
            list.add(SectionCharacteristic.valueOf(key));
        }
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
            Long value = entry.getValue().value;
            SectionHeaderKey key = entry.getKey();
            String description = pad(entry.getValue().description + ": ", descrLength);
            
            if (key == SectionHeaderKey.CHARACTERISTICS) {
                b.append(description
                        + IOUtil.NL
                        + IOUtil.getCharacteristics(value,
                                SECTIONCHARACTERISTICS_SPEC) + IOUtil.NL);
            } else {
                b.append(description + value + " (0x"
                        + Long.toHexString(value) + ")" + IOUtil.NL);
            }
        }
        return b.toString();
    }
    
    private String pad(String string, int length) {
       for(int i = string.length(); i < length; i++) {
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
