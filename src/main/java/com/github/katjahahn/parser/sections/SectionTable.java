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

import static com.github.katjahahn.parser.ByteArrayUtil.*;
import static com.github.katjahahn.parser.IOUtil.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.IOUtil.SpecificationFormat;
import com.github.katjahahn.parser.PEModule;
import com.github.katjahahn.parser.StandardField;
import com.google.common.base.Optional;

/**
 * Represents the section table of a PE.
 * <p>
 * Is constructed by the PELoader.
 * 
 * @author Katja Hahn
 * 
 */
public class SectionTable implements PEModule {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(SectionTable.class.getName());

    private final static String SECTION_TABLE_SPEC = "sectiontablespec";

    /**
     * Size of one entry is {@value}
     */
    public final static int ENTRY_SIZE = 40;

    private List<SectionHeader> headers;
    private final byte[] sectionTableBytes;
    private int numberOfEntries;
    private Map<String, String[]> specification;

    private final long offset;

    /**
     * creates the SectionTable with the bytes of the table and the number of
     * entries TODO create newInstance method
     * 
     * @param sectionTableBytes
     *            the bytes that make up the section table
     * @param numberOfEntries
     *            the number of section headers in the table
     * @param offset
     *            the file offset to the section table
     */
    public SectionTable(byte[] sectionTableBytes, int numberOfEntries,
            long offset) {
        this.sectionTableBytes = sectionTableBytes.clone();
        this.numberOfEntries = numberOfEntries;
        this.offset = offset;
        try {
            specification = IOUtil.readMap(SECTION_TABLE_SPEC);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void read() throws IOException {
        headers = new LinkedList<>();

        for (int i = 0; i < numberOfEntries; i++) {
            int sectionNumber = i + 1;
            int sectionOffset = i * ENTRY_SIZE;
            int headerbytesEnd = sectionOffset + ENTRY_SIZE;
            // next two steps done because of d_resource.dll
            // TODO read table from memory mapped pe, this would help here as well
            if (sectionOffset >= sectionTableBytes.length) {
                //TODO correct sectionNumer
                this.numberOfEntries = i;
                break;
            }
            if (headerbytesEnd > sectionTableBytes.length) {
                headerbytesEnd = sectionTableBytes.length;
            }
            byte[] headerbytes = Arrays.copyOfRange(sectionTableBytes,
                    sectionOffset, headerbytesEnd);

            SpecificationFormat format = new SpecificationFormat(0, 1, 2, 3);
            Map<SectionHeaderKey, StandardField> entries = IOUtil
                    .readHeaderEntries(SectionHeaderKey.class, format,
                            SECTION_TABLE_SPEC, headerbytes, getOffset());

            // TODO is this calculation correct? make unit tests
            long nameOffset = getOffset() + getRelativeNameOffset(headerbytes);
            SectionHeader sectionEntry = new SectionHeader(entries,
                    sectionNumber, sectionOffset, getUTF8String(headerbytes),
                    nameOffset);
            headers.add(sectionEntry);
        }
    }

    /**
     * or too small for the given file Returns all entries of the section table
     * as a list. They are in the same order as they are within the Section
     * Table.
     * 
     * @return ordered section table entries
     */
    public List<SectionHeader> getSectionHeaders() {
        return new LinkedList<>(headers);
    }

    /**
     * Returns the number of sections
     * 
     * @return number of sections and section headers
     */
    public int getNumberOfSections() {
        return numberOfEntries;
    }

    /**
     * Returns the section entry that has the given number or null if there is
     * no section with that number.
     * 
     * @param number
     *            of the section
     * @return the section table entry that has the given number
     * @throw {@link IllegalArgumentException} if no section header for number
     *        found
     */
    public SectionHeader getSectionHeader(int number) {
        for (SectionHeader header : headers) {
            if (header.getNumber() == number) {
                return header;
            }
        }
        throw new IllegalArgumentException(
                "invalid section number, no section header found");
    }

    /**
     * Returns the section entry that has the given name. If there are several
     * sections with the same name, the first one will be returned.
     * 
     * TODO there might be several sections with the same name. Provide a better
     * way to fetch them.
     * 
     * @param sectionName
     *            name of the section
     * @return the section table entry that has the given sectionName
     * @throw {@link IllegalArgumentException} if no section header for name
     *        found
     */
    public SectionHeader getSectionHeader(String sectionName) {
        for (SectionHeader entry : headers) {
            if (entry.getName().equals(sectionName)) {
                return entry;
            }
        }
        throw new IllegalArgumentException(
                "invalid section name, no section header found");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getInfo() {
        StringBuilder b = new StringBuilder();
        b.append("-----------------" + NL + "Section Table" + NL
                + "-----------------" + NL + NL);
        for (int i = 0; i < numberOfEntries; i++) {
            b.append("entry number " + (i + 1) + ": " + NL + "..............."
                    + NL + NL);
            byte[] section = Arrays.copyOfRange(sectionTableBytes, i
                    * ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
            b.append(getNextEntryInfo(section) + NL);
        }

        return b.toString();
    }

    private String getNextEntryInfo(byte[] section) {
        assert section != null;
        StringBuilder b = new StringBuilder();
        for (Entry<String, String[]> entry : specification.entrySet()) {

            String[] specs = entry.getValue();
            long value = getBytesLongValue(section, Integer.parseInt(specs[1]),
                    Integer.parseInt(specs[2]));
            String key = entry.getKey();
            if (key.equals("CHARACTERISTICS")) {
                b.append(specs[0]
                        + ": "
                        + NL
                        + IOUtil.getCharacteristics(value,
                                "sectioncharacteristics") + NL);
            } else 
                if (key.equals("NAME")) {
                b.append(specs[0] + ": " + getUTF8String(section) + NL);

            } else {
                b.append(specs[0] + ": " + value + " (0x"
                        + Long.toHexString(value) + ")" + NL);
            }
        }
        return b.toString();
    }

    private String getUTF8String(byte[] section) {
        String[] values = specification.get("NAME");
        int from = getRelativeNameOffset(section);
        int to = from + Integer.parseInt(values[2]);
        byte[] bytes = Arrays.copyOfRange(section, from, to);
        return new String(bytes, StandardCharsets.UTF_8).trim();
    }

    private int getRelativeNameOffset(byte[] section) {
        String[] values = specification.get("NAME");
        int from = Integer.parseInt(values[1]);
        return from;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getOffset() {
        return offset;
    }

    /**
     * Returns an optional of the first section that has the given name.
     * 
     * @param name
     * @return first section with the given name, absent if no section with that
     *         name found
     */
    public Optional<SectionHeader> getSectionHeaderByName(String name) {
        for (SectionHeader header : headers) {
            if (header.getName().equals(name)) {
                return Optional.of(header);
            }
        }
        return Optional.absent();
    }

    /**
     * Returns the size of the section table.
     * 
     * @return size of the section table
     */
    public int getSize() {
        int result = ENTRY_SIZE * numberOfEntries;
        assert result >= 0 && result % ENTRY_SIZE == 0;
        return result;
    }
}
