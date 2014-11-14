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
package com.github.katjahahn.parser.coffheader;

import static com.github.katjahahn.parser.IOUtil.*;
import static com.github.katjahahn.parser.coffheader.COFFHeaderKey.*;
import static com.google.common.base.Preconditions.*;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.Header;
import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.IOUtil.SpecificationFormat;
import com.github.katjahahn.parser.StandardField;

/**
 * Represents the COFF File Header.
 * 
 * @author Katja Hahn
 * 
 */
public class COFFFileHeader extends Header<COFFHeaderKey> {

    /** the size of the header is {@value} */
    public static final int HEADER_SIZE = 20;
    /** the specification name */
    private static final String COFF_SPEC_FILE = "coffheaderspec";
    /** the bytes that make up the header data */
    private final byte[] headerbytes;
    /** the header fields */
    private Map<COFFHeaderKey, StandardField> data;
    /** the file offset of the header */
    private final long offset;
    /** the logger for the COFF File Header */
    private static final Logger logger = LogManager
            .getLogger(COFFFileHeader.class.getName());

    /**
     * Creates a COFFFileHeader instance based on the byte array.
     * 
     * @param headerbytes
     *            an array that holds the headerbytes. The length of the array
     *            must be {@link #HEADER_SIZE}.
     * @param offset
     *            the file offset of the header
     * @throws IllegalArgumentException
     *             if length of the array != {@link #HEADER_SIZE}
     */
    private COFFFileHeader(byte[] headerbytes, long offset) {
        checkNotNull(headerbytes);
        checkArgument(headerbytes.length == HEADER_SIZE);
        this.headerbytes = headerbytes.clone();
        this.offset = offset;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getOffset() {
        return offset;
    }

    /**
     * Reads the header's fields.
     */
    private void read() {
        // define the specification format
        final int key = 0;
        final int description = 1;
        final int offset = 2;
        final int length = 3;
        SpecificationFormat format = new SpecificationFormat(key, description,
                offset, length);
        // read the header data
        try {
            data = IOUtil.readHeaderEntries(COFFHeaderKey.class, format,
                    COFF_SPEC_FILE, headerbytes, getOffset());
        } catch (IOException e) {
            logger.error("unable to read coff specification: " + e.getMessage());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getInfo() {
        // make title
        StringBuilder b = new StringBuilder("----------------" + NL
                + "COFF File Header" + NL + "----------------" + NL);
        // loop through standard fields
        for (StandardField field : data.values()) {
            long value = field.getValue();
            COFFHeaderKey key = (COFFHeaderKey) field.getKey();
            String description = field.getDescription();
            // handle special fields that have additional representations

            if (key == COFFHeaderKey.CHARACTERISTICS) {
                b.append(NL + description + ": " + NL);
                b.append(getCharacteristicsInfo(value));
            } else if (key == COFFHeaderKey.TIME_DATE) {
                b.append(description + ": ");
                b.append(convertToDate(value));
            } else if (key == COFFHeaderKey.MACHINE) {
                b.append(description + ": ");
                b.append(getMachineTypeString((int) value));
            } else {
                b.append(field.toString());
            }
            b.append(NL);
        }
        return b.toString();
    }

    private static String getCharacteristicsInfo(long value) {
        StringBuilder b = new StringBuilder();
        List<FileCharacteristic> characs = FileCharacteristic.getAllFor(value);
        for (FileCharacteristic ch : characs) {
            b.append("\t* " + ch.getDescription() + NL);
        }
        if (characs.isEmpty()) {
            b.append("\t**no characteristics**" + NL);
        }
        return b.toString();
    }

    /**
     * Returns the machine type description string that belongs to the value.
     * 
     * @param value
     *            the value of the machine type
     * @return the machine type description
     */
    private String getMachineTypeString(int value) {
        return MachineType.getForValue(value).getDescription();
    }

    /**
     * Converts seconds to a date object.
     * 
     * @param seconds
     *            time in seconds
     * @return date
     */
    private Date convertToDate(long seconds) {
        // convert seconds to milli seconds
        long millis = seconds * 1000;
        return new Date(millis);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long get(COFFHeaderKey key) {
        return getField(key).getValue();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StandardField getField(COFFHeaderKey key) {
        return data.get(key);
    }

    /**
     * Returns a list with all characteristics of the file.
     * <p>
     * Ensures that the result is never null.
     * 
     * @return list of file characteristics
     */
    public List<FileCharacteristic> getCharacteristics() {
        long value = get(CHARACTERISTICS);
        List<FileCharacteristic> characteristics = FileCharacteristic
                .getAllFor(value);
        // ensurance
        assert characteristics != null;
        return characteristics;
    }

    /**
     * Returns whether the characteristic is set.
     * 
     * @param characteristic
     *            a file characteristic
     * @return true if characteristic is set, false otherwise
     */
    public boolean hasCharacteristic(FileCharacteristic characteristic) {
        return (get(CHARACTERISTICS) & characteristic.getValue()) != 0;
    }

    /**
     * Returns the enum that denotes the machine type.
     * 
     * @return MachineType
     */
    public MachineType getMachineType() {
        long value = get(MACHINE);
        try {
            return MachineType.getForValue(value);
        } catch (IllegalArgumentException e) {
            logger.error("Unable to resolve machine type for value: " + value);
            return MachineType.UNKNOWN;
        }
    }

    /**
     * Creates a date object from the TIME_DATE read in the COFF File Header.
     * 
     * @return the date
     */
    public Date getTimeDate() {
        return convertToDate(get(TIME_DATE));
    }

    /**
     * Returns the SizeOfOptionalHeader value.
     * 
     * @return size of optional header
     */
    public int getSizeOfOptionalHeader() {
        assert get(SIZE_OF_OPT_HEADER) == (int) get(SIZE_OF_OPT_HEADER);
        // 2-byte value can be casted to int
        return (int) get(SIZE_OF_OPT_HEADER);
    }

    /**
     * Returns the number of sections.
     * 
     * @return number of sections
     */
    public int getNumberOfSections() {
        assert get(SECTION_NR) == (int) get(SECTION_NR);
        // 2-byte value can be casted to int
        return (int) get(SECTION_NR);
    }

    /**
     * Creates an instance of the COFF File Header based on headerbytes and
     * offset.
     * 
     * @param headerbytes
     *            the bytes that make up the COFF File Header
     * @param offset
     *            the file offset to the beginning of the header
     * @return COFFFileHeader instance
     */
    public static COFFFileHeader newInstance(byte[] headerbytes, long offset) {
        COFFFileHeader header = new COFFFileHeader(headerbytes, offset);
        header.read();
        return header;
    }
}
