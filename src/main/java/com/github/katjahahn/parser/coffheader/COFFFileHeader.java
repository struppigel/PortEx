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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.Header;
import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.IOUtil.SpecificationFormat;
import com.github.katjahahn.parser.StandardField;
import com.google.common.base.Preconditions;

/**
 * Represents the COFF File Header.
 * 
 * @author Katja Hahn
 * 
 */
public class COFFFileHeader extends Header<COFFHeaderKey> {

    /**
     * The size of the header is {@value} .
     */
    public static final int HEADER_SIZE = 20;
    private static final String COFF_SPEC_FILE = "coffheaderspec";
    private final byte[] headerbytes;
    private Map<COFFHeaderKey, StandardField> data;
    private final long offset;

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

    private void read() throws IOException {
        // define the specification format
        final int key = 0;
        final int description = 1;
        final int offset = 2;
        final int length = 3;
        SpecificationFormat format = new SpecificationFormat(key, description,
                offset, length);
        // read the header data
        data = IOUtil.readHeaderEntries(COFFHeaderKey.class, format,
                COFF_SPEC_FILE, headerbytes, getOffset());

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
            long value = field.value;
            COFFHeaderKey key = (COFFHeaderKey) field.key;
            String description = field.description;
            // handle special fields that have additional representations
            switch (key) {
            case CHARACTERISTICS:
                b.append(NL + description + ": " + NL);
                b.append(IOUtil.getCharacteristics(value, "characteristics"));
                break;
            case TIME_DATE:
                b.append(description + ": ");
                b.append(convertToDate(value));
                break;
            case MACHINE:
                b.append(description + ": ");
                b.append(getMachineTypeString((int) value));
                break;
            default:
                b.append(field.toString());
            }
            b.append(NL);
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
        final int typeIndex = 1;
        try {
            // read the specification
            Map<String, String[]> map = IOUtil.readMap("machinetype");
            // convert value to hex string
            String key = Integer.toHexString(value);
            // retrieve type string
            String[] ret = map.get(key);
            if (ret != null && ret.length > typeIndex) {
                return ret[typeIndex];
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        throw new IllegalArgumentException("couldn't match type to value "
                + value);
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
        return getField(key).value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StandardField getField(COFFHeaderKey key) {
        return data.get(key);
    }

    /**
     * Returns a description of the machine type.
     * 
     * @param machine
     *            type
     * @return description
     */
    public static String getDescription(MachineType machine) {
        // set indices
        int description = 1;
        int keyString = 0;
        try {
            // read the machinetype specification
            Map<String, String[]> map = IOUtil.readMap("machinetype");
            for (String[] entry : map.values()) {
                // check for key
                if (entry[keyString].equals(machine.getKey())) {
                    // correct machine type found, retrieve description
                    String result = entry[description];
                    assert result != null && result.trim().length() > 0;
                    return result;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        // this should never happen
        throw new IllegalArgumentException("no description found for machine "
                + machine);
    }

    /**
     * Returns a description of the machine type read.
     * 
     * @return machine type description
     */
    public String getMachineDescription() {
        return getDescription(getMachineType());
    }

    /**
     * Returns a list with all characteristics of the file.
     * <p>
     * Ensures that the result is never null.
     * 
     * @return list of file characteristics
     */
    public List<FileCharacteristic> getCharacteristics() {
        // get a list of all key strings whose flags are set
        List<String> keys = IOUtil.getCharacteristicKeys(get(CHARACTERISTICS),
                "characteristics");
        // init empty list
        List<FileCharacteristic> characteristics = new ArrayList<>();
        // fetch enum type for every key string and put to list
        for (String key : keys) {
            characteristics.add(FileCharacteristic.valueOf(key));
        }
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
        return getCharacteristics().contains(characteristic);
    }

    /**
     * Returns a list of the characteristics.
     * 
     * @return list of characteristic descriptions
     */
    public List<String> getCharacteristicsDescriptions() {
        // just forward task to IOUtil
        return IOUtil.getCharacteristicsDescriptions(get(CHARACTERISTICS),
                "characteristics");
    }

    /**
     * Returns the enum that denotes the machine type.
     * 
     * @return MachineType
     */
    public MachineType getMachineType() {
        assert get(MACHINE) == (int) get(MACHINE);
        // 2 byte value can be casted to int
        final int value = (int) get(MACHINE);
        final int enumKeyIndex = 0;
        try {
            // read the specification
            Map<String, String[]> map = IOUtil.readMap("machinetype");
            // convert value to hex string representation, which is the key for
            // the specification map
            String hexKey = Integer.toHexString(value);
            // get the other values for the hex key
            String[] ret = map.get(hexKey);
            // check if found, if not found something went really wrong
            if (ret != null) {
                // cut the beginning of the enum string
                String type = ret[enumKeyIndex].substring("IMAGE_FILE_MACHINE_"
                        .length());
                // retrieve machine type
                MachineType result = MachineType.valueOf(type);
                // There must be a matching machine type, otherwise you coded it
                // wrong
                Preconditions.checkState(result != null);
                return result;
            }
        } catch (IOException e) {
            // could not read the specification
            logger.fatal(e);
            e.printStackTrace();
        }
        throw new IllegalArgumentException("couldn't match type to value "
                + value);
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
     * @throws IOException
     */
    public static COFFFileHeader newInstance(byte[] headerbytes, long offset)
            throws IOException {
        COFFFileHeader header = new COFFFileHeader(headerbytes, offset);
        header.read();
        return header;
    }
}
