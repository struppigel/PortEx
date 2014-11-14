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

import static com.github.katjahahn.parser.ByteArrayUtil.*;
import static com.github.katjahahn.parser.IOUtil.*;
import static com.github.katjahahn.parser.optheader.StandardFieldEntryKey.*;
import static com.github.katjahahn.parser.optheader.WindowsEntryKey.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.Header;
import com.github.katjahahn.parser.HeaderKey;
import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.IOUtil.SpecificationFormat;
import com.github.katjahahn.parser.StandardField;
import com.google.common.base.Optional;

/**
 * Represents the optional header of the PE file.
 * 
 * @author Katja Hahn
 * 
 */
public class OptionalHeader extends Header<OptionalHeaderKey> {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(OptionalHeader.class.getName());

    /* spec locations */
    /** standard fields specification name */
    private static final String STANDARD_SPEC = "optionalheaderstandardspec";
    /** windows fields specification name */
    private static final String WINDOWS_SPEC = "optionalheaderwinspec";
    /** data directories specification name */
    private static final String DATA_DIR_SPEC = "datadirectoriesspec";

    /**
     * Maximum size of the optional header to read all values safely is {@value}
     */
    public static final int MAX_SIZE = 240;

    /* extracted file data */
    /** the data directory entries */
    private Map<DataDirectoryKey, DataDirEntry> dataDirectory;
    /** the standard fields */
    private Map<StandardFieldEntryKey, StandardField> standardFields;
    /** the windows specific fields */
    private Map<WindowsEntryKey, StandardField> windowsFields;

    /** the bytes that make up the optional header */
    private final byte[] headerbytes;
    /** the magic number that defines a PE32 or PE32+ */
    private MagicNumber magicNumber;
    /**
     * the value of the NumberOfRVAAndSizes field, the number of directory
     * entries
     */
    private long directoryNr;
    /** the file offset of the optional header */
    private final long offset;

    /**
     * The magic number of the PE file, indicating whether it is a PE32, PE32+
     * or ROM file
     * 
     * @author Katja Hahn
     * 
     */
    public static enum MagicNumber {
        /**
         * A PE that supports only 32-bit addresses
         */
        PE32(0x10B, "PE32", "PE32, normal executable file"),
        /**
         * A PE that supports up to 64-bit addresses
         */
        PE32_PLUS(0x20B, "PE32+", "PE32+ executable"),
        /**
         * A ROM file. Note: PortEx doesn't support object files by now.
         */
        ROM(0x107, "ROM", "ROM image"),
        /**
         * Magic number could not be read for any reason. This is possible for a
         * minimal DLL, e.g., d_tiny.dll
         */
        UNKNOWN(0x0, "Unknown", "Unknown, this PE file is really weird");

        private int value;
        private String name;
        private String description;

        private MagicNumber(int value, String name, String description) {
            this.value = value;
            this.name = name;
            this.description = description;
        }

        /**
         * The magic number itself
         * 
         * @return the magic number that denotes the type of PE
         */
        public int getValue() {
            return value;
        }

        /**
         * Returns the name of the magic number
         * 
         * @return name
         */
        public String getName() {
            return name;
        }

        /**
         * Returns a description of the magic number
         * 
         * @return description string
         */
        public String getDescription() {
            return description;
        }
    }

    /**
     * Creates an optional header instance with the given headerbytes and the
     * file offset of the beginning of the header
     * 
     * @param headerbytes
     * @param offset
     */
    private OptionalHeader(byte[] headerbytes, long offset) {
        this.headerbytes = headerbytes.clone();
        this.offset = offset;
    }

    /**
     * Creates and returns a new instance of the optional header.
     * 
     * @param headerbytes
     *            the bytes that make up the optional header
     * @param offset
     *            the file offset to the beginning of the optional header
     * @return instance of the optional header
     * @throws IOException
     *             if headerbytes can not be read
     */
    public static OptionalHeader newInstance(byte[] headerbytes, long offset)
            throws IOException {
        OptionalHeader header = new OptionalHeader(headerbytes, offset);
        header.read();
        return header;
    }

    /**
     * Reads the header fields.
     * 
     * @throws IOException
     */
    private void read() throws IOException {
        // read specifications for standard fields and data directories
        Map<String, String[]> standardSpec = IOUtil.readMap(STANDARD_SPEC);

        // read magic number
        this.magicNumber = readMagicNumber(standardSpec);

        /* load fields */
        loadStandardFields();
        loadWindowsSpecificFields();
        loadDataDirectory();
    }

    /**
     * Returns a map of the data directory entries with the
     * {@link DataDirectoryKey} as key
     * 
     * @return the data directory entries
     */
    public Map<DataDirectoryKey, DataDirEntry> getDataDirectory() {
        return new HashMap<>(dataDirectory);
    }

    /**
     * Returns a map of the windows specific fields with the
     * {@link WindowsEntryKey} as key type
     * 
     * @return the windows specific fields
     */
    public Map<WindowsEntryKey, StandardField> getWindowsSpecificFields() {
        return new HashMap<>(windowsFields);
    }

    /**
     * Returns a map of the standard fields.
     * 
     * @return the standard fields
     */
    public Map<StandardFieldEntryKey, StandardField> getStandardFields() {
        return new HashMap<>(standardFields);
    }

    /**
     * Returns the optional data directory entry for the given key or absent if
     * entry doesn't exist.
     * 
     * @param key
     * @return the data directory entry for the given key or absent if entry
     *         doesn't exist.
     */
    public Optional<DataDirEntry> maybeGetDataDirEntry(DataDirectoryKey key) {
        return Optional.fromNullable(dataDirectory.get(key));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long get(OptionalHeaderKey key) {
        return getField(key).getValue();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StandardField getField(OptionalHeaderKey key) {
        if (key instanceof StandardFieldEntryKey) {
            return standardFields.get(key);

        }
        return windowsFields.get(key);
    }

    /**
     * Returns the standard field entry for the given key.
     * 
     * @param key
     * @return the standard field entry for the given key
     */
    public StandardField getStandardFieldEntry(StandardFieldEntryKey key) {
        return standardFields.get(key);
    }

    /**
     * Returns the windows field entry for the given key.
     * 
     * @param key
     * @return the windows field entry for the given key
     */
    public StandardField getWindowsFieldEntry(WindowsEntryKey key) {
        return windowsFields.get(key);
    }

    private void loadStandardFields() throws IOException {
        SpecificationFormat format = new SpecificationFormat(0, 1, 2, 3);
        standardFields = IOUtil.readHeaderEntries(StandardFieldEntryKey.class,
                format, STANDARD_SPEC, headerbytes, getOffset());
        if (getMagicNumber() == MagicNumber.PE32_PLUS) {
            standardFields.remove(BASE_OF_DATA);
        }
    }

    private void loadDataDirectory() throws IOException {
        List<String[]> datadirSpec = IOUtil.readArray(DATA_DIR_SPEC);
        dataDirectory = new HashMap<>();
        final int description = 0;
        int offsetLoc;
        int length = 4; // the actual length

        if (magicNumber == MagicNumber.PE32) {
            offsetLoc = 1;
        } else if (magicNumber == MagicNumber.PE32_PLUS) {
            offsetLoc = 2;
        } else {
            return; // no fields
        }

        int counter = 0;
        for (String[] specs : datadirSpec) {
            if (counter >= directoryNr) {
                break;
            }
            int offset = Integer.parseInt(specs[offsetLoc]);
            if (headerbytes.length >= offset) {
                long address = getBytesLongValueSafely(headerbytes, offset,
                        length);
                long size = getBytesLongValueSafely(headerbytes, offset
                        + length, length);
                // TODO test if this is correct
                long tableEntryOffset = offset + getOffset();
                if (address != 0) {
                    DataDirEntry entry = new DataDirEntry(specs[description],
                            address, size, tableEntryOffset);
                    dataDirectory.put(entry.getKey(), entry);
                }
            }
            counter++;
        }
    }

    private void loadWindowsSpecificFields() throws IOException {
        int offsetLoc;
        int lengthLoc;
        final int description = 1;

        if (magicNumber == MagicNumber.PE32) {
            offsetLoc = 2;
            lengthLoc = 4;
        } else if (magicNumber == MagicNumber.PE32_PLUS) {
            offsetLoc = 3;
            lengthLoc = 5;
        } else {
            windowsFields = IOUtil.initFullEnumMap(WindowsEntryKey.class);
            return; // no fields
        }
        SpecificationFormat format = new SpecificationFormat(0, description,
                offsetLoc, lengthLoc);
        windowsFields = IOUtil.readHeaderEntries(WindowsEntryKey.class, format,
                WINDOWS_SPEC, headerbytes, getOffset());
        directoryNr = windowsFields
                .get(WindowsEntryKey.NUMBER_OF_RVA_AND_SIZES).getValue();
        if (directoryNr > 16) {
            directoryNr = 16;
        }
    }

    @Override
    public String getInfo() {
        return "---------------" + NL + "Optional Header" + NL
                + "---------------" + NL + NL + "Standard fields" + NL
                + "..............." + NL + NL + getStandardFieldsInfo() + NL
                + "Windows specific fields" + NL + "......................."
                + NL + NL + getWindowsSpecificInfo() + NL + "Data directories"
                + NL + "................" + NL + NL + "virtual_address/size"
                + NL + NL + getDataDirInfo();
    }

    /**
     * Returns a description of all data directories.
     * 
     * @return description of all data directories.
     */
    public String getDataDirInfo() {
        StringBuilder b = new StringBuilder();
        for (DataDirEntry entry : dataDirectory.values()) {
            b.append(entry.getKey() + ": " + entry.getVirtualAddress() + "(0x"
                    + Long.toHexString(entry.getVirtualAddress()) + ")/"
                    + entry.getDirectorySize() + "(0x"
                    + Long.toHexString(entry.getDirectorySize()) + ")" + NL);
        }
        return b.toString();
    }

    /**
     * Returns a string with description of the windows specific header fields.
     * Magic number must be set.
     * 
     * @return string with windows specific fields
     */
    public String getWindowsSpecificInfo() {
        StringBuilder b = new StringBuilder();
        for (StandardField entry : windowsFields.values()) {
            long value = entry.getValue();
            HeaderKey key = entry.getKey();
            String description = entry.getDescription();
            if (key.equals(IMAGE_BASE)) {
                b.append(description + ": " + value + " (0x"
                        + Long.toHexString(value) + "), "
                        + getImageBaseDescription(value) + NL);
            } else if (key.equals(SUBSYSTEM)) {
                // subsystem has only 2 bytes
                b.append(description + ": "
                        + getSubsystem().getDescription() + NL);
            } else if (key.equals(DLL_CHARACTERISTICS)) {
                b.append(NL + description + ": " + NL);
                b.append(getCharacteristicsInfo(value) + NL);
            }

            else {
                b.append(description + ": " + value + " (0x"
                        + Long.toHexString(value) + ")" + NL);
                if (key.equals(NUMBER_OF_RVA_AND_SIZES)) {
                    directoryNr = value;
                }
            }
        }
        return b.toString();
    }

    private static String getCharacteristicsInfo(long value) {
        StringBuilder b = new StringBuilder();
        List<DllCharacteristic> characs = DllCharacteristic.getAllFor(value);
        for (DllCharacteristic ch : characs) {
            b.append("\t* " + ch.getDescription() + NL);
        }
        if (characs.isEmpty()) {
            b.append("\t**no characteristics**" + NL);
        }
        return b.toString();
    }

    /**
     * 
     * @return a description of all standard fields
     */
    public String getStandardFieldsInfo() {
        StringBuilder b = new StringBuilder();
        for (StandardField entry : standardFields.values()) {
            long value = entry.getValue();
            HeaderKey key = entry.getKey();
            String description = entry.getDescription();
            if (key.equals(MAGIC_NUMBER)) {
                b.append(description + ": " + value + " --> "
                        + magicNumber.description + NL);
            } else {
                b.append(description + ": " + value + " (0x"
                        + Long.toHexString(value) + ")" + NL);
            }
        }
        return b.toString();
    }

    private MagicNumber readMagicNumber(Map<String, String[]> standardSpec)
            throws IOException {
        int offset = Integer.parseInt(standardSpec.get("MAGIC_NUMBER")[1]);
        int length = Integer.parseInt(standardSpec.get("MAGIC_NUMBER")[2]);
        long value = getBytesLongValueSafely(headerbytes, offset, length);
        for (MagicNumber num : MagicNumber.values()) {
            if (num.getValue() == value) {
                if (num == MagicNumber.ROM) {
                    throw new IOException("Magic number is "
                            + magicNumber.getName()
                            + ", but PortEx does not support object files.");
                }
                return num;
            }
        }
        return MagicNumber.UNKNOWN;
    }

    /**
     * Returns the magic number.
     * 
     * @return the magic number
     */
    public MagicNumber getMagicNumber() {
        return magicNumber;
    }

    /**
     * Returns the description string of the image base.
     * 
     * @param value
     * @return description string of the image base value
     */
    public static String getImageBaseDescription(long value) {
        if (value == 0x10000000)
            return "DLL default";
        if (value == 0x00010000)
            return "default for Windows CE EXEs";
        if (value == 0x00400000)
            return "default for Windows NT, 2000, XP, 95, 98 and Me";
        return "no default value";
    }

    /**
     * Checks if image base is too large or zero and relocates it accordingly.
     * Otherwise the usual image base is returned.
     * 
     * see: @see <a
     * href="https://code.google.com/p/corkami/wiki/PE#ImageBase">corkami</a>
     * 
     * @return relocated image base
     */
    public long getRelocatedImageBase() {
        long imageBase = get(WindowsEntryKey.IMAGE_BASE);
        long sizeOfImage = get(WindowsEntryKey.SIZE_OF_IMAGE);
        if (imageBase + sizeOfImage >= 0x80000000L || imageBase == 0L) {
            return 0x10000L;
        }
        return imageBase;
    }

    /**
     * Returns a list of the DllCharacteristics that are set in the file.
     * 
     * @return list of DllCharacteristics
     */
    public List<DllCharacteristic> getDllCharacteristics() {
        long value = get(DLL_CHARACTERISTICS);
        List<DllCharacteristic> dllChs = DllCharacteristic.getAllFor(value);
        return dllChs;
    }

    /**
     * Returns the subsystem instance of the file.
     * 
     * @return subsystem instance
     */
    public Subsystem getSubsystem() {
        long value = get(SUBSYSTEM);
        return Subsystem.getForValue(value);
    }

    @Override
    public long getOffset() {
        return offset;
    }

    /**
     * Returns minimum size of optional header based on magic number
     * 
     * @return minimum size of optional header
     */
    public int getMinSize() {
        return getMagicNumber() == MagicNumber.PE32 ? 100 : 112;
    }

    /**
     * Returns maximum size estimated for NrOfRVAAndValue = 16 based on magic
     * number
     * 
     * @return maximum size of optional header in bytes
     */
    public int getMaxSize() {
        return getMagicNumber() == MagicNumber.PE32 ? 224 : 240;
    }

    /**
     * TODO return actual size instead of max size
     * 
     * @return number of header bytes
     */
    public long getSize() {
        return headerbytes.length;
    }

    /**
     * Adjusts the file alignment to low alignment mode if necessary.
     * 
     * @return 1 if low alignment mode, file alignment value otherwise
     */
    public long getAdjustedFileAlignment() {
        long fileAlign = get(FILE_ALIGNMENT);
        if (isLowAlignmentMode()) {
            return 1;
        }
        if (fileAlign < 512) { // TODO correct?
            fileAlign = 512;
        }
        // TODO what happens for too big alignment?
        // TODO this is just a test, verify
        if (fileAlign % 512 != 0) {
            long rest = fileAlign % 512;
            fileAlign += (512 - rest);
        }
        return fileAlign;
    }

    /**
     * Determines if the file is in low alignment mode.
     * 
     * @see <a
     *      href="https://code.google.com/p/corkami/wiki/PE#SectionAlignment_/_FileAlignment">corkami
     *      Wiki PE</a>
     * @return true iff file is in low alignment mode
     */
    public boolean isLowAlignmentMode() {
        long fileAlign = get(FILE_ALIGNMENT);
        long sectionAlign = get(SECTION_ALIGNMENT);
        return 1 <= fileAlign && fileAlign == sectionAlign
                && fileAlign <= 0x800;
    }

    /**
     * Determines if the file is in standard alignment mode.
     * 
     * @see <a
     *      href="https://code.google.com/p/corkami/wiki/PE#SectionAlignment_/_FileAlignment">corkami
     *      Wiki PE</a>
     * @return true iff file is in standard alignment mode
     */
    public boolean isStandardAlignmentMode() {
        long fileAlign = get(FILE_ALIGNMENT);
        long sectionAlign = get(SECTION_ALIGNMENT);
        return 0x200 <= fileAlign && fileAlign <= sectionAlign
                && 0x1000 <= sectionAlign;
    }

}
