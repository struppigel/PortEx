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
package com.github.katjahahn.parser;

import static com.github.katjahahn.parser.ByteArrayUtil.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.common.base.Optional;

/**
 * Utilities for file IO needed to read maps and arrays from the text files in
 * the data subdirectory of PortEx.
 * <p>
 * The default specification text files are CSV, where the values are separated
 * by semicolon and a new entry begins on a new line.
 * 
 * @author Katja Hahn
 * 
 */
public final class IOUtil {

    private static final Logger logger = LogManager.getLogger(IOUtil.class
            .getName());
    /**
     * System independend newline.
     */
    public static final String NL = System.getProperty("line.separator");
    /**
     * The default delimiter for a line in a specification file.
     */
    public static final String DEFAULT_DELIMITER = ";";
    /**
     * The folder that contains the specification files
     */
    private static final String SPEC_DIR = "/data/";

    /**
     * Forbidden. This is a utility class.
     */
    private IOUtil() {
    }
    
    /**
     * Loads the bytes at the offset into a byte array with the given length
     * using the raf.
     * 
     * @param offset
     *            to seek
     * @param length
     *            of the byte array, equals number of bytes read
     * @param raf
     *            the random access file
     * @return byte array
     * @throws IOException
     *             if unable to read the bytes
     */
    public static byte[] loadBytes(long offset, int length,
            RandomAccessFile raf) throws IOException {
        assert length >= 0;
        raf.seek(offset);
        byte[] bytes = new byte[length];
        raf.readFully(bytes);
        return bytes;
    }

    /**
     * Reads the entries of a Header and returns a map containing the
     * {@link HeaderKey} as key and {@link StandardField} as value.
     * <p>
     * The map is initialized with all possible HeaderKeys of the subtype and
     * empty fields.
     * <p>
     * The passed instances must not be null and the specName must not be empty.
     * 
     * @param clazz
     *            the concrete subclass of the HeaderKey
     * @param specFormat
     *            the format of the specification file
     * @param specification
     *            the specification to be used for reading the fields
     * @param headerbytes
     *            the bytes of the header
     * @param headerOffset
     *            the file offset to the start of the headerbytes
     * @param <T>
     *            the type for the header key that the returned map shall use
     * @return header entries
     */
    public static <T extends Enum<T> & HeaderKey> Map<T, StandardField> readHeaderEntries(
            Class<T> clazz, SpecificationFormat specFormat, List<String[]> specification,
            byte[] headerbytes, long headerOffset) {
        assert clazz != null && specFormat != null && headerbytes != null;

        /* initializers */
        // init a full map with default fields. Fields that can be read are
        // changed subsequently
        Map<T, StandardField> data = initFullEnumMap(clazz);

        // use the specification format to get the right indices
        int descriptionIndex = specFormat.description;
        int offsetIndex = specFormat.offset;
        int lengthIndex = specFormat.length;
        int keyIndex = specFormat.key;

        // loop through every line in the specification, put read data to the
        // map
        for (String[] specs : specification) {
            // get the enum type for the key string
            T key = Enum.valueOf(clazz, specs[keyIndex].trim());
            // read offset, length, and description, offset is relative to
            // header
            int offset = Integer.parseInt(specs[offsetIndex].trim());
            int length = Integer.parseInt(specs[lengthIndex].trim());
            String description = specs[descriptionIndex];
            // get the absolute file offset for the current field
            long fieldOffset = headerOffset + offset;
            // check if value is entirely contained in the headerbytes
            long value = 0;
            if (headerbytes.length >= offset + length) {
                value = getBytesLongValue(headerbytes, offset, length);
                data.put(key, new StandardField(key, description, value,
                        fieldOffset, length));
            } else {
                // value not entirely contained in array, so use a safe method
                // to fetch it
                value = getBytesLongValueSafely(headerbytes, offset, length);
                // ... and print a warning message
                logger.warn("offset + length larger than headerbytes given");
            }
            // add data to map
            data.put(key, new StandardField(key, description, value,
                    fieldOffset, length));
        }
        assert data != null;
        return data;
    }
    
    /**
     * Reads the entries of a Header and returns a map containing the
     * {@link HeaderKey} as key and {@link StandardField} as value.
     * <p>
     * The map is initialized with all possible HeaderKeys of the subtype and
     * empty fields.
     * <p>
     * The passed instances must not be null and the specName must not be empty.
     * 
     * @param clazz
     *            the concrete subclass of the HeaderKey
     * @param specFormat
     *            the format of the specification file
     * @param specName
     *            the name of the specification file (not the path to it), must
     *            not be empty.
     * @param headerbytes
     *            the bytes of the header
     * @param headerOffset
     *            the file offset to the start of the headerbytes
     * @param <T>
     *            the type for the header key that the returned map shall use
     * @return header entries
     * @throws IOException
     *             if specification file can not be read
     */
    public static <T extends Enum<T> & HeaderKey> Map<T, StandardField> readHeaderEntries(
            Class<T> clazz, SpecificationFormat specFormat, String specName,
            byte[] headerbytes, long headerOffset) throws IOException {
        assert specName != null && specName.trim().length() > 0;
        // get the specification
        List<String[]> specification = readArray(specName);
        // call readHeaderEntries for specification
        return readHeaderEntries(clazz, specFormat, specification, headerbytes, headerOffset);
    }

    /**
     * Initialized a map containing all keys of the Enum T as map-key and
     * default StandardFields as map-value.
     * <p>
     * Ensures that no null value is returned.
     * 
     * @param enumSolver
     *            EnumSolver instance
     * @return the fully initialized map
     */
    private static <T extends Enum<T> & HeaderKey> Map<T, StandardField> initFullEnumMap(
            Class<T> clazz) {
        Map<T, StandardField> map = new EnumMap<>(clazz);
        // loop through all values of the Enum type and add a dummy field
        for (T key : clazz.getEnumConstants()) {
            StandardField dummy = new StandardField(key, "", 0L, 0L, 0L);
            map.put(key, dummy);
        }
        assert map != null;
        return map;
    }

    /**
     * Reads the specified file into a map. The first value is used as key. The
     * rest is put into a list and used as map value. Each entry is one line of
     * the file.
     * <p>
     * Ensures that no null value is returned.
     * <p>
     * Uses the default {@link #DEFAULT_DELIMITER}
     * 
     * @param filename
     *            the name of the specification file (not the path to it)
     * @return a map with the first column as keys and the other columns as
     *         values.
     * @throws IOException
     *             if unable to read the specification file
     */
    public static Map<String, String[]> readMap(String filename)
            throws IOException {
        return readMap(filename, DEFAULT_DELIMITER);
    }

    /**
     * Reads the specified file into a map. The first value is used as key. The
     * rest is put into a list and used as map value. Each entry is one line of
     * the file.
     * <p>
     * Ensures that no null value is returned.
     * 
     * @param filename
     *            the name of the specification file (not the path to it)
     * @param delimiter
     *            the delimiter regex for one column
     * @return a map with the first column as keys and the other columns as
     *         values.
     * @throws IOException
     *             if unable to read the specification file
     */
    public static Map<String, String[]> readMap(String filename,
            String delimiter) throws IOException {
        Map<String, String[]> map = new TreeMap<>();
        // read spec-file as resource, e.g., from a jar
        try (InputStreamReader isr = new InputStreamReader(
                IOUtil.class.getResourceAsStream(SPEC_DIR + filename));
                BufferedReader reader = new BufferedReader(isr)) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                // split line into the values
                String[] values = line.split(delimiter);
                // put first element as key, rest as array of value-strings
                map.put(values[0], Arrays.copyOfRange(values, 1, values.length));
            }
            assert map != null;
            return map;
        }
    }

    /**
     * Reads the specified file from the specification directory into a list of
     * arrays. Each array is the entry of one line in the file.
     * <p>
     * Ensures that no null value is returned.
     * <p>
     * Uses the default {@link #DEFAULT_DELIMITER}
     * 
     * @param filename
     *            the name of the specification file (not the path to it)
     * @return a list of arrays, each array representing a line in the spec
     * @throws IOException
     *             if unable to read the specification file
     */
    public static List<String[]> readArray(String filename) throws IOException {
        return readArray(filename, DEFAULT_DELIMITER);
    }

    /**
     * Reads the specified file from the specification directory into a list of
     * arrays. Each array is the entry of one line in the file.
     * <p>
     * Ensures that no null value is returned.
     * 
     * @param filename
     *            the name of the specification file (not the path to it)
     * @param delimiter
     *            the delimiter regex for one column
     * @return a list of arrays, each array representing a line in the spec
     * @throws IOException
     *             if unable to read the specification file
     */
    public static List<String[]> readArray(String filename, String delimiter)
            throws IOException {
        List<String[]> list = new LinkedList<>();
        // read spec-file as resource, e.g., from a jar
        try (InputStreamReader isr = new InputStreamReader(
                IOUtil.class.getResourceAsStream(SPEC_DIR + filename));
                BufferedReader reader = new BufferedReader(isr)) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                // split line into the values
                String[] values = line.split(delimiter);
                // add all values as entry to the list
                list.add(values);
            }
            assert list != null;
            return list;
        }
    }

    /**
     * Reads the specified file into a list of arrays. Each array is the entry
     * of one line in the file.
     * <p>
     * This method allows to read from files outside of the packaged jar.
     * <p>
     * Ensures that no null value is returned.
     * <p>
     * Uses the default {@link #DEFAULT_DELIMITER}
     * 
     * @param file
     *            the file to read from, UTF-8 encoded
     * @return a list of arrays, each array representing a line in the spec
     * @throws IOException
     *             if unable to read the file
     */
    public static List<String[]> readArrayFrom(File file) throws IOException {
        List<String[]> list = new LinkedList<>();
        // read spec as UTF-8 encoded file
        try (BufferedReader reader = Files.newBufferedReader(file.toPath(),
                Charset.forName("UTF-8"))) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                // split line into the values
                String[] values = line.split(DEFAULT_DELIMITER);
                // add all values as entry to the list
                list.add(values);
            }
            assert list != null;
            return list;
        }
    }

    /**
     * Returns a list of the descriptions of all characteristics that are set by
     * the value flag.
     * <p>
     * This is intented to be used for string output of characteristics.
     * <p>
     * Ensures that no null value is returned.
     * <p>
     * Assumes a fixed file format, i.e.: mask;keystring;description
     * <p>
     * The mask is a hexadecimal value-string (without 0x in front).
     * 
     * @param value
     *            the value of the characteristics field
     * @param filename
     *            the name of the specification file (not the path to it)
     * @return description list, each element is one characteristic flag that
     *         was set
     */
    public static List<String> getCharacteristicsDescriptions(long value,
            String filename) {
        List<String> characteristics = new LinkedList<>();
        try {
            // read specification for characteristics
            Map<String, String[]> map = readMap(filename);
            for (Entry<String, String[]> entry : map.entrySet()) {
                try {
                    // read mask
                    long mask = Long.parseLong(entry.getKey(), 16);
                    // use mask to check if flag is set
                    if ((value & mask) != 0) {
                        characteristics.add(entry.getValue()[1]);
                    }
                } catch (NumberFormatException e) {
                    // Long.parseLong went wrong
                    logger.error("ERROR. number format mismatch in file "
                            + filename);
                    logger.error("value: " + entry.getKey());
                }
            }
        } catch (IOException e) {
            logger.error(e);
        }
        assert characteristics != null;
        return characteristics;
    }

    /**
     * Returns a list of all characteristic keys that have been set by the
     * value.
     * <p>
     * Ensures that no null value is returned.
     * <p>
     * Assumes the fixed file format: mask;keystring;description
     * <p>
     * The mask is a hexadecimal value-string (without 0x in front).
     * 
     * @param value
     *            the value of the characteristics field
     * @param filename
     *            the name of the specification file (not the path to it)
     * @return list of the characteristic's keys that are set
     */
    public static List<String> getCharacteristicKeys(long value, String filename) {
        List<String> keys = new ArrayList<>();
        try {
            // read specification for characteristics
            Map<String, String[]> map = readMap(filename);
            for (Entry<String, String[]> entry : map.entrySet()) {
                try {
                    // read mask
                    long mask = Long.parseLong(entry.getKey(), 16);
                    // use mask to check if flag is set
                    if ((value & mask) != 0) {
                        keys.add(entry.getValue()[0]);
                    }
                } catch (NumberFormatException e) {
                    // Long.parseLong went wrong
                    logger.error("ERROR. number format mismatch in file "
                            + filename);
                    logger.error("value: " + entry.getKey());
                }
            }
        } catch (IOException e) {
            logger.error(e);
        }
        assert keys != null;
        return keys;
    }

    /**
     * Returns String in the second column for the value that matches the first
     * column. Semantically the second column holds the enum type string and the
     * first a set offset or flag.
     * <p>
     * Ensures that no null value is returned.
     * <p>
     * Assumes a fixed file format, i.e.: keyvalue;keystring;description The
     * mask is a hexadecimal value-string (without 0x in front).
     * 
     * @param value
     *            the value to be masked
     * @param filename
     *            the name of the specification file (not the path)
     * @return type/key-string for given value, absent if not found
     */
    public static Optional<String> getEnumTypeString(long value, String filename) {
        try {
            // read the specification
            Map<String, String[]> map = readMap(filename);
            for (Entry<String, String[]> entry : map.entrySet()) {
                try {
                    // get the key
                    long keyValue = Long.parseLong(entry.getKey());
                    // key must match the given value
                    if (value == keyValue) {
                        return Optional.of(entry.getValue()[0]);
                    }
                } catch (NumberFormatException e) {
                    // parseLong went wrong
                    logger.error("ERROR. number format mismatch in file "
                            + filename);
                    logger.error("value: " + entry.getKey());
                }
            }
        } catch (IOException e) {
            logger.error(e);
        }
        return Optional.absent();
    }

    /**
     * Returns a description of all characteristics that are set by the value
     * flag.
     * <p>
     * This is intented to be used for string output of characteristics.
     * <p>
     * Ensures that no null value is returned.
     * <p>
     * Assumes the fixed file format: mask;keystring;description
     * <p>
     * The mask is a hexadecimal value-string (without 0x in front).
     * 
     * @param value
     *            the value of the characteristics field
     * @param filename
     *            the name of the specification file (not the path to it)
     * @return formatted description for all characteristic flags that have been
     *         set
     */
    public static String getCharacteristics(long value, String filename) {
        StringBuilder b = new StringBuilder();
        try {
            // read specification
            Map<String, String[]> map = readMap(filename);
            for (Entry<String, String[]> entry : map.entrySet()) {
                try {
                    // read mask
                    long mask = Long.parseLong(entry.getKey(), 16);
                    // check if flag is set
                    if ((value & mask) != 0) {
                        //add description for this characteristic
                        b.append("\t* " + entry.getValue()[1] + NL);
                    }
                } catch (NumberFormatException e) {
                    // parseLong went wrong
                    logger.error("ERROR. number format mismatch in file "
                            + filename);
                    logger.error("value: " + entry.getKey());
                }
            }
        } catch (IOException e) {
            logger.error(e);
        }
        // check if there is a description at all
        if (b.length() == 0) {
            b.append("\t**no characteristics**" + NL);
        }
        String result = b.toString();
        assert result != null && result.trim().length() > 0;
        return result;
    }

    /**
     * Describes the format/indices of the specification file.
     * 
     */
    public static class SpecificationFormat {
        /**
         * the index of the key
         */
        public int key;
        /**
         * the index of the entry's description
         */
        public int description;
        /**
         * the index of the value's offset
         */
        public int offset;
        /**
         * the index of the value's length
         */
        public int length;

        /**
         * Creates a specification format with the given indices.
         * 
         * @param key
         *            the index of the key
         * @param description
         *            the index of the entry's description
         * @param offset
         *            the index of the value's offset
         * @param length
         *            the index of the value's length
         */
        public SpecificationFormat(int key, int description, int offset,
                int length) {
            this.description = description;
            this.offset = offset;
            this.length = length;
            this.key = key;
        }
    }

}
