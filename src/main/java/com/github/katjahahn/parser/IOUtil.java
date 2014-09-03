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
    // TODO system independend path separators
    private static final String DELIMITER = ";";
    private static final String SPEC_DIR = "/data/";

    /**
     * Forbidden. This is a utility class.
     */
    private IOUtil() {
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
        assert clazz != null && specFormat != null && headerbytes != null;
        assert specName != null && specName.trim().length() > 0;

        /* initializers */
        EnumSolver<T> enumSolver = new EnumSolver<>(clazz);
        // init a full map with default fields. Fields that can be read are
        // changed subsequently
        Map<T, StandardField> data = initFullEnumMap(enumSolver);
        List<String[]> specification = readArray(specName);

        int descriptionIndex = specFormat.description;
        int offsetIndex = specFormat.offset;
        int lengthIndex = specFormat.length;
        int keyIndex = specFormat.key;

        for (String[] specs : specification) {
            T key = enumSolver.valueFor(specs[keyIndex].trim());
            int offset = Integer.parseInt(specs[offsetIndex].trim());
            int length = Integer.parseInt(specs[lengthIndex].trim());
            String description = specs[descriptionIndex];
            // TODO is this correct?
            long fieldOffset = headerOffset + offset;
            if (headerbytes.length >= offset + length) {
                long value = getBytesLongValue(headerbytes, offset, length);
                data.put(key, new StandardField(key, description, value,
                        fieldOffset, length));
            } else {
                long value = getBytesLongValueSafely(headerbytes, offset,
                        length);
                data.put(key, new StandardField(key, description, value,
                        fieldOffset, length));
                logger.warn("offset + length larger than headerbytes given");
            }
        }
        assert data != null;
        return data;
    }

    /**
     * Initialized a map containing all keys of the Enum T as map-key and
     * default StandardFields as map-value.
     * 
     * @param enumSolver
     *            EnumSolver instance
     * @return the fully initialized map
     */
    private static <T extends Enum<T> & HeaderKey> Map<T, StandardField> initFullEnumMap(
            EnumSolver<T> enumSolver) {
        Map<T, StandardField> map = new EnumMap<>(enumSolver.clazz);
        for (T key : enumSolver.values()) {
            map.put(key, new StandardField(key, "", 0L, 0L, 0L));
        }
        return map;
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
     * @return a map with the first column as keys and the other columns as
     *         values.
     * @throws IOException
     *             if unable to read the specification file
     */
    public static Map<String, String[]> readMap(String filename)
            throws IOException {
        Map<String, String[]> map = new TreeMap<>();

        try (InputStreamReader isr = new InputStreamReader(
                IOUtil.class.getResourceAsStream(SPEC_DIR + filename));
                BufferedReader reader = new BufferedReader(isr)) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                String[] values = line.split(DELIMITER);
                map.put(values[0], Arrays.copyOfRange(values, 1, values.length));
            }
            assert map != null;
            return map;
        }
    }

    /**
     * Reads the specified file from the specification directory into a list of
     * arrays. Each array is the entry of one line in the file.
     * 
     * @param filename
     *            the name of the specification file (not the path to it)
     * @return a list of arrays, each array representing a line in the spec
     * @throws IOException
     *             if unable to read the specification file
     */
    public static List<String[]> readArray(String filename) throws IOException {
        return readArray(filename, DELIMITER);
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
        try (InputStreamReader isr = new InputStreamReader(
                IOUtil.class.getResourceAsStream(SPEC_DIR + filename));
                BufferedReader reader = new BufferedReader(isr)) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                String[] values = line.split(delimiter);
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
     * 
     * @param file
     *            the file to read from
     * @return a list of arrays, each array representing a line in the spec
     * @throws IOException
     *             if unable to read the file
     */
    public static List<String[]> readArrayFrom(File file) throws IOException {
        List<String[]> list = new LinkedList<>();
        try (BufferedReader reader = Files.newBufferedReader(file.toPath(),
                Charset.forName("UTF-8"))) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                String[] values = line.split(DELIMITER);
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
            Map<String, String[]> map = readMap(filename);
            for (Entry<String, String[]> entry : map.entrySet()) {
                try {
                    long mask = Long.parseLong(entry.getKey(), 16);
                    if ((value & mask) != 0) {
                        characteristics.add(entry.getValue()[1]);
                    }
                } catch (NumberFormatException e) {

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
            Map<String, String[]> map = readMap(filename);
            for (Entry<String, String[]> entry : map.entrySet()) {
                try {
                    long mask = Long.parseLong(entry.getKey(), 16);
                    if ((value & mask) != 0) {
                        keys.add(entry.getValue()[0]);
                    }
                } catch (NumberFormatException e) {
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
     * 
     * @param value
     * @param filename
     * @return type/key for given value
     */
    public static Optional<String> getType(long value, String filename) {
        try {
            Map<String, String[]> map = readMap(filename);
            for (Entry<String, String[]> entry : map.entrySet()) {
                try {
                    long keyValue = Long.parseLong(entry.getKey());
                    if (value == keyValue) {
                        return Optional.of(entry.getValue()[0]);
                    }
                } catch (NumberFormatException e) {
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
            Map<String, String[]> map = readMap(filename);
            for (Entry<String, String[]> entry : map.entrySet()) {
                try {
                    long mask = Long.parseLong(entry.getKey(), 16);
                    if ((value & mask) != 0) {
                        b.append("\t* " + entry.getValue()[1] + NL);
                    }
                } catch (NumberFormatException e) {
                    logger.error("ERROR. number format mismatch in file "
                            + filename);
                    logger.error("value: " + entry.getKey());
                }
            }
        } catch (IOException e) {
            logger.error(e);
        }
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

    /**
     * Used by
     * {@link IOUtil#readHeaderEntries(Class, SpecificationFormat, String, byte[])}
     * to be able to use Enum static methods based on a class.
     * 
     * @param <T>
     *            the Enum type
     */
    private static class EnumSolver<T extends Enum<T>> {

        private Class<T> clazz;

        public EnumSolver(Class<T> clazz) {
            this.clazz = clazz;
        }

        public T valueFor(String key) {
            return Enum.valueOf(clazz, key);
        }

        public T[] values() {
            return clazz.getEnumConstants();
        }
    }

}
