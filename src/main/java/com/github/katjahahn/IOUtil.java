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
package com.github.katjahahn;

import static com.github.katjahahn.ByteArrayUtil.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.google.java.contract.Ensures;

/**
 * Utilities for file IO needed to read maps and arrays from the text files in
 * the data subdirectory of PortEx.
 * <p>
 * The specification text files are CSV, where the values are separated by
 * semicolon and a new entry begins on a new line.
 * 
 * @author Katja Hahn
 * 
 */
public class IOUtil {

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

    public static <T extends Enum<T> & HeaderKey> Map<T, StandardField> readHeaderEntries(
            Class<T> clazz, SpecificationFormat specFormat, String specName,
            byte[] headerbytes) throws IOException {

        EnumSolver<T> enumSolver = new EnumSolver<>(clazz);
        Map<T, StandardField> data = initFullEnumMap(enumSolver);
        List<String[]> specification = readArray(specName);

        int descriptionIndex = specFormat.description;
        int offsetIndex = specFormat.offset;
        int lengthIndex = specFormat.length;
        int keyIndex = specFormat.key;

        for (String[] specs : specification) {
            T key = enumSolver.valueFor(specs[keyIndex]);
            int offset = Integer.parseInt(specs[offsetIndex]);
            int length = Integer.parseInt(specs[lengthIndex]);
            long value = getBytesLongValue(headerbytes, offset, length);
            data.put(key,
                    new StandardField(key, specs[descriptionIndex], value));
        }
        return data;
    }

    private static <T extends Enum<T> & HeaderKey> Map<T, StandardField> initFullEnumMap(
            EnumSolver<T> enumSolver) {
        Map<T, StandardField> map = new HashMap<>();
        for (T key : enumSolver.values()) {
            map.put(key, new StandardField(key, "", 0L));
        }
        return map;
    }

    /**
     * Reads the specified file into a map. The first value is used as key. The
     * rest is put into a list and used as map value. Each entry is one line of
     * the file.
     * 
     * @param filename
     *            the name of the specification file (not the path to it)
     * @return a map with the first column as keys and the other columns as
     *         values.
     * @throws IOException
     *             if unable to read the specification file
     */
    @Ensures("result != null")
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
    @Ensures("result != null")
    public static List<String[]> readArray(String filename) throws IOException {
        List<String[]> list = new LinkedList<>();
        try (InputStreamReader isr = new InputStreamReader(
                IOUtil.class.getResourceAsStream(SPEC_DIR + filename));
                BufferedReader reader = new BufferedReader(isr)) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                String[] values = line.split(DELIMITER);
                list.add(values);
            }
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
    @Ensures("result != null")
    public static List<String[]> readArrayFrom(File file) throws IOException {
        List<String[]> list = new LinkedList<>();
        try (BufferedReader reader = Files.newBufferedReader(file.toPath(),
                Charset.forName("UTF-8"))) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                String[] values = line.split(DELIMITER);
                list.add(values);
            }
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
    @Ensures("result != null")
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
    @Ensures("result != null")
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
        return keys;
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
    @Ensures({ "result != null", "result.trim().length() > 0" })
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
        return b.toString();
    }

    public static class SpecificationFormat {
        public int key;
        public int description;
        public int offset;
        public int length;

        public SpecificationFormat(int key, int description, int offset,
                int length) {
            this.description = description;
            this.offset = offset;
            this.length = length;
            this.key = key;
        }
    }

    public static class EnumSolver<T extends Enum<T>> {

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
