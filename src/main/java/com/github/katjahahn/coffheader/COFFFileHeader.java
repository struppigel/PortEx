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
package com.github.katjahahn.coffheader;

import static com.github.katjahahn.ByteArrayUtil.*;
import static com.github.katjahahn.coffheader.COFFHeaderKey.*;

import java.io.IOException;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.HeaderKey;
import com.github.katjahahn.IOUtil;
import com.github.katjahahn.PEModule;
import com.github.katjahahn.StandardEntry;

/**
 * Reads the COFF File Header and allows access to the information in it.
 * 
 * @author Katja Hahn
 * 
 */
public class COFFFileHeader extends PEModule {

	public static final String COFF_SPEC_FILE = "coffheaderspec";
	public static final int HEADER_SIZE = 20;

	private final byte[] headerbytes;
	private List<StandardEntry> data;
	private Map<String, String[]> specification;

	/**
	 * @constructor Creates a COFFFileHeader instance that uses the bytes
	 *              specified.
	 * 
	 * @param headerbytes
	 *            an array that holds the headerbytes. The length of the array
	 *            has to be HEADER_SIZE.
	 */
	public COFFFileHeader(byte[] headerbytes) {
		assert headerbytes.length == HEADER_SIZE;
		this.headerbytes = headerbytes.clone();
		try {
			specification = IOUtil.readMap(COFF_SPEC_FILE);
		} catch (NumberFormatException | IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Reads the data from the headerbytes array into a list of StandardEntries.
	 */
	@Override
	public void read() throws IOException {
		data = new LinkedList<>();
		int description = 0;
		int offset = 1;
		int length = 2;
		for (Entry<String, String[]> entry : specification.entrySet()) {

			String[] specs = entry.getValue();
			int value = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offset]),
					Integer.parseInt(specs[length]));
			HeaderKey key = COFFHeaderKey.valueOf(entry.getKey());
			data.add(new StandardEntry(key, specs[description], value));
		}
	}

	/**
	 * Constructs a string that summarizes all COFF File Header values.
	 * 
	 * @return string
	 */
	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder("----------------" + NL
				+ "COFF File Header" + NL + "----------------" + NL);
		for (StandardEntry entry : data) {

			int value = (int) entry.value; //COFF has no 8 Byte values
			HeaderKey key = entry.key;
			String description = entry.description;
			if (key.equals(CHARACTERISTICS)) {
				b.append(NL + description + ": " + NL);
				b.append(IOUtil.getCharacteristics(value, "characteristics")
						+ NL);
			} else if (key.equals(TIME_DATE)) {
				b.append(description + ": ");
				b.append(convertToDate(value) + NL);
			} else if (key.equals(MACHINE)) {
				b.append(description + ": ");
				b.append(getMachineTypeString(value) + NL);
			} else {
				b.append(description + ": " + value + NL);
			}
		}
		return b.toString();
	}

	private String getMachineTypeString(int value) {
		try {
			Map<String, String[]> map = IOUtil.readMap("machinetype");
			String key = Integer.toHexString(value);
			String[] ret = map.get(key);
			if (ret != null) {
				return ret[1];
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
	private Date convertToDate(int seconds) {
		long millis = (long) seconds * 1000;
		return new Date(millis);
	}

	/**
	 * Returns the COFF File Header value for the given entry key.
	 * 
	 * @param key
	 * @return
	 */
	public int get(COFFHeaderKey key) {
		for (StandardEntry entry : data) {
			if (entry.key.equals(key)) {
				return (int) entry.value; //COFF has > 4 Byte values --> enough for int
			}
		}
		throw new IllegalArgumentException("invalid key");
	}

	/**
	 * Returns a description of the machine type.
	 * 
	 * @param machine
	 * @return description
	 */
	public static String getDescription(MachineType machine) {
		int description = 1;
		int keyString = 0;
		try {
			Map<String, String[]> map = IOUtil.readMap("machinetype");
			for (String[] entry : map.values()) {
				if (entry[keyString].equals(machine.getKey())) {
					return entry[description];
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null; // this should never happen
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
	 * Returns the characteristics value.
	 * 
	 * @return
	 */
	public int getCharacteristics() {
		return get(CHARACTERISTICS);
	}

	/**
	 * Returns a list of the characteristics.
	 * 
	 * @return
	 */
	public List<String> getCharacteristicsDescriptions() {
		return IOUtil.getCharacteristicsDescriptions(getCharacteristics(),
				"characteristics");
	}

	/**
	 * Returns the enum that denotes the machine type.
	 * 
	 * @return MachineType
	 */
	public MachineType getMachineType() {
		int value = get(MACHINE);
		try {
			Map<String, String[]> map = IOUtil.readMap("machinetype");
			String hexKey = Integer.toHexString(value);
			String[] ret = map.get(hexKey);
			if (ret != null) {
				String type = ret[0].substring("IMAGE_FILE_MACHINE_".length());
				return MachineType.valueOf(type);
			}
		} catch (IOException e) {
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
	 * Returns the optional header size.
	 * 
	 * @return
	 */
	public int getSizeOfOptionalHeader() {
		return get(SIZE_OF_OPT_HEADER);
	}

	/**
	 * Returns the number of sections.
	 * 
	 * @return number of sections
	 */
	public int getNumberOfSections() {
		return get(SECTION_NR);
	}

}
