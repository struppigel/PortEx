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
import static com.google.common.base.Preconditions.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.HeaderKey;
import com.github.katjahahn.IOUtil;
import com.github.katjahahn.PEHeader;
import com.github.katjahahn.StandardField;

/**
 * Reads the COFF File Header and allows access to the information in it.
 * 
 * @author Katja Hahn
 * 
 */
public class COFFFileHeader extends PEHeader {

	/**
	 * The size of the header is {@value}
	 */
	public static final int HEADER_SIZE = 20;

	private static final String COFF_SPEC_FILE = "coffheaderspec";
	private final byte[] headerbytes;
	private List<StandardField> data;
	private Map<String, String[]> specification;
	private final long offset;
	
	private static final Logger logger = LogManager.getLogger(COFFFileHeader.class
			.getName());

	/**
	 * Creates a COFFFileHeader instance based on the byte array.
	 * 
	 * @param headerbytes
	 *            an array that holds the headerbytes. The length of the array
	 *            has to be {@link #HEADER_SIZE}.
	 * @param offset the file offset of the header
	 * @throws IllegalArgumentException if length of the array != {@link #HEADER_SIZE}
	 */
	public COFFFileHeader(byte[] headerbytes, long offset) {
		checkNotNull(headerbytes);
		checkArgument(headerbytes.length == HEADER_SIZE);
		this.headerbytes = headerbytes.clone();
		this.offset = offset;
		try {
			specification = IOUtil.readMap(COFF_SPEC_FILE);
		} catch (NumberFormatException | IOException e) {
			logger.error(e);
			e.printStackTrace();
		}
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
	public void read() throws IOException {
		data = new LinkedList<>();
		int description = 0;
		int offset = 1;
		int length = 2;
		for (Entry<String, String[]> entry : specification.entrySet()) {

			String[] specs = entry.getValue();
			long value = getBytesLongValue(headerbytes,
					Integer.parseInt(specs[offset]),
					Integer.parseInt(specs[length]));
			HeaderKey key = COFFHeaderKey.valueOf(entry.getKey());
			data.add(new StandardField(key, specs[description], value));
		}
	}

	/**
	 * Constructs a string that summarizes all COFF File Header values.
	 * 
	 * @return information string
	 */
	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder("----------------" + NL
				+ "COFF File Header" + NL + "----------------" + NL);
		for (StandardField entry : data) {

			long value = entry.value;
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
				b.append(getMachineTypeString((int) value) + NL);
			} else {
				b.append(description + ": " + value + NL);
			}
		}
		return b.toString();
	}

	/**
	 * Returns the machine type description string that belongs to the value.
	 * @param value the value of the machine type
	 * @return the machine type description
	 */
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
	private Date convertToDate(long seconds) {
		long millis = seconds * 1000;
		return new Date(millis);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Long get(HeaderKey key) {
		for (StandardField entry : data) {
			if (entry.key.equals(key)) {
				return entry.value;
			}
		}
		return null;
	}

	/**
	 * Returns a description of the machine type.
	 * 
	 * @param machine type
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
	 * Returns a list with all characteristics of the file.
	 * 
	 * @return list of file characteristics
	 */
	public List<FileCharacteristic> getCharacteristics() {
		List<String> keys = IOUtil.getCharacteristicKeys(get(CHARACTERISTICS)
				.intValue(), "characteristics");
		List<FileCharacteristic> characteristics = new ArrayList<>();
		for (String key : keys) {
			characteristics.add(FileCharacteristic.valueOf(key));
		}
		return characteristics;
	}

	/**
	 * Returns a list of the characteristics.
	 * 
	 * @return list of characteristic descriptions
	 */
	public List<String> getCharacteristicsDescriptions() {
		return IOUtil.getCharacteristicsDescriptions(get(CHARACTERISTICS)
				.intValue(), "characteristics");
	}

	/**
	 * Returns the enum that denotes the machine type.
	 * 
	 * @return MachineType
	 */
	public MachineType getMachineType() {
		int value = get(MACHINE).intValue();
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
	 * Returns the SizeOfOptionalHeader value.
	 * 
	 * @return size of optional header
	 */
	public Long getSizeOfOptionalHeader() {
		return get(SIZE_OF_OPT_HEADER);
	}

	/**
	 * Returns the number of sections.
	 * 
	 * @return number of sections
	 */
	public Long getNumberOfSections() {
		return get(SECTION_NR);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public StandardField getField(HeaderKey key) {
		for (StandardField entry : data) {
			if (entry.key.equals(key)) {
				return entry;
			}
		}
		return null;
	}

}
