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
package com.github.katjahahn.sections;

import static com.github.katjahahn.sections.SectionHeaderKey.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.HeaderKey;
import com.github.katjahahn.IOUtil;
import com.github.katjahahn.PEHeader;
import com.github.katjahahn.StandardField;
import com.google.common.base.Optional;

/**
 * Represents an entry of the {@link SectionTable}. The instance is usually
 * created by the {@link SectionTable}.
 * 
 * @author Katja Hahn
 * 
 */
public class SectionHeader extends PEHeader {

	private static final String SECTIONCHARACTERISTICS_SPEC = "sectioncharacteristics";
	private final HashMap<SectionHeaderKey, StandardField> entries = new HashMap<>();
	private String name;
	private final int number;
	private final long offset;

	/**
	 * Creates a Section Table Entry instance.
	 * 
	 * @param number
	 *            the number of the entry, beginning by 1 with the first entry
	 *            in the Section Headers
	 */
	public SectionHeader(int number, long offset) {
		this.number = number;
		this.offset = offset;
	}
	
	/**
	 * Returns the PointerToRawData rounded down to a multiple of 512.
	 * 
	 * @return aligned PointerToRawData
	 */
	public long getAlignedPointerToRaw() {
		return getValue(POINTER_TO_RAW_DATA) & ~0x1ff;
	}
	
	/**
	 * Returns the SizeOfRawData rounded up to a multiple of 4kb.
	 * 
	 * @return aligned SizeOfRawData
	 */
	public long getAlignedSizeOfRaw() {
		long sizeOfRaw = getValue(SIZE_OF_RAW_DATA);
		if(sizeOfRaw == (sizeOfRaw & ~0xfff)) {
			return sizeOfRaw;
		}
		return (sizeOfRaw + 0xfff) & ~0xfff;
	}
	
	/**
	 * Returns the VirtualSize rounded up to a multiple of 4kb.
	 * 
	 * @return aligned VirtualSize
	 */
	public long getAlignedVirtualSize() {
		long virtSize = getValue(VIRTUAL_SIZE);
		if(virtSize == (virtSize & ~0xfff)) {
			return virtSize;
		}
		return (virtSize + 0xfff) & ~0xfff;
	}

	/**
	 * Sets the name of the section table entry
	 * 
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
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
		return number;
	}

	/**
	 * Returns the long value that belongs to the given key. Note:
	 * {@link SectionHeaderKey.NAME} will throw an exception. Use
	 * {@link #getName()} instead.
	 * 
	 * @param key
	 * @return long value
	 * @throw {@link IllegalArgumentException} if not found
	 */
	@Override
	public long getValue(HeaderKey key) {
		Optional<StandardField> entry = getField(key);
		if (entry.isPresent()) {
			return entry.get().value;
		}
		throw new IllegalArgumentException("key not found " + key);
	}
	
	/**
     * Returns the long value that belongs to the given key. Note:
     * {@link SectionHeaderKey.NAME} will return absent. Use
     * {@link #getName()} instead.
     * 
     * @param key
     * @return optional value, absent if key doesn't exist
     */
    @Override
    public Optional<Long> get(HeaderKey key) {
        Optional<StandardField> entry = getField(key);
        if (entry.isPresent()) {
            return Optional.of(entry.get().value);
        }
        return Optional.absent();
    }

	/**
	 * Returns the {@link StandardField} for the given key
	 * 
	 * @param key
	 * @return standard entry
	 */
	@Override
	public Optional<StandardField> getField(HeaderKey key) {
		return Optional.fromNullable(entries.get(key));
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
	 * Adds a {@link StandardField} to the section table entry
	 * 
	 * @param entry
	 */
	public void add(StandardField entry) {
		if (entry.key instanceof SectionHeaderKey) {
			entries.put((SectionHeaderKey) entry.key, entry);
		} else {
			throw new IllegalArgumentException("invalid key");
		}
	}

	/**
	 * Returns a list of all characteristics of that section.
	 * 
	 * @return list of all characteristics
	 */
	public List<SectionCharacteristic> getCharacteristics() {
		List<SectionCharacteristic> list = new ArrayList<>();
		List<String> keys = IOUtil.getCharacteristicKeys(
				getValue(SectionHeaderKey.CHARACTERISTICS),
				SECTIONCHARACTERISTICS_SPEC);
		for (String key : keys) {
			list.add(SectionCharacteristic.valueOf(key));
		}
		return list;
	}

	@Override
	public String toString() {
		StringBuilder b = new StringBuilder();
		b.append("Name: " + getName() + IOUtil.NL);

		for (Entry<SectionHeaderKey, StandardField> entry : entries
				.entrySet()) {
			Long value = entry.getValue().value;
			SectionHeaderKey key = entry.getKey();
			if (key == SectionHeaderKey.CHARACTERISTICS) {
				b.append(entry.getValue().description
						+ ": "
						+ IOUtil.NL
						+ IOUtil.getCharacteristics(value,
								SECTIONCHARACTERISTICS_SPEC) + IOUtil.NL);
			} else {
				b.append(entry.getValue().description + ": " + value + " (0x"
						+ Long.toHexString(value) + ")" + IOUtil.NL);
			}
		}
		return b.toString();
	}

	@Override
	public long getOffset() {
		return offset;
	}

	@Override
	public String getInfo() {
		return this.toString();
	}

	@Override
	public void read() throws IOException {
		// TODO Auto-generated method stub
	}
	
}
