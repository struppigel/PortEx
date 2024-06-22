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
package com.github.struppigel.parser.optheader;

import com.github.struppigel.parser.Header;
import com.github.struppigel.parser.HeaderKey;
import com.github.struppigel.parser.IOUtil;
import com.github.struppigel.parser.IOUtil.SpecificationFormat;
import com.github.struppigel.parser.StandardField;
import com.github.struppigel.parser.*;
import com.google.common.base.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.github.struppigel.parser.ByteArrayUtil.getBytesLongValueSafely;
import static com.github.struppigel.parser.IOUtil.NL;
import static com.github.struppigel.parser.optheader.StandardFieldEntryKey.BASE_OF_DATA;
import static com.github.struppigel.parser.optheader.StandardFieldEntryKey.MAGIC_NUMBER;
import static com.github.struppigel.parser.optheader.WindowsEntryKey.*;

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
	 * Returns maybe the standard field entry for the given key.
	 * 
	 * If the file is a PE32+, it will not have a base of data field and return
	 * absent for the base of data key.
	 * 
	 * @param key the key of the standard field
	 * @return the standard field entry for the given key
	 */
	public Optional<StandardField> maybeGetStandardFieldEntry(
			StandardFieldEntryKey key) {
		return Optional.fromNullable(standardFields.get(key));
	}

	/**
	 * Returns the standard field entry for the given key.
	 * 
	 * @param key the key of the standard field
	 * @return the standard field entry for the given key
	 * @throws IllegalArgumentException if key is base of data for a PE32+
	 */
	public StandardField getStandardFieldEntry(StandardFieldEntryKey key) {
		if (!standardFields.containsKey(key)) {
			throw new IllegalArgumentException("standard field " + key
					+ " does not exist!");
		}
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
		IOUtil.SpecificationFormat format = new IOUtil.SpecificationFormat(0, 1, 2, 3);
		standardFields = IOUtil.readHeaderEntries(StandardFieldEntryKey.class,
				format, STANDARD_SPEC, headerbytes, getOffset());
		// PE32+ has no base of data, the read standardfield contains arbitrary
		// data from next fields
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
				long address = ByteArrayUtil.getBytesLongValueSafely(headerbytes, offset,
						length);
				long size = ByteArrayUtil.getBytesLongValueSafely(headerbytes, offset
						+ length, length);
				// TODO test if this is correct
				long tableEntryOffset = offset + getOffset();
				if (address != 0) {
					DataDirEntry entry = new DataDirEntry(specs[description],
							address, size, tableEntryOffset, isLowAlignmentMode());
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
		IOUtil.SpecificationFormat format = new IOUtil.SpecificationFormat(0, description,
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
		return "---------------" + IOUtil.NL + "Optional Header" + IOUtil.NL
				+ "---------------" + IOUtil.NL + IOUtil.NL + "Standard fields" + IOUtil.NL
				+ "..............." + IOUtil.NL + IOUtil.NL + getStandardFieldsInfo() + IOUtil.NL
				+ "Windows specific fields" + IOUtil.NL + "......................."
				+ IOUtil.NL + IOUtil.NL + getWindowsSpecificInfo() + IOUtil.NL + "Data directories"
				+ IOUtil.NL + "................" + IOUtil.NL + IOUtil.NL + "virtual_address/size"
				+ IOUtil.NL + IOUtil.NL + getDataDirInfo();
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
					+ Long.toHexString(entry.getDirectorySize()) + ")" + IOUtil.NL);
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
						+ getImageBaseDescription(value) + IOUtil.NL);
			} else if (key.equals(SUBSYSTEM)) {
				// subsystem has only 2 bytes
				b.append(description + ": " + getSubsystem().getDescription()
						+ IOUtil.NL);
			} else if (key.equals(DLL_CHARACTERISTICS)) {
				b.append(IOUtil.NL + description + ": " + IOUtil.NL);
				b.append(getCharacteristicsInfo(value) + IOUtil.NL);
			}

			else {
				b.append(description + ": " + value + " (0x"
						+ Long.toHexString(value) + ")" + IOUtil.NL);
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
			b.append("\t* " + ch.getDescription() + IOUtil.NL);
		}
		if (characs.isEmpty()) {
			b.append("\t**no characteristics**" + IOUtil.NL);
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
						+ magicNumber.description + IOUtil.NL);
			} else {
				b.append(description + ": " + value + " (0x"
						+ Long.toHexString(value) + ")" + IOUtil.NL);
			}
		}
		return b.toString();
	}

	private MagicNumber readMagicNumber(Map<String, String[]> standardSpec)
			throws IOException {
		int offset = Integer.parseInt(standardSpec.get("MAGIC_NUMBER")[1]);
		int length = Integer.parseInt(standardSpec.get("MAGIC_NUMBER")[2]);
		long value = ByteArrayUtil.getBytesLongValueSafely(headerbytes, offset, length);
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
	 * Description for the major and minor linker version in the Optional Header
	 * @return textual description for linker version or "Unknown linker version" if not known.
	 */
	public String getLinkerVersionDescription() {
		int major = (int) get(StandardFieldEntryKey.MAJOR_LINKER_VERSION);
		int minor = (int) get(StandardFieldEntryKey.MINOR_LINKER_VERSION);
		String description = "";
		switch (major) {
			case 1:
				description = "800";
				break;
			case 2:
				description = "900";
				break;
			case 4:
				if(minor == 0) description = "1000";
				if(minor == 2) description = "1020";
				break;
			case 5:
				description = "(1100) Visual Studio 5.0";
				break;
			case 6:
				description = "(1200) Visual Studio 6.0";
				break;
			case 7:
				if(minor == 0) description = "(1300) Visual Studio 2002 7.0";
				if(minor == 1) description = "(1310) Visual Studio 2003 7.1";
				break;
			case 8:
				description = "(1400) Visual Studio 2005 8.0";
				break;
			case 9:
				description = "(1500) Visual Studio 2008 9.0";
				break;
			case 10:
				description = "(1600) Visual Studio 2010 10.0";
				break;
			case 11:
				description = "(1700) Visual Studio 2012 11.0";
				break;
			case 12:
				description = "(1800) Visual Studio 2013 12.0";
				break;
			case 14:
				if(minor == 0) description = "(1900) Visual Studio 2015 14.0";

				if(minor == 1) description = "(1910) Visual Studio 2017 15.0-15.2";
				if(minor == 11) description = "(1911) Visual Studio 2017 15.3";
				if(minor == 12) description = "(1912) Visual Studio 2017 15.5";
				if(minor == 13) description = "(1913) Visual Studio 2017 15.6";
				if(minor == 14) description = "(1914) Visual Studio 2017 15.7";
				if(minor == 15) description = "(1915) Visual Studio 2017 15.8";
				if(minor == 16) description = "(1916) Visual Studio 2017 15.9";

				if(minor == 20) description = "(1920) Visual Studio 2019 16.0";
				if(minor == 21) description = "(1921) Visual Studio 2019 16.1";
				if(minor == 22) description = "(1922) Visual Studio 2019 16.2";
				if(minor == 23) description = "(1923) Visual Studio 2019 16.3";
				if(minor == 24) description = "(1924) Visual Studio 2019 16.4";
				if(minor == 25) description = "(1925) Visual Studio 2019 16.5";
				if(minor == 26) description = "(1926) Visual Studio 2019 16.6";
				if(minor == 27) description = "(1927) Visual Studio 2019 16.7";
				if(minor == 28) description = "(1928) Visual Studio 2019 16.8-16.9";
				if(minor == 29) description = "(1929) Visual Studio 2019 16.10-16.11";

				if(minor == 30) description = "(1930) Visual Studio 2022 17.0";
				if(minor == 31) description = "(1931) Visual Studio 2022 17.1";
				if(minor == 32) description = "(1932) Visual Studio 2022 17.2";
				if(minor == 33) description = "(1933) Visual Studio 2022 17.3";
				if(minor == 34) description = "(1934) Visual Studio 2022 17.4";
				break;
			default:
				description = "Unknown linker version";
		}
		return description;
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
