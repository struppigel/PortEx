package com.github.katjahahn.pemodules;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.FileIO;

public class OptionalHeader extends PEModule {

	/* spec location */
	private static final String STANDARD_SPEC = "optionalheaderstandardspec";
	private static final String WINDOWS_SPEC = "optionalheaderwinspec";
	private static final String DATA_DIR_SPEC = "datadirectoriesspec";

	/* magic number values */
	private static final int PE32 = 0x10B;
	private static final int PE32_PLUS = 0x20B;
	private static final int ROM = 0x107;

	/* extracted file data */
	private List<DataDirEntry> dataDirEntries;
	private List<StandardEntry> standardFields;
	private List<StandardEntry> windowsFields;

	private final byte[] headerbytes;
	private int magicNumber;
	private int rvaNumber;

	public OptionalHeader(byte[] headerbytes) {
		this.headerbytes = headerbytes;
		try {
			Map<String, String[]> standardSpec = FileIO.readMap(STANDARD_SPEC);
			Map<String, String[]> windowsSpec = FileIO.readMap(WINDOWS_SPEC);
			List<String[]> datadirSpec = FileIO.readArray(DATA_DIR_SPEC);

			this.magicNumber = getMagicNumber(standardSpec);

			loadStandardFields(standardSpec);
			loadWindowsSpecificFields(windowsSpec);
			loadDataDirectories(datadirSpec);
		} catch (NumberFormatException | IOException e) {
			e.printStackTrace();
		}
	}

	public List<DataDirEntry> getDataDirEntries() {
		return new LinkedList<>(dataDirEntries);
	}

	public List<StandardEntry> getWindowsSpecificFields() {
		return new LinkedList<>(windowsFields);
	}

	public List<StandardEntry> getStandardFields() {
		return new LinkedList<>(standardFields);
	}

	public DataDirEntry getDataDirEntry(String fieldname) {
		for (DataDirEntry entry : dataDirEntries) {
			if (entry.fieldName.equals(fieldname)) {
				return entry;
			}
		}
		return null;
	}

	public StandardEntry getStandardFieldEntry(String key) {
		for (StandardEntry entry : standardFields) {
			if (entry.key.equals(key)) {
				return entry;
			}
		}
		return null;
	}

	public StandardEntry getWindowsFieldEntry(String key) {
		for (StandardEntry entry : windowsFields) {
			if (entry.key.equals(key)) {
				return entry;
			}
		}
		return null;
	}

	private void loadStandardFields(Map<String, String[]> standardSpec) {
		standardFields = new LinkedList<>();
		int description = 0;
		int offset = 1;
		int length = 2;

		for (Entry<String, String[]> entry : standardSpec.entrySet()) {
			String[] specs = entry.getValue();
			int value = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offset]),
					Integer.parseInt(specs[length]));
			String key = entry.getKey();
			standardFields
					.add(new StandardEntry(key, specs[description], value));
		}

	}

	private void loadDataDirectories(List<String[]> datadirSpec) {
		dataDirEntries = new LinkedList<>();
		final int description = 0;
		int offset;
		int length = 3;

		if (magicNumber == PE32) {
			offset = 1;
		} else if (magicNumber == PE32_PLUS) {
			offset = 2;
		} else {
			return; // no fields
		}

		int counter = 0;
		for (String[] specs : datadirSpec) {
			if (counter >= rvaNumber) {
				break;
			}
			int value = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offset]),
					Integer.parseInt(specs[length]));
			if (value != 0) {
				int address = value & 0xFF00 >> 8;
				int size = value & 0x00FF;
				dataDirEntries.add(new DataDirEntry(specs[description],
						address, size));
			}
			counter++;
		}
	}

	private void loadWindowsSpecificFields(Map<String, String[]> windowsSpec) {
		windowsFields = new LinkedList<StandardEntry>();
		int offsetLoc;
		int lengthLoc;
		final int description = 0;

		if (magicNumber == PE32) {
			offsetLoc = 1;
			lengthLoc = 3;
		} else if (magicNumber == PE32_PLUS) {
			offsetLoc = 2;
			lengthLoc = 4;
		} else {
			return; // no fields
		}

		for (Entry<String, String[]> entry : windowsSpec.entrySet()) {
			String[] specs = entry.getValue();
			int value = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offsetLoc]),
					Integer.parseInt(specs[lengthLoc]));
			String key = entry.getKey();
			windowsFields
					.add(new StandardEntry(key, specs[description], value));
			if (key.equals("NUMBER_OF_RVA_AND_SIZES")) {
				this.rvaNumber = value;
			}
		}
	}

	@Override
	public String getInfo() {
		return "---------------" + NEWLINE + "Optional Header" + NEWLINE
				+ "---------------" + NEWLINE + NEWLINE + "Standard fields"
				+ NEWLINE + "..............." + NEWLINE + NEWLINE
				+ getStandardFieldsInfo() + NEWLINE + "Windows specific fields"
				+ NEWLINE + "......................." + NEWLINE + NEWLINE
				+ getWindowsSpecificInfo() + NEWLINE + "Data directories"
				+ NEWLINE + "................" + NEWLINE + NEWLINE
				+ "virtual_address/size" + NEWLINE + NEWLINE + getDataDirInfo();
	}

	private String getDataDirInfo() {
		StringBuilder b = new StringBuilder();
		for (DataDirEntry entry : dataDirEntries) {
			b.append(entry.fieldName + ": " + entry.virtualAddress + "(0x"
					+ Integer.toHexString(entry.virtualAddress) + ")/"
					+ entry.size + NEWLINE);
		}
		return b.toString();
	}

	/**
	 * Returns a string with description of the windows specific header fields.
	 * Magic number must be set.
	 * 
	 * @return string with windows specific fields
	 */
	private String getWindowsSpecificInfo() {
		StringBuilder b = new StringBuilder();
		for (StandardEntry entry : windowsFields) {
			int value = entry.value;
			String key = entry.key;
			String description = entry.description;
			if (key.equals("IMAGE_BASE")) {
				b.append(description + ": " + value + " (0x"
						+ Integer.toHexString(value) + "), "
						+ getImageBaseDescription(value) + NEWLINE);
			} else if (key.equals("SUBSYSTEM")) {
				b.append(description + ": " + getSubsystemDescription(value)
						+ NEWLINE);
			} else if (key.equals("DLL_CHARACTERISTICS")) {
				b.append(NEWLINE + description + ": " + NEWLINE);
				b.append(getCharacteristics(value, "dllcharacteristics")
						+ NEWLINE);
			}

			else {
				b.append(description + ": " + value + " (0x"
						+ Integer.toHexString(value) + ")" + NEWLINE);
				if (key.equals("NUMBER_OF_RVA_AND_SIZES")) {
					rvaNumber = value;
				}
			}
		}
		return b.toString();
	}

	private String getStandardFieldsInfo() {
		StringBuilder b = new StringBuilder();
		for (StandardEntry entry : standardFields) {
			int value = entry.value;
			String key = entry.key;
			String description = entry.description;
			if (key.equals("MAGIC_NUMBER")) {
				b.append(description + ": " + value + " --> "
						+ getMagicNumberString(value) + NEWLINE);
			} else if (key.equals("BASE_OF_DATA")) {
				if (magicNumber == PE32) {
					b.append(description + ": " + value + " (0x"
							+ Integer.toHexString(value) + ")" + NEWLINE);
				}
			} else {
				b.append(description + ": " + value + " (0x"
						+ Integer.toHexString(value) + ")" + NEWLINE);
			}
		}
		return b.toString();
	}

	private int getMagicNumber(Map<String, String[]> standardSpec) {
		int offset = Integer.parseInt(standardSpec.get("MAGIC_NUMBER")[1]);
		int length = Integer.parseInt(standardSpec.get("MAGIC_NUMBER")[2]);
		return getBytesIntValue(headerbytes, offset, length);
	}

	private String getMagicNumberString(int magicNumber) {
		switch (magicNumber) {
		case PE32:
			return "PE32, normal executable file";
		case PE32_PLUS:
			return "PE32+ executable";
		case ROM:
			return "ROM image";
		default:
			throw new IllegalArgumentException(
					"unable to recognize magic number");
		}
	}

	private String getImageBaseDescription(int value) {
		switch (value) {
		case 0x10000000:
			return "DLL default";
		case 0x00010000:
			return "default for Windows CE EXEs";
		case 0x00400000:
			return "default for Windows NT, 2000, XP, 95, 98 and Me";
		default:
			return "no default value";
		}
	}

	private String getSubsystemDescription(int value) {
		try {
			Map<String, String[]> map = FileIO.readMap("subsystem");
			return map.get(String.valueOf(value))[1];
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
