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
		int offsetLoc = 1;
		int lengthLoc = 2;

		for (Entry<String, String[]> entry : standardSpec.entrySet()) {
			String[] specs = entry.getValue();
			int value = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offsetLoc]),
					Integer.parseInt(specs[lengthLoc]));
			String key = entry.getKey();
			standardFields
					.add(new StandardEntry(key, specs[description], value));
		}

	}

	private void loadDataDirectories(List<String[]> datadirSpec) {
		dataDirEntries = new LinkedList<>();
		final int description = 0;
		int offsetLoc;
		int length = 4; //the actual length

		if (magicNumber == PE32) {
			offsetLoc = 1;
		} else if (magicNumber == PE32_PLUS) {
			offsetLoc = 2;
		} else {
			return; // no fields
		}

		int counter = 0;
		for (String[] specs : datadirSpec) {
			if (counter >= rvaNumber) {
				break;
			}
			int address = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offsetLoc]),
					length);
			int size = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offsetLoc]) + length,
					length);
			if (address != 0) {
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
		return "---------------" + NL + "Optional Header" + NL
				+ "---------------" + NL + NL + "Standard fields" + NL
				+ "..............." + NL + NL + getStandardFieldsInfo() + NL
				+ "Windows specific fields" + NL + "......................."
				+ NL + NL + getWindowsSpecificInfo() + NL + "Data directories"
				+ NL + "................" + NL + NL + "virtual_address/size"
				+ NL + NL + getDataDirInfo();
	}

	public String getDataDirInfo() {
		StringBuilder b = new StringBuilder();
		for (DataDirEntry entry : dataDirEntries) {
			b.append(entry.fieldName + ": " + entry.virtualAddress + "(0x"
					+ Integer.toHexString(entry.virtualAddress) + ")/"
					+ entry.size + "(0x"
					+ Integer.toHexString(entry.size) + ")" + NL);
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
		for (StandardEntry entry : windowsFields) {
			int value = entry.value;
			String key = entry.key;
			String description = entry.description;
			if (key.equals("IMAGE_BASE")) {
				b.append(description + ": " + value + " (0x"
						+ Integer.toHexString(value) + "), "
						+ getImageBaseDescription(value) + NL);
			} else if (key.equals("SUBSYSTEM")) {
				b.append(description + ": " + getSubsystemDescription(value)
						+ NL);
			} else if (key.equals("DLL_CHARACTERISTICS")) {
				b.append(NL + description + ": " + NL);
				b.append(getCharacteristics(value, "dllcharacteristics") + NL);
			}

			else {
				b.append(description + ": " + value + " (0x"
						+ Integer.toHexString(value) + ")" + NL);
				if (key.equals("NUMBER_OF_RVA_AND_SIZES")) {
					rvaNumber = value;
				}
			}
		}
		return b.toString();
	}

	public String getStandardFieldsInfo() {
		StringBuilder b = new StringBuilder();
		for (StandardEntry entry : standardFields) {
			int value = entry.value;
			String key = entry.key;
			String description = entry.description;
			if (key.equals("MAGIC_NUMBER")) {
				b.append(description + ": " + value + " --> "
						+ getMagicNumberString(value) + NL);
			} else if (key.equals("BASE_OF_DATA")) {
				if (magicNumber == PE32) {
					b.append(description + ": " + value + " (0x"
							+ Integer.toHexString(value) + ")" + NL);
				}
			} else {
				b.append(description + ": " + value + " (0x"
						+ Integer.toHexString(value) + ")" + NL);
			}
		}
		return b.toString();
	}

	public int getMagicNumber(Map<String, String[]> standardSpec) {
		int offset = Integer.parseInt(standardSpec.get("MAGIC_NUMBER")[1]);
		int length = Integer.parseInt(standardSpec.get("MAGIC_NUMBER")[2]);
		return getBytesIntValue(headerbytes, offset, length);
	}

	public static String getMagicNumberString(int magicNumber) {
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

	public static String getImageBaseDescription(int value) {
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

	public static String getSubsystemDescription(int value) {
		try {
			Map<String, String[]> map = FileIO.readMap("subsystem");
			return map.get(String.valueOf(value))[1];
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
