package com.github.katjahahn.pemodules;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.FileIO;

public class OptionalHeader extends PEModule {

	private static final String STANDARD_SPEC = "optionalheaderstandardspec";
	private static final String WINDOWS_SPEC = "optionalheaderwinspec";
	private static final String DATA_DIR_SPEC = "datadirectoriesspec";

	/* Magic number values */
	private static final int PE32 = 0x10B;
	private static final int PE32_PLUS = 0x20B;
	private static final int ROM = 0x107;

	private final byte[] headerbytes;
	private Map<String, String[]> standardSpec;
	private Map<String, String[]> windowsSpec;
	private List<String[]> datadirSpec;
	private int magicNumber;
	private int rvaNumber;

	public OptionalHeader(byte[] headerbytes) {
		this.headerbytes = headerbytes;
		try {
			standardSpec = FileIO.readMap(STANDARD_SPEC);
			windowsSpec = FileIO.readMap(WINDOWS_SPEC);
			datadirSpec = FileIO.readArray(DATA_DIR_SPEC);
		} catch (NumberFormatException | IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public String getInfo() {
		return "Standard fields" + NEWLINE + "..............." + NEWLINE
				+ NEWLINE + getStandardFields() + NEWLINE
				+ "Windows specific fields" + NEWLINE
				+ "......................." + NEWLINE + NEWLINE
				+ getWindowsSpecificFields() + NEWLINE + "Data directories"
				+ NEWLINE + "................" + NEWLINE + NEWLINE
				+ "virtual_address/size" + NEWLINE + NEWLINE
				+ getDataDirectories();
	}

	private String getDataDirectories() {
		StringBuilder b = new StringBuilder();
		final int description = 0;
		int offset;
		int length = 3;

		if (magicNumber == PE32) {
			offset = 1;
		} else if (magicNumber == PE32_PLUS) {
			offset = 2;
		} else {
			return "no fields";
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
				b.append(specs[description] + ": " + address + "(0x"
						+ Integer.toHexString(address) + ")/" + size + NEWLINE);
			}
			counter++;
		}
		return b.toString();
	}

	/**
	 * Returns a string with description of the windows specific header fields.
	 * Magic number must be set.
	 * 
	 * @return string with windows specific fields
	 */
	private String getWindowsSpecificFields() {

		final int description = 0;
		int offset;
		int length;

		if (magicNumber == PE32) {
			offset = 1;
			length = 3;
		} else if (magicNumber == PE32_PLUS) {
			offset = 2;
			length = 4;
		} else {
			return "no fields";
		}
		return buildWindowsFieldsString(description, offset, length);
	}

	private String buildWindowsFieldsString(final int description, int offset,
			int length) {
		StringBuilder b = new StringBuilder();
		for (Entry<String, String[]> entry : windowsSpec.entrySet()) {
			String[] specs = entry.getValue();
			int value = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offset]),
					Integer.parseInt(specs[length]));
			String key = entry.getKey();
			if (key.equals("IMAGE_BASE")) {
				b.append(specs[description] + ": " + value + " (0x"
						+ Integer.toHexString(value) + "), "
						+ getImageBaseDescription(value) + NEWLINE);
			} else if (key.equals("SUBSYSTEM")) {
				b.append(specs[description] + ": "
						+ getSubsystemDescription(value) + NEWLINE);
			} else if (key.equals("DLL_CHARACTERISTICS")) {
				b.append(NEWLINE + specs[description] + ": " + NEWLINE);
				b.append(getCharacteristics(value, "dllcharacteristics") + NEWLINE);
			}

			else {
				b.append(specs[description] + ": " + value + " (0x"
						+ Integer.toHexString(value) + ")" + NEWLINE);
				if (key.equals("NUMBER_OF_RVA_AND_SIZES")) {
					rvaNumber = value;
				}
			}
		}
		return b.toString();
	}

	private String getStandardFields() {
		StringBuilder b = new StringBuilder();
		int description = 0;
		int offset = 1;
		int length = 2;
		for (Entry<String, String[]> entry : standardSpec.entrySet()) {

			String[] specs = entry.getValue();
			int value = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offset]),
					Integer.parseInt(specs[length]));
			String key = entry.getKey();
			if (key.equals("MAGIC_NUMBER")) {
				b.append(specs[description] + ": " + value + " --> "
						+ getMagicNumberString(value) + NEWLINE);
			} else if (key.equals("BASE_OF_DATA")) {
				this.magicNumber = getMagicNumber();
				if (magicNumber == PE32) {
					b.append(specs[description] + ": " + value + " (0x"
							+ Integer.toHexString(value) + ")" + NEWLINE);
				}
			} else {
				b.append(specs[description] + ": " + value + " (0x"
						+ Integer.toHexString(value) + ")" + NEWLINE);
			}
		}
		return b.toString();
	}

	private int getMagicNumber() {
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
			return "ERROR, unable to recognize magic number";
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
		return "ERROR, no subsystem description for value: " + value;
	}
}
