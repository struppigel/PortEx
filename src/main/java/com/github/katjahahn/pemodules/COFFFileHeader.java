package com.github.katjahahn.pemodules;

import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.FileIO;

public class COFFFileHeader extends PEModule {

	public static final String COFF_SPEC_FILE = "coffheaderspec";
	public static final int HEADER_SIZE = 20;

	private final byte[] headerbytes;
	private Map<String, String[]> specification;

	public COFFFileHeader(byte[] headerbytes) {
		assert headerbytes.length == HEADER_SIZE;
		this.headerbytes = headerbytes;
		try {
			specification = FileIO.readMap(COFF_SPEC_FILE);
		} catch (NumberFormatException | IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder();
		for (Entry<String, String[]> entry : specification.entrySet()) {

			String[] specs = entry.getValue();
			int value = getBytesIntValue(headerbytes, Integer.parseInt(specs[1]),
					Integer.parseInt(specs[2]));
			String key = entry.getKey();
			if (key.equals("CHARACTERISTICS")) {
				b.append(NEWLINE + specs[0] + ": " + NEWLINE);
				b.append(getCharacteristics(value, "characteristics") + NEWLINE);
			} else if (key.equals("TIME_DATE")) {
				b.append(specs[0] + ": ");
				b.append(getTimeDate(value) + NEWLINE);
			} else if (key.equals("MACHINE")) {
				b.append(specs[0] + ": ");
				b.append(getMachineType(value) + NEWLINE);
			} else {
				b.append(specs[0] + ": " + value + NEWLINE);
			}
		}
		return b.toString();
	}

	private String getMachineType(int value) {
		try {
			Map<String, String[]> map = FileIO.readMap("machinetype");
			String key = Integer.toHexString(value);
			String[] ret = map.get(key);
			if (ret != null) {
				return ret[1];
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return "ERROR: couldn't match type to value " + value;
	}

	private Date getTimeDate(int seconds) {
		long millis = (long) seconds * 1000;
		return new Date(millis);
	}
	
	public int get(String key) {
		String[] specs = specification.get(key);
		int value = getBytesIntValue(headerbytes, Integer.parseInt(specs[1]),
				Integer.parseInt(specs[2]));
		return value;
	}

	public int getSizeOfOptionalHeader() {
		return get("SIZE_OF_OPT_HEADER");
	}

	public int getNumberOfSections() {
		return get("SECTION_NR");
	}

}
