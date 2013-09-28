package com.github.katjahahn.pemodules;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.FileIO;

public class SectionTable extends PEModule {

	private final static String SECTION_TABLE_SPEC = "sectiontablespec";
	public final static int ENTRY_SIZE = 40;

	private final byte[] sectionTableBytes;
	private final int numberOfEntries;
	private Map<String, String[]> specification;

	public SectionTable(byte[] sectionTableBytes, int numberOfEntries) {
		this.sectionTableBytes = sectionTableBytes;
		this.numberOfEntries = numberOfEntries;
		try {
			specification = FileIO.readMap(SECTION_TABLE_SPEC);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public Integer getPointerToRawData(String sectionName) {
		for (int i = 0; i < numberOfEntries; i++) {
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			if (isSection(sectionName, section)) {
				return getPointerToRawData(section);
			}
		}

		return null;
	}

	private Integer getPointerToRawData(byte[] section) {
		for (Entry<String, String[]> entry : specification.entrySet()) {
			if(entry.getKey().equals("POINTER_TO_RAW_DATA")) {
				String[] specs = entry.getValue();
				int value = getBytesIntValue(section, Integer.parseInt(specs[1]),
						Integer.parseInt(specs[2]));
				return value;
			}
		}
		return null;
	}

	private boolean isSection(String sectionName, byte[] section) {
		for (String key : specification.keySet()) {
			if (key.equals("NAME")
					&& getUTF8String(section).equals(sectionName)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder();

		for (int i = 0; i < numberOfEntries; i++) {
			b.append("entry number " + (i + 1) + ": " + NEWLINE
					+ "..............." + NEWLINE + NEWLINE);
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			b.append(getNextEntryInfo(section) + NEWLINE);
		}

		return b.toString();
	}

	private String getNextEntryInfo(byte[] section) {
		StringBuilder b = new StringBuilder();
		for (Entry<String, String[]> entry : specification.entrySet()) {

			String[] specs = entry.getValue();
			long value = getBytesLongValue(section, Integer.parseInt(specs[1]),
					Integer.parseInt(specs[2]));
			String key = entry.getKey();
			if (key.equals("CHARACTERISTICS")) {
				b.append(specs[0] + ": " + NEWLINE
						+ getCharacteristics(value, "sectioncharacteristics")
						+ NEWLINE);
			} else if (key.equals("NAME")) {
				b.append(specs[0] + ": " + getUTF8String(section) + NEWLINE);

			} else {
				b.append(specs[0] + ": " + value + " (0x"
						+ Long.toHexString(value) + ")" + NEWLINE);
			}
		}
		return b.toString();
	}

	private String getUTF8String(byte[] section) {
		String[] values = specification.get("NAME");
		int from = Integer.parseInt(values[1]);
		int to = from + Integer.parseInt(values[2]);
		byte[] bytes = Arrays.copyOfRange(section, from, to);
		try {
			return new String(bytes, "UTF8").trim();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "ERROR";
	}

	public Integer getVirtualAddress(String sectionName) {
		for (int i = 0; i < numberOfEntries; i++) {
			byte[] section = Arrays.copyOfRange(sectionTableBytes, i
					* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
			if (isSection(sectionName, section)) {
				return getVirtualAddress(section);
			}
		}
		return null;
	}

	private Integer getVirtualAddress(byte[] section) {
		for (Entry<String, String[]> entry : specification.entrySet()) {
			if(entry.getKey().equals("VIRTUAL_ADDRESS")) {
				String[] specs = entry.getValue();
				int value = getBytesIntValue(section, Integer.parseInt(specs[1]),
						Integer.parseInt(specs[2]));
				return value;
			}
		}
		return null;
	}
	
	// TODO not tested and it is almost the same code as getPointerToRawData
		public Integer getSize(String sectionName) {
			for (int i = 0; i < numberOfEntries; i++) {
				byte[] section = Arrays.copyOfRange(sectionTableBytes, i
						* ENTRY_SIZE, i * ENTRY_SIZE + ENTRY_SIZE);
				if (isSection(sectionName, section)) {
					return getSizeOfRawData(section);
				}
			}

			return null;
		}

		public Integer getSizeOfRawData(byte[] section) {
			for (Entry<String, String[]> entry : specification.entrySet()) {
				if (entry.getKey().equals("SIZE_OF_RAW_DATA")) {
					String[] specs = entry.getValue();
					int value = getBytesIntValue(section,
							Integer.parseInt(specs[1]), Integer.parseInt(specs[2]));
					return value;
				}
			}
			return null;
		}

}
