package com.github.katjahahn.pemodules;

import java.io.IOException;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.FileIO;

public class COFFFileHeader extends PEModule {

	public static final String COFF_SPEC_FILE = "coffheaderspec";
	public static final int HEADER_SIZE = 20;

	private final byte[] headerbytes;
	private List<StandardEntry> data;

	public COFFFileHeader(byte[] headerbytes) {
		assert headerbytes.length == HEADER_SIZE;
		this.headerbytes = headerbytes;
		try {
			Map<String, String[]> specification = FileIO
					.readMap(COFF_SPEC_FILE);
			loadData(specification);
		} catch (NumberFormatException | IOException e) {
			e.printStackTrace();
		}
	}

	private void loadData(Map<String, String[]> specification) {
		data = new LinkedList<>();
		int description = 0;
		int offset = 1;
		int length = 2;
		for (Entry<String, String[]> entry : specification.entrySet()) {

			String[] specs = entry.getValue();
			int value = getBytesIntValue(headerbytes,
					Integer.parseInt(specs[offset]),
					Integer.parseInt(specs[length]));
			String key = entry.getKey();
			data.add(new StandardEntry(key, specs[description], value));
		}
	}

	@Override
	public String getInfo() {
		StringBuilder b = new StringBuilder("----------------" + NL
				+ "COFF File Header" + NL + "----------------" + NL);
		for (StandardEntry entry : data) {

			int value = entry.value;
			String key = entry.key;
			String description = entry.description;
			if (key.equals("CHARACTERISTICS")) {
				b.append(NL + description + ": " + NL);
				b.append(getCharacteristics(value, "characteristics") + NL);
			} else if (key.equals("TIME_DATE")) {
				b.append(description + ": ");
				b.append(convertToDate(value) + NL);
			} else if (key.equals("MACHINE")) {
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
			Map<String, String[]> map = FileIO.readMap("machinetype");
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

	private Date convertToDate(int seconds) {
		long millis = (long) seconds * 1000;
		return new Date(millis);
	}

	public int get(String key) {
		for (StandardEntry entry : data) {
			if (entry.key.equals(key)) {
				return entry.value;
			}
		}
		throw new IllegalArgumentException("invalid key");
	}

	public static String getDescription(MachineType machine) {
		int description = 1;
		int keyString = 0;
		try {
			Map<String, String[]> map = FileIO.readMap("machinetype");
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

	public String getMachineDescription() {
		return getDescription(getMachineType());
	}

	public int getCharacteristics() {
		return get("CHARACTERISTICS");
	}

	public List<String> getCharacteristicsDescriptions() {
		return PEModule.getCharacteristicsDescriptions(getCharacteristics(),
				"characteristics");
	}

	public MachineType getMachineType() {
		int value = get("MACHINE");
		try {
			Map<String, String[]> map = FileIO.readMap("machinetype");
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

	public Date getTimeDate() {
		return convertToDate(get("TIME_DATE"));
	}

	public int getSizeOfOptionalHeader() {
		return get("SIZE_OF_OPT_HEADER");
	}

	public int getNumberOfSections() {
		return get("SECTION_NR");
	}

}
