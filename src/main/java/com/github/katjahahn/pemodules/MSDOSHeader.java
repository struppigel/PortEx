package com.github.katjahahn.pemodules;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.FileIO;

public class MSDOSHeader extends PEModule {

	private static final byte[] MZ_SIGNATURE = "MZ".getBytes();
	public static final int HEADER_SIZE = 28;
	private static final String specification = "msdosheaderspec";
	private static Map<String, StandardEntry> headerData;

	public MSDOSHeader(byte[] headerbytes) {
		if (hasSignature(headerbytes)) {
			loadHeaderData(headerbytes);
		}
	}

	private boolean hasSignature(byte[] headerbytes) {
		if(headerbytes.length < 28) {
			throw new IllegalArgumentException("not enough headerbytes for MS DOS Header");
		} else {
			for(int i = 0; i < MZ_SIGNATURE.length; i++) {
				if(MZ_SIGNATURE[i] != headerbytes[i]) {
					return false;
				}
			}
			return true;
		}
	}
	
	public List<StandardEntry> getHeaderEntries() {
		return new LinkedList<>(headerData.values());
	}
	
	public StandardEntry get(String keyString) {
		return headerData.get(keyString);
	}

	private void loadHeaderData(byte[] headerbytes) {
		headerData = new HashMap<>();
		int offsetLoc = 0;
		int sizeLoc = 1;
		int descriptionLoc = 2;
		try {
			Map<String, String[]> map = FileIO.readMap(specification);
			for (Entry<String, String[]> entry : map.entrySet()) {
				String key = entry.getKey();
				String[] spec = entry.getValue();
				int value = getBytesIntValue(headerbytes,
						Integer.parseInt(spec[offsetLoc]),
						Integer.parseInt(spec[sizeLoc]));
				headerData.put(key, new StandardEntry(key,
						spec[descriptionLoc], value));
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	@Override
	public String getInfo() {
		if (headerData == null) {
			return "No MS DOS Header found!" + NL;
		} else {
			StringBuilder b = new StringBuilder("-------------" + NL
					+ "MS DOS Header" + NL + "-------------" + NL);
			for (StandardEntry entry : headerData.values()) {
				b.append(entry.description + ": " + entry.value + " (0x"
						+ Integer.toHexString(entry.value) + ")" + NL);
			}
			return b.toString();
		}
	}

}
