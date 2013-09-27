package com.github.katjahahn.pemodules;

import java.util.Arrays;

public class SectionSummary extends PEModule {

	private final byte[] filebytes;
	private RSRCSection rsrc;
	private final SectionTable table;
	private final int virtualRSRCAddress;

	public SectionSummary(byte[] filebytes, SectionTable table, int virtualRSRCAddress) {
		this.filebytes = filebytes;
		this.table = table;
		this.virtualRSRCAddress = virtualRSRCAddress;
	}

	@Override
	public String getInfo() {
		long pointer = table.getPointerToRawData(".rsrc");
		byte[] rsrcbytes = Arrays.copyOfRange(filebytes, (int) pointer,
				filebytes.length);
		rsrc = new RSRCSection(rsrcbytes, filebytes, virtualRSRCAddress);
		return ".rsrc section" + NEWLINE + "............." + NEWLINE + NEWLINE
				+ rsrc.getInfo();
	}

}
