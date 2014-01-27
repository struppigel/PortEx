package com.github.katjahahn;

import com.github.katjahahn.coffheader.COFFFileHeader;
import com.github.katjahahn.msdos.MSDOSHeader;
import com.github.katjahahn.optheader.OptionalHeader;
import com.github.katjahahn.sections.SectionTable;

/**
 * Data class that collects and holds the main information of a PE file. It is 
 * usually constructed by the PELoader.
 * 
 * @author Katja Hahn
 *
 */
public class PEData {
	
	private final PESignature pesig;
	private final COFFFileHeader coff;
	private final OptionalHeader opt;
	private final SectionTable table;
	private final MSDOSHeader msdos;

	public PEData(MSDOSHeader msdos, PESignature pesig, COFFFileHeader coff, OptionalHeader opt, SectionTable table) {
		this.pesig = pesig;
		this.coff = coff;
		this.opt = opt;
		this.msdos = msdos;
		this.table = table;
	}
	
	public MSDOSHeader getMSDOSHeader() {
		return msdos;
	}
	
	public PESignature getPESignature() {
		return pesig;
	}
	
	public SectionTable getSectionTable() {
		return table;
	}
	
	public COFFFileHeader getCOFFFileHeader() {
		return coff;
	}
	
	public OptionalHeader getOptionalHeader() {
		return opt;
	}

}
