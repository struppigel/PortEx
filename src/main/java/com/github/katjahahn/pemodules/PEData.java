package com.github.katjahahn.pemodules;


public class PEData extends PEModule {
	
	private final MSDOSHeader msdos;
	private final COFFFileHeader coff;
	private final OptionalHeader opt;
	private final SectionTable table;

	public PEData(MSDOSHeader msdos, COFFFileHeader coff, OptionalHeader opt, SectionTable table) {
		this.msdos = msdos;
		this.coff = coff;
		this.opt = opt;
		this.table = table;
	}
	
	public MSDOSHeader getMSDOSHeader() {
		return msdos;
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

	@Override
	public String getInfo() {
		//TODO
		return null;
	}

}
