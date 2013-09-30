package com.github.katjahahn.pemodules;


public class PEData extends PEModule {
	
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

	@Override
	public String getInfo() {
		//TODO
		return null;
	}

}
