package com.github.katjahahn.pemodules.sections;

import com.github.katjahahn.pemodules.PEModule;

public class PESection extends PEModule {

	private byte[] sectionbytes;
	
	protected PESection() {}

	public PESection(byte[] sectionbytes) {
		this.sectionbytes = sectionbytes;
	}
	
	public byte[] getDump() {
		return sectionbytes;
	}

	@Override
	public String getInfo() {
		return null;
	}

}
