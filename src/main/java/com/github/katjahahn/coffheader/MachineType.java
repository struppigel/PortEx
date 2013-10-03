package com.github.katjahahn.coffheader;

public enum MachineType {
	UNKNOWN, AM33, AMD64, ARM, ARMV7, EBC, I386, IA64, M32R, MIPS16, MIPSFPU, MIPSFPU16, POWERPC, POWERPCFP, R4000, SH3, SH3DSP, SH4, SH5, THUMB, WCEMIPSV2;
	
	public String getKey() {
		return "IMAGE_FILE_MACHINE_" + this.toString();
	}

}
