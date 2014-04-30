package com.github.katjahahn.sections;

import com.github.katjahahn.Characteristic;

public enum SectionCharacteristic implements Characteristic {
	RESERVED_0("Reserved for future use."),
	RESERVED_1("Reserved for future use."),
	RESERVED_2("Reserved for future use."),
	RESERVED_4("Reserved for future use."),
	IMAGE_SCN_TYPE_NO_PAD("The section should not be padded to the next boundary. DEPRECATED"),
	RESERVED_10("Reserved for future use."),
	IMAGE_SCN_CNT_CODE("The section contains executable code."),
	IMAGE_SCN_CNT_INITIALIZED_DATA("The section contains initialized data."),
	IMAGE_SCN_CNT_UNINITIALIZED_DATA("The section contains uninitialized data."),
	IMAGE_SCN_LNK_OTHER("Reserved for future use."),
	IMAGE_SCN_LNK_INFO("The section contains comments or other information. Valid for object files only."),
	RESERVED_400("Reserved for future use."),
	IMAGE_SCN_LNK_REMOVE("The section will not become part of the image. Valid for object files only."),
	IMAGE_SCN_LNK_COMDAT("The section contains COMDAT data."),
	IMAGE_SCN_GPREL("The section contains data referenced through the global pointer (GP)."),
	IMAGE_SCN_MEM_PURGEABLE("Reserved for future use."),
	IMAGE_SCN_MEM_16BIT("For ARM machine types, the section contains Thumb code. Reserved for future use with other machine types."),
	IMAGE_SCN_MEM_LOCKED("Reserved for future use."),
	IMAGE_SCN_MEM_PRELOAD("Reserved for future use."),
	IMAGE_SCN_ALIGN_1BYTES("Align data on a 1-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_2BYTES("Align data on a 2-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_4BYTES("Align data on a 4-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_8BYTES("Align data on a 8-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_16BYTES("Align data on a 16-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_32BYTES("Align data on a 32-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_64BYTES("Align data on a 64-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_128BYTES("Align data on a 128-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_256BYTES("Align data on a 256-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_512BYTES("Align data on a 512-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_1024BYTES("Align data on a 1024-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_2048BYTES("Align data on a 2048-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_4096BYTES("Align data on a 4096-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_8192BYTES("Align data on a 8192-byte boundary. Valid only for object files."),
	IMAGE_SCN_LNK_NRELOC_OVFL("The section contains extended relocations."),
	IMAGE_SCN_MEM_DISCARDABLE("The section can be discarded as needed."),
	IMAGE_SCN_MEM_NOT_CACHED("The section cannot be cached."),
	IMAGE_SCN_MEM_NOT_PAGED("The section is not pageable."),
	IMAGE_SCN_MEM_SHARED("The section can be shared in memory."),
	IMAGE_SCN_MEM_EXECUTE("The section can be executed as code."),
	IMAGE_SCN_MEM_READ("The section can be read."),
	IMAGE_SCN_MEM_WRITE("The section can be written to.");

	private String description;
	
	private SectionCharacteristic(String description) {
		this.description = description;
	}
	
	/**
	 * Returns the description of the section characteristic.
	 * 
	 * @return description
	 */
	public String getDescription() {
		return description;
	}
}
