/*******************************************************************************
 * Copyright 2014 Katja Hahn
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package com.github.katjahahn.parser.sections;

import com.github.katjahahn.parser.Characteristic;

/**
 * Represents the attributes of a section.
 * 
 * @author Katja Hahn
 *
 */
public enum SectionCharacteristic implements Characteristic {
	RESERVED_0("Reserved 0", "Reserved for future use.", true, false),
	RESERVED_1("Reserved 1", "Reserved for future use.", true, false),
	RESERVED_2("Reserved 2", "Reserved for future use.", true, false),
	RESERVED_4("Reserved 4", "Reserved for future use.", true, false),
	IMAGE_SCN_TYPE_NO_PAD("No Pad", "The section should not be padded to the next boundary. DEPRECATED", false, true),
	RESERVED_10("Reserved 10", "Reserved for future use.", true, false),
	IMAGE_SCN_CNT_CODE("Code", "The section contains executable code."),
	IMAGE_SCN_CNT_INITIALIZED_DATA("Initialized Data", "The section contains initialized data."),
	IMAGE_SCN_CNT_UNINITIALIZED_DATA("Uninitialized Data", "The section contains uninitialized data."),
	IMAGE_SCN_LNK_OTHER("Lnk Other (reserved)", "Reserved for future use.", true, false),
	IMAGE_SCN_LNK_INFO("Lnk Info", "The section contains comments or other information. Valid for object files only."),
	RESERVED_400("Reserved 400","Reserved for future use.", true, false),
	IMAGE_SCN_LNK_REMOVE("Lnk Remove", "The section will not become part of the image. Valid for object files only."),
	IMAGE_SCN_LNK_COMDAT("COMDAT data", "The section contains COMDAT data."),
	IMAGE_SCN_GPREL("Global Pointer Ref.","The section contains data referenced through the global pointer (GP)."),
	IMAGE_SCN_MEM_PURGEABLE("Purgeable (reserved)","Reserved for future use.", true, false),
	IMAGE_SCN_MEM_16BIT("Mem 16 Bit (reserved)", "For ARM machine types, the section contains Thumb code. Reserved for future use with other machine types.", true, false),
	IMAGE_SCN_MEM_LOCKED("Mem Locked (reserved)", "Reserved for future use.", true, false),
	IMAGE_SCN_MEM_PRELOAD("Preload (reserved)", "Reserved for future use.", true, false),
	IMAGE_SCN_ALIGN_1BYTES("Align 1 Byte","Align data on a 1-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_2BYTES("Align 2 Bytes", "Align data on a 2-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_4BYTES("Align 4 Bytes", "Align data on a 4-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_8BYTES("Align 8 Bytes", "Align data on a 8-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_16BYTES("Align 16 Bytes", "Align data on a 16-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_32BYTES("Align 32 Bytes", "Align data on a 32-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_64BYTES("Align 64 Bytes", "Align data on a 64-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_128BYTES("Align 128 Bytes", "Align data on a 128-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_256BYTES("Align 256 Bytes", "Align data on a 256-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_512BYTES("Align 512 Bytes", "Align data on a 512-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_1024BYTES("Align 1024 Bytes", "Align data on a 1024-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_2048BYTES("Align 2048 Bytes", "Align data on a 2048-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_4096BYTES("Align 4096 Bytes", "Align data on a 4096-byte boundary. Valid only for object files."),
	IMAGE_SCN_ALIGN_8192BYTES("Align 8192 Bytes", "Align data on a 8192-byte boundary. Valid only for object files."),
	IMAGE_SCN_LNK_NRELOC_OVFL("Extended Relocations", "The section contains extended relocations."),
	IMAGE_SCN_MEM_DISCARDABLE("Discardable","The section can be discarded as needed."),
	IMAGE_SCN_MEM_NOT_CACHED("Not Cached","The section cannot be cached."),
	IMAGE_SCN_MEM_NOT_PAGED("Not Pageable", "The section is not pageable."),
	IMAGE_SCN_MEM_SHARED("Shared", "The section can be shared in memory."),
	IMAGE_SCN_MEM_EXECUTE("Execute", "The section can be executed as code."),
	IMAGE_SCN_MEM_READ("Read", "The section can be read."),
	IMAGE_SCN_MEM_WRITE("Write", "The section can be written to.");

	private String shortName;
	private String description;
	private boolean deprecated;
	private boolean reserved;
	
	private SectionCharacteristic(String shortName, String description) {
	    this.shortName = shortName;
		this.description = description;
		this.reserved = false;
		this.deprecated = false;
	}
	
	private SectionCharacteristic(String shortName, String description, boolean reserved, boolean deprecated) {
		this.shortName = shortName;
	    this.description = description;
		this.reserved = reserved;
		this.deprecated = deprecated;
	}
	
	public String shortName() {
	    return shortName;
	}
	
	/**
	 * Returns the description of the section characteristic.
	 * 
	 * @return description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isReserved() {
		return reserved;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isDeprecated() {
		return deprecated;
	}
}
