package com.github.katjahahn.parser.sections.rsrc.version;

import com.github.katjahahn.parser.Characteristic;

public enum FileOS implements Characteristic {
	VOS_DOS      ("MS-DOS",         0x00010000L),
	VOS_NT       ("Windows NT",     0x00040000L),
	VOS_WINDOWS16("16-bit Windows", 0x00000001L),
	VOS_WINDOWS32("32-bit Windows", 0x00000004L),
	VOS_OS216    ("16-bit OS/2",    0x00020000L),
	VOS_OS232    ("32-bit OS/2",    0x00030000L),
	VOS_PM16     ("16-bit Presentation Manager",    0x00000002L),
	VOS_PM32     ("32-bit Presentation Manager",    0x00000003L),
	VOS_UNKNOWN  ("Uknown", 0L);
	
    private String description;
    private long value;

    private FileOS(String description, long value) {
        this.description = description;
        this.value = value;
    }

	@Override
	public boolean isReserved() {
		return false;
	}

	@Override
	public boolean isDeprecated() {
		return false;
	}

	@Override
	public String getDescription() {
		return description;
	}

	@Override
	public long getValue() {
		return value;
	}
    
    
}
