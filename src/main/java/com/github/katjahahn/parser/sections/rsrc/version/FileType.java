package com.github.katjahahn.parser.sections.rsrc.version;

import com.github.katjahahn.parser.Characteristic;

public enum FileType implements Characteristic {
	
	VFT_APP ( "application", 1L ),
	VFT_DLL ("DLL", 2L),
	VFT_DRV ("device driver", 3L),
	VFT_FONT ("font", 4L),
	VFT_STATIC_LIB ("static-link library", 7L),
	VFT_UNKNOWN ("unknown", 0L),
	VFT_VXD ("virtual device", 5L);

	private String description;
    private long value;

    private FileType(String description, long value) {
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
