package com.github.katjahahn.parser.sections.rsrc.version;

public enum FontFileSubtype implements FileSubtype {
	
	VFT2_FONT_RASTER ("raster", 1L),
	VFT2_FONT_TRUETYPE ("TrueType font", 3L),
	VFT2_FONT_VECTOR ("vector font", 2L),
	VFT2_UNKNOWN("unknown font type", 0L);
	
	private String description;
    private long value;

    private FontFileSubtype(String description, long value) {
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
