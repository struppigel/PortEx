package com.github.katjahahn.parser.sections.rsrc.version;

public class UndefinedSubtype implements FileSubtype {
	
	private long value;
	private boolean reserved;
	
	public UndefinedSubtype(long value) {
		this(value, false);
	}
	
	public UndefinedSubtype(long value, boolean reserved) {
		this.value = value;
		this.reserved = reserved;
	}

	@Override
	public boolean isReserved() {
		return reserved;
	}

	@Override
	public boolean isDeprecated() {
		return false;
	}

	@Override
	public String getDescription() {
		return Long.toString(value);
	}

	@Override
	public long getValue() {
		return value;
	}

}
