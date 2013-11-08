package com.github.katjahahn;

public class StandardEntry {

	public String key;
	public String description;
	public int value;

	public StandardEntry(String key, String description, int value) {
		this.key = key;
		this.description = description;
		this.value = value;
	}

	@Override
	public String toString() {
		return description + ": " + value + " (0x" + Integer.toHexString(value)
				+ ")";
	}
}
