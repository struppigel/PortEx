package com.github.katjahahn;

/**
 * A data class for a typical entry of PE Headers
 * 
 * @author Katja Hahn
 *
 */
public class StandardEntry {

	public String key;
	public String description;
	public long value;

	/**
	 * @constructor Creates a standard entry with the values specified.
	 * 
	 * @param key
	 * @param description
	 * @param value
	 */
	public StandardEntry(String key, String description, long value) {
		this.key = key;
		this.description = description;
		this.value = value;
	}

	@Override
	public String toString() {
		return description + ": " + value + " (0x" + Long.toHexString(value)
				+ ")";
	}
}
