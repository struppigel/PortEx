package com.github.katjahahn.pemodules;

public class DataDirEntry {
	
	public String fieldName;
	public int virtualAddress;
	public int size;

	public DataDirEntry(String fieldName, int virtualAddress, int size) {
		this.fieldName = fieldName;
		this.virtualAddress = virtualAddress;
		this.size = size;
	}
}
