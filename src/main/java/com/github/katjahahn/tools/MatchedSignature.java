package com.github.katjahahn.tools;

public class MatchedSignature {
	
	public long address;
	public String signature;
	public String name;
	public boolean epOnly;

	public MatchedSignature(long address, String signature, String name, boolean epOnly) {
		this.address = address;
		this.name = name;
		this.signature = signature;
		this.epOnly = epOnly;
	}
}
