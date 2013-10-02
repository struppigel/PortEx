package com.github.katjahahn.pemodules.sections;

import java.util.HashMap;

import com.github.katjahahn.pemodules.StandardEntry;

public class SectionTableEntry {
	
	private final HashMap<String, StandardEntry> entries = new HashMap<>();
	private String name;

	public void setName(String name) {
		this.name = name;
	}
	
	public String getName() {
		return name;
	}
	
	public Integer get(String key) {
		return entries.get(key).value;
	}

	public void add(StandardEntry entry) {
		entries.put(entry.key, entry);
	}
	
}
