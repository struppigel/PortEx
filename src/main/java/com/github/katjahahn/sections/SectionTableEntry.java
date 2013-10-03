package com.github.katjahahn.sections;

import java.util.HashMap;

import com.github.katjahahn.StandardEntry;

public class SectionTableEntry {

	private final HashMap<SectionTableEntryKey, StandardEntry> entries = new HashMap<>();
	private String name;

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public Integer get(SectionTableEntryKey key) {
		return entries.get(key).value;
	}

	public void add(StandardEntry entry) {
		SectionTableEntryKey entryKey = SectionTableEntryKey.valueOf(entry.key);
		if (entryKey != null) {
			entries.put(entryKey, entry);
		} else {
			throw new IllegalArgumentException("invalid key"); //TODO maybe new StandardEntry class
		}
	}

}
