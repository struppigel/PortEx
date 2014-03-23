package com.github.katjahahn.sections;

import com.github.katjahahn.HeaderKey;

public enum SectionTableEntryKey implements HeaderKey {
	
	NAME, VIRTUAL_ADDRESS, VIRTUAL_SIZE, SIZE_OF_RAW_DATA, POINTER_TO_RAW_DATA, 
	POINTER_TO_RELOCATIONS, POINTER_TO_LINE_NUMBERS, NUMBER_OF_RELOCATIONS,
	NUMBER_OF_LINE_NUMBERS, CHARACTERISTICS;

}
