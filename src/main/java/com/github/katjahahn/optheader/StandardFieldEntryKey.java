package com.github.katjahahn.optheader;

import com.github.katjahahn.HeaderKey;

public enum StandardFieldEntryKey implements HeaderKey {
	MAGIC_NUMBER, MAJOR_LINKER_VERSION, MINOR_LINKER_VERSION, SIZE_OF_CODE, 
	SIZE_OF_INIT_DATA, SIZE_OF_UNINIT_DATA, ADDR_OF_ENTRY_POINT, BASE_OF_CODE, 
	BASE_OF_DATA;
}
