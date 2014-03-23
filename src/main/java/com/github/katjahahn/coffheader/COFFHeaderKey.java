package com.github.katjahahn.coffheader;

import com.github.katjahahn.HeaderKey;

/**
 * Keys for entries you can read from the COFF File Header
 * 
 * @author Katja Hahn
 *
 */
public enum COFFHeaderKey implements HeaderKey {

	MACHINE, SECTION_NR, TIME_DATE, SIZE_OF_OPT_HEADER, CHARACTERISTICS;
}
