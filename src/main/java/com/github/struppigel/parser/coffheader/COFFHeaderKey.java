/*******************************************************************************
 * Copyright 2014 Katja Hahn
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package com.github.struppigel.parser.coffheader;

import com.github.struppigel.parser.HeaderKey;
import com.github.struppigel.parser.HeaderKey;

/**
 * These are the keys for entries you can read from the COFF File Header.
 * 
 * @author Katja Hahn
 * 
 */
public enum COFFHeaderKey implements HeaderKey {
	/**
	 * The number that identifies the type of target machine.
	 * <p>
	 * Prefer to get the machine type as enum
	 * 
	 * @see MachineType
	 * @see COFFFileHeader#getMachineType()
	 */
	MACHINE,
	/**
	 * The number of sections in the file. This indicates the size of the
	 * section table.
	 * 
	 * @see COFFFileHeader#getNumberOfSections()
	 */
	SECTION_NR,
	/**
	 * Indicates when the file was created.
	 */
	TIME_DATE,
	/**
	 * The number of entries in the symbol table. This data can be used to
	 * locate the string table, which immediately follows the symbol table. This
	 * value should be zero for an image because COFF debugging information is
	 * deprecated.
	 */
	NR_OF_SYMBOLS,
	/**
	 * The file offset of the COFF symbol table, or zero if no COFF symbol table
	 * is present. This value should be zero for an image because COFF debugging
	 * information is deprecated.
	 */
	POINTER_TO_SYMB_TABLE,
	/**
	 * Size of optional header. The value determines the beginning of the
	 * section table.
	 */
	SIZE_OF_OPT_HEADER,
	/**
	 * The flags that indicate the attributes of the file.
	 * 
	 * @see COFFFileHeader#getCharacteristics()
	 * @see FileCharacteristic
	 */
	CHARACTERISTICS;
}
