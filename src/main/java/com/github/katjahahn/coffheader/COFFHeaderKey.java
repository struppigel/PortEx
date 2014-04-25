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
package com.github.katjahahn.coffheader;

import com.github.katjahahn.HeaderKey;

/**
 * Keys for entries you can read from the COFF File Header
 * 
 * @author Katja Hahn
 * 
 */
public enum COFFHeaderKey implements HeaderKey {

	MACHINE, SECTION_NR, TIME_DATE, NR_OF_SYMBOLS, POINTER_TO_SYMB_TABLE, 
	SIZE_OF_OPT_HEADER, CHARACTERISTICS;
}
