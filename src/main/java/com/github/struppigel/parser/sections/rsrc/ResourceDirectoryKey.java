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
package com.github.struppigel.parser.sections.rsrc;

import com.github.struppigel.parser.HeaderKey;
import com.github.struppigel.parser.HeaderKey;

/**
 * Represents the header key of a resource directory table.
 * 
 * @author Katja Hahn
 *
 */
public enum ResourceDirectoryKey implements HeaderKey {
	/**
	 * Resource flags. This field is reserved for future use.
	 */
	CHARACTERISTICS, // TODO check as reserved value in anomalies
	/**
	 * The time that the resource data was created by the resource compiler.
	 */
	TIME_DATE_STAMP,
	/**
	 * The major version number, set by the user.
	 */
	MAJOR_VERSION,
	/**
	 * The minor version number, set by the user.
	 */
	MINOR_VERSION,
	/**
	 * The number of directory entries immediately following the table that use
	 * strings to identify Type, Name, or Language entries (depending on the
	 * level of the table).
	 */
	NR_OF_NAME_ENTRIES,
	/**
	 * The number of directory entries immediately following the Name entries
	 */
	NR_OF_ID_ENTRIES;
}
