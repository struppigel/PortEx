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
package com.github.katjahahn.sections.edata;

import com.github.katjahahn.HeaderKey;

/**
 * 
 * @author Katja Hahn
 *
 * Header keys for the {@link ExportDirTable}
 *
 */
public enum ExportDirTableKey implements HeaderKey {

	EXPORT_FLAGS, TIME_DATE_STAMP, MAJOR_VERSION, MINOR_VERSION, NAME_RVA, 
	ORDINAL_BASE, ADDR_TABLE_ENTRIES, NR_OF_NAME_POINTERS, 
	EXPORT_ADDR_TABLE_RVA, NAME_POINTER_RVA, ORDINAL_TABLE_RVA;

}
