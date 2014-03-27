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
package com.github.katjahahn.msdos;

import com.github.katjahahn.HeaderKey;

public enum MSDOSHeaderKey implements HeaderKey {
	SIGNATURE_WORD, LAST_PAGE_SIZE, FILE_PAGES, RELOCATION_ITEMS, 
	HEADER_PARAGRAPHS, MINALLOC, MAXALLOC, INITIAL_SS, INITIAL_SP, 
	COMPLEMENTED_CHECKSUM, INITIAL_IP, PRE_RELOCATED_INITIAL_CS, 
	RELOCATION_TABLE_OFFSET, OVERLAY_NR;
}
