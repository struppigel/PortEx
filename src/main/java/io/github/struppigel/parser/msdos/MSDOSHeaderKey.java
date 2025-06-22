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
package io.github.struppigel.parser.msdos;

import io.github.struppigel.parser.HeaderKey;

/**
 * Keys for the MSDOS Header values
 * 
 * @author Katja Hahn
 * 
 */
public enum MSDOSHeaderKey implements HeaderKey {
    /**
     * 'MZ' signature
     */
    SIGNATURE_WORD,
    /**
     * Number of bytes in last 512-byte page of executable
     */
    LAST_PAGE_SIZE,
    /**
     * Total number of 512-byte pages in executable, including last page
     */
    FILE_PAGES,
    /**
     * Number of relocation entries
     */
    RELOCATION_ITEMS,
    /**
     * Header size in paragraphs
     */
    HEADER_PARAGRAPHS,
    /**
     * Minimum paragraphs of memory allocated in addition to the code size
     */
    MINALLOC,
    /**
     * Maximum number of paragraphs allocated in addition to the code size
     */
    MAXALLOC,
    /**
     * Initial SS relative to start of executable
     */
    INITIAL_SS,
    /**
     * Initial SP
     */
    INITIAL_SP,
    /**
     * Checksum (or 0) of executable
     */
    COMPLEMENTED_CHECKSUM,
    /**
     * IP relative to start of executable (entry point)
     */
    INITIAL_IP,
    /**
     * CS relative to start of executable (entry point)
     */
    PRE_RELOCATED_INITIAL_CS,
    /**
     * Offset of relocation table
     */
    RELOCATION_TABLE_OFFSET,
    /**
     * Overlay number
     */
    OVERLAY_NR, 
    /**
     * Rich Header
     */
    E_RESERVED28, E_RESERVED30, E_RESERVED32, E_RESERVED34, 
    E_OEMID, E_OEMINFO, E_RESERVED40, E_RESERVED42, E_RESERVED44, E_RESERVED46, 
    E_RESERVED48, E_RESERVED50, E_RESERVED52, E_RESERVED54, E_RESERVED56, 
    E_RESERVED58, 
    /**
     * PE Signature offset
     */
    E_LFANEW;
}
