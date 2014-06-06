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
package com.github.katjahahn.sections;

import com.github.katjahahn.HeaderKey;

public enum SectionHeaderKey implements HeaderKey {
    /**
     * An 8-byte, null-padded UTF-8 encoded string.
     */
    NAME,
    /**
     * The total size of the section when loaded into memory.
     */
    VIRTUAL_ADDRESS,
    /**
     * For executable images, the address of the first byte of the section
     * relative to the image base when the section is loaded into memory.
     */
    VIRTUAL_SIZE,
    /**
     * The size of the initialized data on disk.
     */
    SIZE_OF_RAW_DATA,
    /**
     * The file pointer to the first page of the section within the COFF file.
     */
    POINTER_TO_RAW_DATA,
    /**
     * The file pointer to the beginning of relocation entries for the section.
     * This is set to zero for executable images or if there are no relocations.
     */
    POINTER_TO_RELOCATIONS,
    /**
     * The file pointer to the beginning of line-number entries for the section.
     * This value should be zero for an image because COFF debugging information
     * is deprecated.
     */
    POINTER_TO_LINE_NUMBERS,
    /**
     * The number of relocation entries for the section. This is set to zero for
     * executable images.
     */
    NUMBER_OF_RELOCATIONS,
    /**
     * The number of line-number entries for the section. This value should be
     * zero for an image because COFF debugging information is deprecated.
     */
    NUMBER_OF_LINE_NUMBERS,
    /**
     * Characteristics of the section.
     */
    CHARACTERISTICS;

}
