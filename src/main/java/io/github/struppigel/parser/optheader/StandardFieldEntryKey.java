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
package io.github.struppigel.parser.optheader;

/**
 * Represents the key of a standard field in the optional header.
 * <p>
 * Descriptions are from the PECOFF specification.
 * 
 * @author Katja Hahn
 * 
 */
public enum StandardFieldEntryKey implements OptionalHeaderKey {
    /**
     * The unsigned integer that identifies the state of the image file. The
     * most common number is 0x10B, which identifies it as a normal executable
     * file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a
     * PE32+ executable.
     */
    MAGIC_NUMBER,
    /**
     * The linker major version number.
     */
    MAJOR_LINKER_VERSION,
    /**
     * The linker minor version number.
     */
    MINOR_LINKER_VERSION,
    /**
     * The size of the code (text) section, or the sum of all code sections if
     * there are multiple sections.
     */
    SIZE_OF_CODE,
    /**
     * The size of the initialized data section, or the sum of all such sections
     * if there are multiple data sections.
     */
    SIZE_OF_INIT_DATA,
    /**
     * The size of the uninitialized data section (BSS), or the sum of all such
     * sections if there are multiple BSS sections.
     */
    SIZE_OF_UNINIT_DATA,
    /**
     * The address of the entry point relative to the image base when the
     * executable file is loaded into memory. For program images, this is the
     * starting address. For device drivers, this is the address of the
     * initialization function. An entry point is optional for DLLs. When no
     * entry point is present, this field must be zero.
     */
    ADDR_OF_ENTRY_POINT,
    /**
     * The address that is relative to the image base of the beginning-of-code
     * section when it is loaded into memory.
     */
    BASE_OF_CODE,
    /**
     * The address that is relative to the image base of the beginning-of-data
     * section when it is loaded into memory. Only present in PE32 files.
     */
    BASE_OF_DATA;
}
