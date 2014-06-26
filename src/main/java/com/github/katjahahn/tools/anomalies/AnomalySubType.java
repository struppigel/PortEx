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
package com.github.katjahahn.tools.anomalies;

/**
 * Represent the semantics of an anomaly.
 * <p>
 * The subtype is a specific description for the anomaly. This avoids having to
 * search for parts of the description string to find certain anomalies.
 * 
 * @author Katja Hahn
 */
public enum AnomalySubType {

    /** MSDOS Header */

    /**
     * The MSDOS header is collapsed, i.e. parts are missing.
     */
    COLLAPSED_MSDOS_HEADER,

    /** COFF File Header */

    /**
     * The PE File Header was moved to overlay, this is the result of
     * manipulating e_lfanew to point to the overlay.
     */
    PE_HEADER_IN_OVERLAY,
    /**
     * The optional header is collapsed.
     */
    COLLAPSED_OPTIONAL_HEADER,
    /**
     * The SIZE_OF_OPTIONAL_HEADER is too large.
     * <p>
     * This may result in a SEC_TABLE_IN_OVERLAY anomaly.
     */
    TOO_LARGE_OPTIONAL_HEADER,
    /**
     * The optional header is too small //TODO same as collapsed
     */
    TOO_SMALL_OPTIONAL_HEADER,
    /**
     * The file has more than 96 sections.
     */
    TOO_MANY_SECTIONS,
    /**
     * The file has no sections.
     */
    SECTIONLESS,
    /**
     * Deprecated NR_OF_SYMBOLS is set.
     */
    DEPRECATED_NR_OF_SYMB,
    /**
     * Deprecated POINTER_TO_SYMBOL_TABLE is set.
     */
    DEPRECATED_PTR_TO_SYMB_TABLE,
    /**
     * Reserved file characteristics are set.
     */
    RESERVED_FILE_CHARACTERISTICS,
    /**
     * Deprecated file characteristics are set.
     */
    DEPRECATED_FILE_CHARACTERISTICS,

    /** Optional Header */

    /**
     * The image base is too large.
     */
    TOO_LARGE_IMAGE_BASE,
    /**
     * The image base is zero.
     */
    ZERO_IMAGE_BASE,
    /**
     * The image base has a non-default value.
     */
    NON_DEFAULT_IMAGE_BASE,
    /**
     * The image base is not a multiple of 64K.
     */
    NOT_MULT_OF_64K_IMAGE_BASE,
    /**
     * SIZE_OF_IMAGE is not aligned to SECTION_ALIGNMENT.
     */
    NOT_SEC_ALIGNED_SIZE_OF_IMAGE,
    /**
     * Unusual number of data directories.
     */
    UNUSUAL_DATA_DIR_NR,
    /**
     * No data directory present
     */
    NO_DATA_DIR,
    /**
     * Reserved data directories are present.
     */
    RESERVED_DATA_DIR,
    /**
     * Data directory entry doesn't point to a valid location, i.e. outside the
     * file
     */
    INVALID_DATA_DIR,
    /**
     * SIZE_OF_HEADERS is too small.
     */
    TOO_SMALL_SIZE_OF_HEADERS,
    /**
     * SIZE_OF_HEADERS is not alinged to FILE_ALIGNMENT.
     */
    NOT_FILEALIGNED_SIZE_OF_HEADERS,
    /**
     * SIZE_OF_HEADERS is not the rounded up header size.
     */
    NON_DEFAULT_SIZE_OF_HEADERS,
    /**
     * Reserved DLL Characteristics are set.
     */
    RESERVED_DLL_CHARACTERISTICS,
    /**
     * Deprecated DLL Characteristics are set.
     */
    DEPRECATED_DLL_CHARACTERISTICS,
    /**
     * Reserved Win32Version is set.
     */
    RESERVED_WIN32VERSION,
    /**
     * Reserved LoaderFlags are set.
     */
    RESERVED_LOADER_FLAGS,
    /**
     * FILE_ALIGNMENT is not a power of two.
     */
    NOT_POW_OF_TWO_FILEALIGN,
    /**
     * FILE_ALIGNMENT is smaller than 512.
     */
    TOO_SMALL_FILEALIGN,
    /**
     * FILE_ALIGNMENT is larger than 65536.
     */
    TOO_LARGE_FILEALIGN,
    /**
     * FILE_ALIGNMENT is not 512.
     */
    NON_DEFAULT_FILEALIGN,
    /**
     * SECTION_ALIGNMENT is smaller than FILE_ALIGNMENT.
     */
    TOO_SMALL_SECALIGN,
    /**
     * Low alignment mode is set.
     */
    LOW_ALIGNMENT_MODE,
    /**
     * The ADDRESS_OF_ENTRY_POINT is too small.
     */
    TOO_SMALL_EP,
    /**
     * The ADDRESS_OF_ENTRY_POINT is zero.
     */
    ZERO_EP,
    /**
     * The ADDRESS_OF_ENTRY_POINT points into virtual space.
     */
    VIRTUAL_EP,

    /** Section Table */

    /**
     * The section name is unusual.
     */
    UNUSUAL_SEC_NAME,
    /**
     * Control symbols in section name. This is a special case of
     * UNUSUAL_SEC_NAME.
     */
    CTRL_SYMB_IN_SEC_NAME,
    /**
     * The section table is moved to overlay.
     */
    SEC_TABLE_IN_OVERLAY,
    /**
     * The SIZE_OF_RAW_DATA is larger than the file size permits.
     */
    TOO_LARGE_SIZE_OF_RAW,
    /**
     * Contraints for extendec reloc have been violated.
     */
    EXTENDED_RELOC_VIOLATIONS,
    /**
     * Reserved section characteristics are set.
     */
    RESERVED_SEC_CHARACTERISTICS,
    /**
     * Deprecated section characteristics are set.
     */
    DEPRECATED_SEC_CHARACTERISTICS,
    /**
     * Section characteristics are either missing or superfluous. (Based on
     * conventions given by section name, see PECOFF spec) //TODO add to thesis
     */
    UNUSUAL_SEC_CHARACTERISTICS,
    /**
     * Sections are physically overlapping.
     */
    OVERLAPPING_SEC,
    /**
     * Sections are duplicated. This is a special case of OVERLAPPING_SEC.
     */
    DUPLICATE_SEC,
    /**
     * The virtual addresses of the sections are not in ascending order.
     */
    NOT_ASCENDING_SEC_VA,
    /**
     * Deprecated POINTER_TO_LINE_NUMBER set
     */
    DEPRECATED_PTR_OF_LINE_NR,
    /**
     * Deprecated NUMBER_OF_LINE_NUMBERS set.
     */
    DEPRECATED_NR_OF_LINE_NR,
    /**
     * The section has a zero virtual size.
     */
    ZERO_VIRTUAL_SIZE,
    /**
     * The section has a zero size of raw data.
     */
    ZERO_SIZE_OF_RAW_DATA,
    /**
     * Section characteristics that are only valid for object files are set.
     */
    OBJECT_ONLY_SEC_CHARACTERISTICS,
    /**
     * TODO POINTER_TO_RELOCATIONS is zero ??
     */
    ZERO_POINTER_TO_RELOC, // TODO must be zero?
    ZERO_NR_OF_RELOC, // TODO must be zero? correct in thesis as well
    /**
     * TODO
     */
    UNINIT_DATA_CONTRAINTS_VIOLATION,
    /**
     * SIZE_OF_RAW_DATA is not a multiple of file alignment
     */
    NOT_FILEALIGNED_SIZE_OF_RAW,
    /**
     * POINTER_TO_RAW_DATA is not a multiple of file alignment
     */
    NOT_FILEALIGNED_PTR_TO_RAW, DEPRECATED_NR_OF_RELOC, // TODO add to thesis
    DEPRECATED_PTR_TO_RELOC; // TODO add to thesis
}
