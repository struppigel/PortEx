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

import static com.github.katjahahn.tools.anomalies.AnomalyType.*;

/**
 * Represent the semantics of an anomaly.
 * <p>
 * The subtype is a specific description for the anomaly. This avoids having to
 * search for parts of the description string to find certain anomalies.
 * 
 * @author Katja Hahn
 */
public enum AnomalySubType {

    /**************************** MSDOS Header ******************************/

    /**
     * The MSDOS header is collapsed, i.e. parts are missing.
     */
    COLLAPSED_MSDOS_HEADER(STRUCTURE),
    
    /**
     * Reserved MSDOS field is not zero
     */
    RESERVED_MSDOS_FIELD(RESERVED),
    
    /*************************** COFF File Header *****************************/

    /**
     * The PE File Header was moved to overlay, this is the result of
     * manipulating e_lfanew to point to the overlay.
     */
    PE_HEADER_IN_OVERLAY(STRUCTURE),
    /**
     * The optional header size is too small, thus the Optional Header overlaps
     * with the Section Table.
     */
    COLLAPSED_OPTIONAL_HEADER(STRUCTURE),
    /**
     * The SIZE_OF_OPTIONAL_HEADER is too large.
     * <p>
     * This may result in a SEC_TABLE_IN_OVERLAY anomaly.
     */
    TOO_LARGE_OPTIONAL_HEADER(WRONG),
    /**
     * The file has more than 96 sections.
     */
    TOO_MANY_SECTIONS(STRUCTURE),
    /**
     * The file has no sections.
     */
    SECTIONLESS(STRUCTURE),
    /**
     * Deprecated NR_OF_SYMBOLS is set.
     */
    DEPRECATED_NR_OF_SYMB(DEPRECATED),
    /**
     * Deprecated POINTER_TO_SYMBOL_TABLE is set.
     */
    DEPRECATED_PTR_TO_SYMB_TABLE(DEPRECATED),
    /**
     * Reserved file characteristics are set.
     */
    RESERVED_FILE_CHARACTERISTICS(RESERVED),
    /**
     * Deprecated file characteristics are set.
     */
    DEPRECATED_FILE_CHARACTERISTICS(DEPRECATED),

    /**************************** Optional Header ******************************/

    /**
     * The image base is too large.
     */
    TOO_LARGE_IMAGE_BASE(WRONG),
    /**
     * The image base is zero.
     */
    ZERO_IMAGE_BASE(WRONG),
    /**
     * The image base has a non-default value.
     */
    NON_DEFAULT_IMAGE_BASE(NON_DEFAULT),
    /**
     * The image base is not a multiple of 64K.
     */
    NOT_MULT_OF_64K_IMAGE_BASE(WRONG),
    /**
     * SIZE_OF_IMAGE is not aligned to SECTION_ALIGNMENT.
     */
    NOT_SEC_ALIGNED_SIZE_OF_IMAGE(WRONG),
    /**
     * Unusual number of data directories.
     */
    UNUSUAL_DATA_DIR_NR(NON_DEFAULT),
    /**
     * No data directory present
     */
    NO_DATA_DIR(STRUCTURE),
    /**
     * Reserved data directories are present.
     */
    RESERVED_DATA_DIR(RESERVED),
    /**
     * Data directory entry doesn't point to a valid location, i.e. outside the
     * file
     */
    INVALID_DATA_DIR(WRONG),
    /**
     * SIZE_OF_HEADERS is too small.
     */
    TOO_SMALL_SIZE_OF_HEADERS(WRONG),
    /**
     * SIZE_OF_HEADERS is not alinged to FILE_ALIGNMENT.
     */
    NOT_FILEALIGNED_SIZE_OF_HEADERS(WRONG),
    /**
     * SIZE_OF_HEADERS is not the rounded up header size.
     */
    NON_DEFAULT_SIZE_OF_HEADERS(NON_DEFAULT),
    /**
     * Reserved DLL Characteristics are set.
     */
    RESERVED_DLL_CHARACTERISTICS(RESERVED),
    /**
     * Deprecated DLL Characteristics are set.
     */
    DEPRECATED_DLL_CHARACTERISTICS(DEPRECATED),
    /**
     * Reserved Win32Version is set.
     */
    RESERVED_WIN32VERSION(RESERVED),
    /**
     * Reserved LoaderFlags are set.
     */
    RESERVED_LOADER_FLAGS(RESERVED),
    /**
     * FILE_ALIGNMENT is not a power of two.
     */
    NOT_POW_OF_TWO_FILEALIGN(WRONG),
    /**
     * FILE_ALIGNMENT is smaller than 512.
     */
    TOO_SMALL_FILEALIGN(NON_DEFAULT),
    /**
     * FILE_ALIGNMENT is larger than 65536.
     */
    TOO_LARGE_FILEALIGN(WRONG),
    /**
     * FILE_ALIGNMENT is not 512.
     */
    NON_DEFAULT_FILEALIGN(NON_DEFAULT),
    /**
     * SECTION_ALIGNMENT is smaller than FILE_ALIGNMENT.
     */
    TOO_SMALL_SECALIGN(WRONG),
    /**
     * Low alignment mode is set.
     */
    LOW_ALIGNMENT_MODE(NON_DEFAULT),
    /**
     * The ADDRESS_OF_ENTRY_POINT is too small.
     */
    TOO_SMALL_EP(WRONG),
    /**
     * The ADDRESS_OF_ENTRY_POINT is zero.
     */
    ZERO_EP(WRONG),
    /**
     * The ADDRESS_OF_ENTRY_POINT points into virtual space.
     */
    VIRTUAL_EP(WRONG),
    /**
     * Entry point is in the last section of the PE file
     */
    EP_IN_LAST_SECTION(NON_DEFAULT),

    /**************************** Section Table ******************************/

    /**
     * Entry point is within a writeable section. This is suspicious. The file
     * might be infected.
     */
    EP_IN_WRITEABLE_SEC(NON_DEFAULT),
    /**
     * The section name is unusual.
     */
    UNUSUAL_SEC_NAME(NON_DEFAULT),
    /**
     * Control symbols in section name. This is a special case of
     * UNUSUAL_SEC_NAME.
     */
    CTRL_SYMB_IN_SEC_NAME(NON_DEFAULT),
    /**
     * The section table is moved to overlay.
     */
    SEC_TABLE_IN_OVERLAY(STRUCTURE),
    /**
     * The SIZE_OF_RAW_DATA is larger than the file size permits.
     */
    TOO_LARGE_SIZE_OF_RAW(WRONG),
    /**
     * Contraints for extendec reloc have been violated.
     */
    EXTENDED_RELOC_VIOLATIONS(WRONG),
    /**
     * Reserved section characteristics are set.
     */
    RESERVED_SEC_CHARACTERISTICS(RESERVED),
    /**
     * Deprecated section characteristics are set.
     */
    DEPRECATED_SEC_CHARACTERISTICS(DEPRECATED),
    /**
     * Section characteristics are either missing or superfluous. (Based on
     * conventions given by section name, see PECOFF spec) //TODO add to thesis
     */
    UNUSUAL_SEC_CHARACTERISTICS(NON_DEFAULT),
    /**
     * Sections are physically shuffled.
     */
    PHYSICALLY_SHUFFLED_SEC(STRUCTURE),
    /**
     * Sections are physically overlapping.
     */
    PHYSICALLY_OVERLAPPING_SEC(STRUCTURE),
    /**
     * Sections are duplicated. This is a special case of
     * {@link #PHYSICALLY_OVERLAPPING_SEC}.
     */
    PHYSICALLY_DUPLICATED_SEC(STRUCTURE),
    /**
     * Sections are overlapping in virtual space
     */
    VIRTUALLY_OVERLAPPING_SEC(STRUCTURE),
    /**
     * Sections have are mapped to the same virtual location. This is a special
     * case of {@link #VIRTUALLY_OVERLAPPING_SEC}
     */
    VIRTUALLY_DUPLICATED_SEC(STRUCTURE),
    /**
     * The virtual addresses of the sections are not in ascending order.
     */
    NOT_ASCENDING_SEC_VA(STRUCTURE),
    /**
     * Deprecated POINTER_TO_LINE_NUMBER set
     */
    DEPRECATED_PTR_OF_LINE_NR(DEPRECATED),
    /**
     * Deprecated NUMBER_OF_LINE_NUMBERS set.
     */
    DEPRECATED_NR_OF_LINE_NR(DEPRECATED),
    /**
     * The section has a zero virtual size.
     */
    ZERO_VIRTUAL_SIZE(WRONG),
    /**
     * The section has a zero size of raw data.
     */
    ZERO_SIZE_OF_RAW_DATA(WRONG),
    /**
     * Section characteristics that are only valid for object files are set.
     */
    OBJECT_ONLY_SEC_CHARACTERISTICS(WRONG),
    /**
     * TODO POINTER_TO_RELOCATIONS is zero ??
     */
    ZERO_POINTER_TO_RELOC(WRONG), // TODO must be zero?
    ZERO_NR_OF_RELOC(WRONG), // TODO must be zero? correct in thesis as well
    /**
     * TODO
     */
    UNINIT_DATA_CONTRAINTS_VIOLATION(WRONG),
    /**
     * SIZE_OF_RAW_DATA is not a multiple of file alignment
     */
    NOT_FILEALIGNED_SIZE_OF_RAW(WRONG),
    /**
     * POINTER_TO_RAW_DATA is not a multiple of file alignment
     */
    NOT_FILEALIGNED_PTR_TO_RAW(WRONG),
    /**
     * TODO
     */
    DEPRECATED_NR_OF_RELOC(DEPRECATED), // TODO add to thesis
    /**
     * TODO
     */
    DEPRECATED_PTR_TO_RELOC(DEPRECATED), // TODO add to thesis

    /**************************** Import Section ******************************/

    /**
     * Kernel32.dll imports by ordinal are suspicious according to Szor
     */
    KERNEL32_BY_ORDINAL_IMPORTS(NON_DEFAULT),

    /**
     * Imports, Exports, or Resources, etc, are stretched over several sections
     */
    FRACTIONATED_DATADIR(STRUCTURE),
    
    /**************************** Resource Section ******************************/
    
    /**
     * Resource tree has a loop.
     */
    RESOURCE_LOOP(STRUCTURE);

    private final AnomalyType superType;

    private AnomalySubType(AnomalyType superType) {
        this.superType = superType;
    }

    public AnomalyType getSuperType() {
        return superType;
    }
}
