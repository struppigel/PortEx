/*******************************************************************************
 * Copyright 2014 Karsten Phillip Boris Hahn
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
package com.github.struppigel.tools.anomalies;

import java.util.Optional;

import static com.github.struppigel.tools.anomalies.AnomalyType.*;

/**
 * Represent the semantics of an anomaly.
 * <p>
 * The subtype is a specific description for the anomaly. This avoids having to
 * search for parts of the description string to find certain anomalies.
 * 
 * @author Karsten Hahn
 */
public enum AnomalySubType {

    /**************************** RE Hints ******************************/

    /**
     * Often involves multiple structures in the PE file, purpose is to deliver
     * reverse engineering hints, with less focus on how and where this was determined.
     */

    AHK_RE_HINT(RE_HINT, "The executable is an AutoHotKey wrapper. Extract the resource and check the script."),

    ARCHIVE_RE_HINT(RE_HINT, "This file has an embedded archive, extract the contents with an unarchiver"),

    AUTOIT_RE_HINT(RE_HINT, "The file is an AutoIt script executable, use AutoIt-Ripper to unpack the script"),

    ELECTRON_PACKAGE_RE_HINT(RE_HINT, "This is an Electron Package executable. Look for *.asar archive in resources folder. This might be a separate file."),

    EMBEDDED_EXE_RE_HINT(RE_HINT, "This file contains an embedded executable, extract and analyse it"),

    FAKE_VMP_RE_HINT(RE_HINT, "This might be protected with an older version of VMProtect, but many have fake VMProtect section names. So check if this is really the case."),

    INSTALLER_RE_HINT(RE_HINT, "This file is an installer, extract the install script and contained files, try 7zip or run the file and look into TEMP"),

    NULLSOFT_RE_HINT(RE_HINT, "This file is a Nullsoft installer, download 7zip v15.02 to extract the install script and contained files"),

    PYINSTALLER_RE_HINT(RE_HINT, "This file is a PyInstaller executable. Use pyinstxtractor to extract the python bytecode, then apply a decompiler to the main .pyc"),

    SCRIPT_TO_EXE_WRAPPED_RE_HINT(RE_HINT, "This might be a Script-to-Exe wrapped file, check the resources for a compressed or plain script."),

    SFX_RE_HINT(RE_HINT, "This file is a self-extracting-archive. Try to extract the files with 7zip or run the file and collect them from TEMP"),

    UPX_PACKER_RE_HINT(RE_HINT, "This file seems to be packed with UPX, unpack it with upx.exe -d <sample>"),


    /**************************** MSDOS Header ******************************/

    /**
     * The MSDOS header is collapsed, i.e. parts are missing.
     */
    COLLAPSED_MSDOS_HEADER(STRUCTURE),

    /**
     * Reserved MSDOS field is not zero
     */
    RESERVED_MSDOS_FIELD(RESERVED),
    
    /**
     * e_lfanew points to second half of file
     */
    LARGE_E_LFANEW(NON_DEFAULT),

    /**************************** RICH Header ******************************/

    /**
     * Calculated checksum is not the same as the XOR key/checksum saved in rich header
     * This is a hint towards Rich header manipulation
     */
    RICH_CHECKSUM_INVALID(NON_DEFAULT),

    /*************************** COFF File Header *****************************/

    /**
     * Timestamp is too far in the past.
     */
    TIME_DATE_TOO_LOW(NON_DEFAULT),
    /**
     * Timestamp is in future.
     */
    TIME_DATE_IN_FUTURE(NON_DEFAULT),
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
     * The file has more than 95 sections.
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
     * PE file header might be a different one in memory than on disk //TODO add to thesis
     */
    DUPLICATED_PE_FILE_HEADER(STRUCTURE),
    /**
     * ImageBase + SizeOfImage too large.
     */
    TOO_LARGE_IMAGE_BASE(WRONG),
    /**
     * SizeOfCode is too large
     */
    TOO_LARGE_SIZE_OF_CODE(WRONG),
    /**
     * SizeOfInitializedData is too large
     */
    TOO_LARGE_SIZE_OF_INIT_DATA(WRONG),
    /**
     * SizeOfUninitializedData is too large
     */
    TOO_LARGE_SIZE_OF_UNINIT_DATA(WRONG),
    /**
     * BaseOfData is too large
     */
    TOO_LARGE_BASE_OF_DATA(WRONG),
    /**
     * BaseOfCode is too large
     */
    TOO_LARGE_BASE_OF_CODE(WRONG),
    /**
     * SizeOfCode is too small
     */
    TOO_SMALL_SIZE_OF_CODE(WRONG),
    /**
     * SizeOfInitializedData is too small
     */
    TOO_SMALL_SIZE_OF_INIT_DATA(WRONG),
    /**
     * SizeOfUninitializedData is too small
     */
    TOO_SMALL_SIZE_OF_UNINIT_DATA(WRONG),
    /**
     * BaseOfData is too small
     */
    TOO_SMALL_BASE_OF_DATA(WRONG),
    /**
     * BaseOfCode is too small
     */
    TOO_SMALL_BASE_OF_CODE(WRONG),
    /**
     * The base of data is zero although there is at least one data section.
     */
    ZERO_BASE_OF_DATA(WRONG),
    /**
     * The base of code is zero although there is at least one code section.
     */
    ZERO_BASE_OF_CODE(WRONG),
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
     * GLOBAL_PTR data directory size is set, but must be zero
     */
    GLOBAL_PTR_SIZE_SET(WRONG),
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
     * Section table is in virtual space
     */
    VIRTUAL_SECTION_TABLE(STRUCTURE),
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
     * The section name is empty.
     */
    EMPTY_SEC_NAME(NON_DEFAULT),
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
     * Constraints for extended reloc have been violated.
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
     * conventions given by section name, see PECOFF spec)
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
    UNINIT_DATA_CONSTRAINTS_VIOLATION(WRONG),
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
    DEPRECATED_NR_OF_RELOC(DEPRECATED),
    /**
     * TODO
     */
    DEPRECATED_PTR_TO_RELOC(DEPRECATED),
    //The following are suspicious section characteristics
   /**
    * A section is writeable and executable
    */
    WRITE_AND_EXECUTE_SECTION(NON_DEFAULT),
    /**
     * A section is writeable only.
     */
    WRITEABLE_ONLY_SECTION(NON_DEFAULT),
    /**
     * No characteristics specified for a section
     */
    CHARACTERLESS_SECTION(NON_DEFAULT),

    /**************************** Import Section ******************************/
    
    /**
     * So many imports, exports, resources or any other data that the maximum 
     * limits for parsing them were reached.
     * TODO detect for imports, resources, exports, delay-load imports
     */
    EXHAUSTIVE_DATA(STRUCTURE),
    
    /**
     * Kernel32.dll imports by ordinal are suspicious according to Szor
     */
    KERNEL32_BY_ORDINAL_IMPORTS(NON_DEFAULT),

    /**
     * Imports, Exports, or Resources, etc, are stretched over several sections
     */
    FRACTIONATED_DATADIR(STRUCTURE),
    
    /**
     * Any structures of the import directory are in virtual space. //TODO add to thesis
     */
    VIRTUAL_IMPORTS(STRUCTURE), //TODO implement virtual exports, relocs, etc
    
    /**
     * Import is typical for process injection
     */
    PROCESS_INJECTION_IMPORT(NON_DEFAULT),
    
    /**************************** Export Section ******************************/
    
    /**
     * File contains export entries with invalid RVAs.
     */
    INVALID_EXPORTS(STRUCTURE),

    /**************************** Resource Section ******************************/

    /**
     * Resource tree has a loop
     */
    RESOURCE_LOOP(STRUCTURE),
    /**
     * Invalid resource location
     */
    RESOURCE_LOCATION_INVALID(WRONG),
    /**
     * Name of a named resource entry is interesting
     */
    RESOURCE_NAME(NON_DEFAULT),


    /**************************** CLR Section ******************************/

    /**
     * Version string in Metadata root is broken
     * TODO check if AnomalyType NON_DEFAULT is correct
     */
    METADATA_ROOT_VERSION_STRING_BROKEN(NON_DEFAULT),
    /**
     * Name of the stream is not zero terminated
     * TODO check if AnomalyType NON_DEFAULT is correct
     */
    NON_ZERO_TERMINATED_STREAM_NAME(NON_DEFAULT),
    /**
     * Several streams with the same name exist
     */
    DUPLICATED_STREAMS(STRUCTURE),
    /**
     * Usage of unreadable characters for strings in the #Strings heap. Typical obfuscation method.
     */
    UNREADABLE_CHARS_IN_STRINGS_HEAP(NON_DEFAULT)
    ;

    private final AnomalyType superType;
    private final Optional<String> description;

    AnomalySubType(AnomalyType superType) {
        this.description = Optional.empty();
        this.superType = superType;

        if(superType.equals(RE_HINT)) {
            assert(this.description.isPresent());
        }
    }

    AnomalySubType(AnomalyType superType, String description) {
        this.description = Optional.ofNullable(description);
        this.superType = superType;

        if(superType.equals(RE_HINT)) {
            assert(this.description.isPresent());
        }
    }

    /**
     * Must be present for RE_HINTS, unfortunately I cannot create Subclass of Enum
     * @return
     */
    public Optional<String> getDescription() { return description; }

    public AnomalyType getSuperType() {
        return superType;
    }
}
