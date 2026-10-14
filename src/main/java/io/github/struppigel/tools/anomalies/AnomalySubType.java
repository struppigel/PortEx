/*******************************************************************************
 * Copyright 2024 Karsten Phillip Boris Hahn
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
package io.github.struppigel.tools.anomalies;

import static io.github.struppigel.tools.anomalies.AnomalyType.*;

/**
 * Represent the semantics of an anomaly.
 * <p>
 * The subtype is a specific description for the anomaly. This avoids having to
 * search for parts of the description string to find certain anomalies.
 * 
 * @author Karsten Hahn
 */
public enum AnomalySubType {

    /**
     * For usage with ReHints which can contain anomalies that are not part of the normal anomaly scanning
     */
    RE_HINT(NON_DEFAULT),

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
     * Any structures of the import directory are in virtual space.
     */
    VIRTUAL_IMPORTS(STRUCTURE), //TODO implement virtual exports, relocs, etc
    
    /**
     * Import is typical for process injection or unpacking stubs
     */
    PROCESS_INJECTION_OR_UNPACKING_IMPORT(NON_DEFAULT),
    
    /**************************** Export Section ******************************/
    
    /**
     * File contains export entries with invalid RVAs.
     */
    INVALID_EXPORTS(STRUCTURE),

    /**
     * The number of export entries exceeds the internal maximum
     */
    MAX_EXPORTS(STRUCTURE),

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

    /**
     * The specified resource has a match on a signature
     */
    RESOURCE_HAS_SIGNATURE(NON_DEFAULT),

    /**
     * Interesting file type signature in resources
     */
    RESOURCE_FILE_TYPE(NON_DEFAULT),

    /**************************** Debug Dir ******************************/


    UNUSUAL_PDB_PATH(NON_DEFAULT),

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
    UNREADABLE_CHARS_IN_STRINGS_HEAP(NON_DEFAULT),

    /*
     * The following subtypes of the CLI header, the metadata root and the #~ stream header follow one rule: a value
     * the runtime rejects is WRONG (or RESERVED/STRUCTURE by kind of field), one it accepts is NON_DEFAULT unless
     * ECMA-335 forbids it. Runtime = .NET Framework 4.8.1 on Windows 10.0.26200, one property changed in a clean
     * executable, rows in src/test/resources/runtime-acceptance/clr-runtime-acceptance.tsv.
     */

    /**
     * Cb of the CLI header is smaller than the 0x48 bytes of the header.
     * Spec II.25.3.3: "Size of the header in bytes". Runtime: rejected (Cb 0x40).
     */
    CLR_TOO_SMALL_HEADER_SIZE(WRONG),
    /**
     * Cb of the CLI header is larger than the 0x48 bytes of the header.
     * Spec II.25.3.3: "Size of the header in bytes", no fixed value. Runtime: accepted (Cb 0x50).
     */
    CLR_UNUSUAL_HEADER_SIZE(NON_DEFAULT),
    /**
     * MajorRuntimeVersion of the CLI header is not 2.
     * Spec II.25.3.3: "The minimum version of the runtime required to run this program, currently 2".
     * Runtime: rejected (3).
     */
    CLR_INVALID_RUNTIME_MAJOR_VERSION(WRONG),
    /**
     * MinorRuntimeVersion of the CLI header is neither 0 nor 5.
     * Spec II.25.3.3: "currently 0". The Microsoft compilers write 5. Runtime: accepted (9).
     */
    CLR_UNUSUAL_RUNTIME_MINOR_VERSION(NON_DEFAULT),
    /**
     * COMIMAGE_FLAGS_ILONLY is cleared.
     * Spec II.25.3.3.1: "Shall be 1". Typed as an exception: the runtime accepts it and shipped Microsoft images
     * clear it (ReadyToRun and mixed mode: 143 of 472 assemblies of .NET Framework 4.8.1 and .NET 8 on the test
     * machine, e.g. flags 0xC in System.Private.CoreLib.dll).
     */
    CLR_UNUSUAL_ILONLY_CLEARED(NON_DEFAULT),
    /**
     * COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is set.
     * Spec II.25.3.3.1: "Shall be 0". Typed as an exception: 8 shipped .NET Framework assemblies set it (flags 0x18,
     * e.g. CustomMarshalers.dll). Runtime: my fixture with a managed entry point token was rejected, the token is
     * read as a native entry point then.
     */
    CLR_UNUSUAL_NATIVE_ENTRYPOINT(NON_DEFAULT),
    /**
     * COMIMAGE_FLAGS_TRACKDEBUGDATA is set.
     * Spec II.25.3.3.1: "Should be 0". Runtime: accepted.
     */
    CLR_TRACKDEBUGDATA_SET(RESERVED),
    /**
     * A flag bit of the CLI header is set that is neither in ECMA-335 nor defined by Microsoft.
     * Spec II.25.3.3.1: "All unspecified bits should be zero". Runtime: rejected (0x100).
     */
    CLR_UNDEFINED_FLAGS(RESERVED),
    /**
     * CodeManagerTable or ExportAddressTableJumps of the CLI header is not zero.
     * Spec II.25.3.3: "Always 0". Runtime: accepted (CodeManagerTable), rejected (ExportAddressTableJumps).
     * ManagedNativeHeader is not reported, ReadyToRun images use it.
     */
    CLR_NONZERO_HEADER_FIELD(WRONG),
    /**
     * MajorVersion or MinorVersion of the metadata root is not 1.
     * Spec II.24.2.1: "1 (ignore on read)". Runtime: rejected (2 and 5, "Old version error"), so the loader
     * treats the value differently from the specification.
     */
    METADATA_ROOT_INVALID_VERSION(WRONG),
    /**
     * Reserved or Flags of the metadata root is not 0.
     * Spec II.24.2.1: "Reserved, always 0". Runtime: accepted (Reserved), rejected (Flags).
     */
    METADATA_ROOT_RESERVED_SET(RESERVED),
    /**
     * MajorVersion or MinorVersion of the #~ stream is not 2.0.
     * Spec II.24.2.6: "shall be 2" and "shall be 0". Runtime: rejected (3.0 and 2.1).
     */
    TABLES_STREAM_INVALID_VERSION(WRONG),
    /**
     * A Reserved field of the #~ stream header is not as specified (0 at offset 0, 1 at offset 7).
     * Spec II.24.2.6: "Reserved, always 0" and "Reserved, always 1". Runtime: accepted. The second field is not 1
     * in 117 of 472 shipped Microsoft assemblies (.NET Framework 4.8.1, .NET 8), so the booster score must be low.
     */
    TABLES_STREAM_RESERVED_SET(RESERVED),
    /**
     * HeapSizes of the #~ stream has a bit set other than 0x01, 0x02 and 0x04.
     * Spec II.24.2.6 defines only these three bits. Runtime: rejected (0x40), accepted (0x80).
     */
    TABLES_STREAM_UNDEFINED_HEAP_SIZES(RESERVED),
    /**
     * The Valid bit vector of the #~ stream has a bit above 0x2c set.
     * Spec II.24.2.6: "It is invalid to include non-existent tables in Valid, so all bits above 0x2c shall be
     * zero". Runtime: not tested.
     */
    TABLES_STREAM_NON_EXISTENT_TABLES(WRONG),
    /**
     * Export, exception, TLS or load config data directory of a .NET image is not zero.
     * Spec II.25.2.3.3: "Always 0". Typed as an exception: found in 8 (export), 143 (exception), 2 (TLS) and 16
     * (load config) of 721 shipped assemblies of .NET Framework 4.8.1 and .NET 8, mixed mode and x64 images.
     * Resource, certificate and debug directories are not reported, 721, 719 and 512 of those assemblies have them.
     */
    CLR_UNUSUAL_DATA_DIR(NON_DEFAULT),
    /**
     * Bound import or delay import data directory of a .NET image is not zero.
     * Spec II.25.2.3.3: "Always 0". Not found in any of 721 shipped assemblies. Runtime: rejected with a data
     * directory pointing at the CLI header, which the Windows loader parses, so that result is not specific.
     * Architecture, global ptr and the reserved directory are reported by the optional header scanning.
     */
    CLR_UNEXPECTED_DATA_DIR(WRONG),
    /**
     * The size of a stream is not a multiple of 4.
     * Spec II.24.2.2: "Size of this stream in bytes, shall be a multiple of 4". Runtime: accepted (#US reduced by 1),
     * rejected (#Strings reduced by 1, the last string lost its terminator). The specification forbids it.
     */
    CLR_STREAM_SIZE_NOT_ALIGNED(WRONG),
    /**
     * A stream has a name other than #~, #-, #Strings, #US, #Blob and #GUID.
     * Spec II.24.2.2 names "five possible kinds of streams" and does not forbid others, #- is the uncompressed
     * variant of #~ that Microsoft tools write. Runtime: accepted (#GUID renamed, nothing referring to the heap, with
     * the same change without the rename as control).
     */
    CLR_UNUSUAL_STREAM_NAME(NON_DEFAULT),
    /**
     * The first entry of the #Strings, #US or #Blob heap is not the empty entry (a single 0x00 byte).
     * Spec II.24.2.3: "the first entry is always the empty string", II.24.2.4: "The first entry in both these
     * heaps is the empty 'blob' that consists of the single byte 0x00". Runtime: not tested.
     */
    CLR_HEAP_FIRST_ENTRY_NOT_EMPTY(WRONG),
    /**
     * A .NET image with the IL only flag has more than one import descriptor.
     * Spec II.25.3.1: "The Import Table directory entry points to a one element zero terminated array of Import
     * Directory entries". Mixed mode and ReadyToRun images import more and are not checked. Runtime: not tested.
     */
    CLR_MULTIPLE_IMPORT_DESCRIPTORS(STRUCTURE),
    /**
     * The imported DLL of a .NET image with the IL only flag is not mscoree.dll (compared without case, Windows
     * file names are not case sensitive).
     * Spec II.25.3.1: "Name: RVA of null-terminated ASCII string mscoree.dll". Runtime: not tested.
     */
    CLR_INVALID_IMPORT_DLL(WRONG),
    /**
     * The symbol imported from mscoree.dll is not _CorExeMain for an exe or _CorDllMain for a DLL, or it is
     * imported by ordinal.
     * Spec II.25.3.1: "Shall be _CorExeMain for a .exe file and _CorDllMain for a .dll file", "Case sensitive",
     * "Bit 31 shall be set to 0 indicating import by name". Runtime: not tested.
     */
    CLR_INVALID_IMPORT_SYMBOL(WRONG),
    /**
     * The hint of the import from mscoree.dll is not 0.
     * Spec II.25.3.1: "Hint: Shall be 0". Runtime: not tested.
     */
    CLR_NONZERO_IMPORT_HINT(WRONG),
    /**
     * The two least significant bits of the first byte of a method body are neither tiny (2) nor fat (3).
     * Spec II.25.4.1: "These 2 bits will be one and only one of the following" (tiny 0x2, fat 0x3). Only methods
     * with IL code and a body are checked. Runtime: not tested.
     */
    CLR_INVALID_METHOD_HEADER(WRONG),
    /**
     * The size of a fat method header is not 3 (4-byte integers).
     * Spec II.25.4.3: "Size of this header expressed as the count of 4-byte integers occupied (currently 3)".
     * Runtime: sizes 2, 4 and 5 rejected (bad IL range, invalid program) or run differently (size 5 printed OK but
     * exited with 0 instead of 42), the loader reads the code behind the header size.
     */
    CLR_INVALID_FAT_HEADER_SIZE(WRONG),
    /**
     * A fat method header does not start on a 4-byte boundary.
     * Spec II.25.4: "Fat method headers shall start on a 4-byte boundary". Runtime: not tested.
     */
    CLR_MISALIGNED_FAT_HEADER(WRONG),
    /**
     * The CLI header is in a section that is writeable.
     * Spec II.25.3.3: "The header should be placed in a read-only, sharable section of the image". Structural
     * malformation by the thesis, Def. 36 (like a writeable PE header). Runtime: not tested.
     */
    CLR_HEADER_IN_WRITEABLE_SECTION(STRUCTURE),
    /**
     * The Module table does not have exactly one row (row count in the #~ header).
     * Spec II.22.30: "The Module table shall contain one and only one row [ERROR]". Runtime: not tested.
     */
    CLR_MODULE_ROW_COUNT(STRUCTURE),
    /**
     * The Assembly table has more than one row.
     * Spec II.22.2: "The Assembly table shall contain zero or one row [ERROR]". Runtime: not tested.
     */
    CLR_MULTIPLE_ASSEMBLY_ROWS(STRUCTURE),
    /**
     * The name of a Module, Assembly, TypeDef, MethodDef or Field row is empty, or the namespace of a TypeDef row
     * is not null but empty.
     * Spec II.22.30, II.22.2, II.22.37, II.22.26, II.22.15: "Name shall index a non-empty string [ERROR]";
     * II.22.37: "If non-null, then TypeNamespace shall index a non-empty string in the String heap [ERROR]".
     * One anomaly per kind of table, for the first row, the description gives the count. Runtime: not tested.
     */
    CLR_EMPTY_NAME(WRONG),
    /**
     * The Mvid of the Module row is null.
     * Spec II.22.30: "Mvid shall index a non-null GUID in the Guid heap [ERROR]". Runtime: not tested.
     */
    CLR_NULL_MVID(WRONG),
    /**
     * Generation, EncId or EncBaseId of the Module row is not zero.
     * Spec II.22.30: "reserved, shall be zero". Runtime: not tested.
     */
    CLR_MODULE_RESERVED_SET(RESERVED),
    /**
     * Two TypeDef rows that are no nested types have the same namespace and name.
     * Spec II.22.37: "There shall be no duplicate rows in the TypeDef table, based on TypeNamespace+TypeName
     * (unless this is a nested type) [ERROR]". Nested types are not compared, their owner is not looked up.
     * Runtime: not tested.
     */
    CLR_DUPLICATE_TYPEDEF(STRUCTURE),
    /**
     * The Extends column of the TypeDef table leads back to a type through TypeDef rows.
     * Spec II.22.37: "A Class cannot extend itself, or any of its children ... since this would introduce loops in
     * the hierarchy tree [ERROR]". Runtime: not tested.
     */
    CLR_INHERITANCE_LOOP(STRUCTURE),
    /**
     * FieldList or MethodList of a TypeDef row is not null and points behind the Field or MethodDef table.
     * Spec II.22.37: "If FieldList is non-null, it shall index a valid row in the Field table, where valid means
     * 1 <= row <= rowcount+1 [ERROR]", the same for MethodList. Runtime: not tested.
     */
    CLR_INVALID_LIST_INDEX(WRONG),
    /**
     * The Extends column of a TypeDef row is wrong: a class other than <Module> and System.Object has none, an
     * interface has one, or it points behind the TypeDef, TypeRef or TypeSpec table.
     * Spec II.22.37: "Every Class (with the exception of System.Object and the special class <Module>) shall extend
     * one, and only one, other Class - so Extends for a Class shall be non-null [ERROR]", "An Interface never
     * extends another Type - so Extends shall be null [ERROR]", "Extends shall index a valid row in the TypeDef,
     * TypeRef, or TypeSpec table, where valid means 1 <= row <= rowcount [ERROR]". Runtime: not tested.
     */
    CLR_INVALID_EXTENDS(WRONG),
    /**
     * The Flags of a MethodDef row combine bits that the specification excludes or require each other: member
     * access 7, Static with Final, Virtual or NewSlot, Final with Abstract, Abstract with PInvokeImpl,
     * CompilerControlled with SpecialName or RTSpecialName, Abstract, Final, NewSlot or Strict without Virtual,
     * RTSpecialName without SpecialName, PInvokeImpl with Virtual.
     * Spec II.22.26 items 6 to 9, 23 and 24, all [ERROR], values in II.23.1.10. Runtime: not tested.
     */
    CLR_INVALID_METHOD_FLAGS(WRONG),
    /**
     * Two MethodDef rows of the same type have the same name and signature, CompilerControlled methods excluded.
     * Spec II.22.26: "There shall be no duplicate rows in the MethodDef table, based upon owner + Name + Signature
     * [ERROR]". The owner follows from the MethodList runs of the TypeDef table. Runtime: not tested.
     */
    CLR_DUPLICATE_METHOD(STRUCTURE),

    /**************************** Overlay ******************************/
    /**
     * There was a signature match in the overlay
     */
    OVERLAY_HAS_SIGNATURE(NON_DEFAULT),

    /**************************** Certificate Table ******************************/
    /*
     * The certificate table holds the Authenticode signatures. Its address is a
     * file offset. Anomalies of the data directory entry are DataDirAnomalies,
     * those of WIN_CERTIFICATE header fields FieldAnomalies, structural ones
     * StructureAnomalies with the key CERTIFICATE_TABLE, and those of fields of
     * the PKCS#7 signature AuthenticodeAnomalies. A table that starts outside
     * of the file is reported as INVALID_DATA_DIR, exceeded parser limits as
     * EXHAUSTIVE_DATA.
     */

    /**
     * The certificate table offset is not a multiple of 8
     */
    CERT_DIR_NOT_ALIGNED(WRONG),
    /**
     * The certificate table size is larger than the file or the end of the
     * table exceeds the 32-bit address range
     */
    CERT_DIR_SIZE_EXCEEDS_FILE(WRONG),
    /**
     * The certificate table size is smaller than a WIN_CERTIFICATE header
     */
    CERT_DIR_TOO_SMALL(WRONG),
    /**
     * dwLength of a WIN_CERTIFICATE is smaller than its header or larger than
     * the table
     */
    CERT_INVALID_LENGTH(WRONG),
    /**
     * wRevision of a WIN_CERTIFICATE is neither 0x0100 nor 0x0200. The PE format
     * lists these values as "include (but are not limited to)", so this is valid
     * but unknown. Windows behaviour is not verified.
     */
    CERT_UNKNOWN_REVISION(NON_DEFAULT),
    /**
     * wRevision of a WIN_CERTIFICATE is the legacy 0x0100
     */
    CERT_DEPRECATED_REVISION(DEPRECATED),
    /**
     * wCertificateType is the reserved WIN_CERT_TYPE_RESERVED_1
     */
    CERT_RESERVED_TYPE(RESERVED),
    /**
     * wCertificateType is X509 or TS_STACK_SIGNED. The specification defines
     * them, but Windows does not support them for Authenticode.
     */
    CERT_UNSUPPORTED_TYPE(NON_DEFAULT),
    /**
     * wCertificateType is not one of the defined values. The PE format lists the
     * types as "include (but are not limited to)" and says entries "can contain
     * any certificate type", so this is valid but unknown. Windows behaviour is
     * not verified.
     */
    CERT_UNKNOWN_TYPE(NON_DEFAULT),
    /**
     * The certificate table is cut off by the end of the file
     */
    CERT_TABLE_TRUNCATED(STRUCTURE),
    /**
     * The certificate table overlaps the headers
     */
    CERT_TABLE_IN_HEADERS(STRUCTURE),
    /**
     * The certificate table overlaps the raw data of a section
     */
    CERT_TABLE_IN_SECTION(STRUCTURE),
    /**
     * Data follows the certificate table, which should be the last data of
     * the file
     */
    CERT_TABLE_NOT_LAST(STRUCTURE),
    /**
     * The certificate table pointer is shifted, a WIN_CERTIFICATE exists
     * nearby
     */
    CERT_TABLE_MISPLACED(STRUCTURE),
    /**
     * The certificate table has more than one WIN_CERTIFICATE, Windows only
     * uses the first one
     */
    CERT_MULTIPLE_ENTRIES(STRUCTURE),
    /**
     * The certificate table is larger than its entries
     */
    CERT_TABLE_EXTRA_DATA(STRUCTURE),
    /**
     * A WIN_CERTIFICATE has data after the PKCS#7 signature, which the
     * signature does not cover (CVE-2013-3900)
     */
    CERT_DATA_AFTER_PKCS7(STRUCTURE),
    /**
     * The PKCS#7 signature has an element that its format does not define,
     * e.g. after the values of an attribute or after the unauthenticated
     * attributes of a signer, data that the signature does not cover
     */
    CERT_EXTRA_SIGNATURE_ELEMENT(STRUCTURE),
    /**
     * The PKCS#7 signature can not be parsed (truncated or collapsed ASN.1)
     */
    CERT_MALFORMED_PKCS7(STRUCTURE),
    /**
     * Signatures are nested deeply or a signer has many nested signatures
     */
    CERT_UNUSUAL_NESTING(STRUCTURE),
    /**
     * A signature has not exactly one signer.
     * Authenticode_PE (Authenticode Profile of PKCS #7 SignedData): "Because Authenticode signatures support only
     * one signer, digestAlgorithms must contain only one digestAlgorithmIdentifier", "Because Authenticode supports
     * only one signer, only one SignerInfo structure is in signerInfos". Runtime: not tested.
     */
    CERT_UNUSUAL_SIGNER_COUNT(STRUCTURE),
    /**
     * The certificate of a signer is not embedded.
     * Authenticode_PE, certificates: "For Authenticode signatures, certificates contains the signer certificate and
     * any intermediate certificates". Runtime: not tested.
     */
    CERT_MISSING_SIGNER_CERTIFICATE(STRUCTURE),
    /**
     * An unauthenticated attribute is larger than 64 KiB, data that the
     * signature does not cover
     */
    CERT_LARGE_UNAUTH_ATTRIBUTE(STRUCTURE),
    /**
     * An embedded certificate is unrelated to the signers and the other
     * certificates
     */
    CERT_ISOLATED_CERTIFICATE(STRUCTURE),
    /**
     * The computed image digest differs from the signed digest: the file was
     * modified after signing or the signature was copied from another file
     */
    CERT_IMAGE_DIGEST_MISMATCH(WRONG),
    /**
     * The messageDigest attribute differs from the digest of the signed
     * content
     */
    CERT_MESSAGE_DIGEST_MISMATCH(WRONG),
    /**
     * The signature of a signer is invalid
     */
    CERT_INVALID_SIGNER_SIGNATURE(WRONG),
    /**
     * The signature of an embedded certificate is invalid
     */
    CERT_INVALID_CERTIFICATE_SIGNATURE(WRONG),
    /**
     * A timestamp does not cover the signature or its signature is invalid
     */
    CERT_INVALID_TIMESTAMP(WRONG),
    /**
     * An EC key uses explicit curve parameters instead of a named curve
     * (CurveBall, CVE-2020-0601), which RFC 5480 forbids
     */
    CERT_EXPLICIT_EC_PARAMETERS(WRONG),
    /**
     * An ECDSA signature value r or s is zero or not smaller than the curve
     * order (Psychic Signatures, CVE-2022-21449)
     */
    CERT_INVALID_ECDSA_VALUE(WRONG),
    /**
     * A content type of the signature is not the expected one.
     * Authenticode_PE: "contentType must be set to SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4)", the type of
     * the SpcAttributeTypeAndOptionalValue "is set to SPC_PE_IMAGE_DATAOBJ OID (1.3.6.1.4.1.311.2.1.15)".
     * Runtime: not tested.
     */
    CERT_WRONG_CONTENT_TYPE(WRONG),
    /**
     * The digest algorithms of a signature contradict each other.
     * Authenticode_PE: digestAlgorithms "must match the value set in the SignerInfo structure's digestAlgorithm
     * field. If not, the signature has been tampered with", the digestAlgorithm of the DigestInfo "must match" both.
     * Runtime: not tested.
     */
    CERT_DIGEST_ALGORITHM_MISMATCH(WRONG),
    /**
     * A mandatory signed attribute is missing.
     * Authenticode_PE, authenticatedAttributes: "The following attributes are always present: contentType ...,
     * messageDigest", "SPC_SP_OPUS_INFO_OBJID ... is always present in an Authenticode signature".
     * Runtime: not tested.
     */
    CERT_MISSING_SIGNED_ATTRIBUTE(WRONG),
    /**
     * The padding of a WIN_CERTIFICATE is not zero
     */
    CERT_NONZERO_PADDING(WRONG),
    /**
     * A certificate serial number is longer than 20 bytes (RFC 5280)
     */
    CERT_OVERSIZED_SERIAL(WRONG),
    /**
     * A certificate serial number is zero or negative. RFC 5280 section 4.1.2.2:
     * "The serial number MUST be a positive integer"
     */
    CERT_NON_POSITIVE_SERIAL(WRONG),
    /**
     * An object identifier has more than 64 content bytes or an arc beyond the long range.
     * RFC 5280 appendix B: OIDs have no maximum size, implementations must support
     * 20 arcs, arcs below 2^28 and 100 characters in dotted notation, and CAs "SHOULD NOT
     * issue certificates that contain OIDs that exceed these requirements". Every OID
     * beyond the parser limit exceeds those bounds.
     */
    CERT_OVERSIZED_OID(WRONG),
    /**
     * The page hashes are malformed.
     * Not grounded in Authenticode_PE: it says the binary structure of the page hashes "is outside the scope of this
     * paper". The type is a judgement, a page hash that does not match the page is an integrity failure like
     * CERT_IMAGE_DIGEST_MISMATCH.
     */
    CERT_INVALID_PAGE_HASHES(WRONG),
    /**
     * MD2 or MD5 is used, which allow collisions (e.g. Flame)
     */
    CERT_WEAK_DIGEST(DEPRECATED),
    /**
     * SHA-1 is used
     */
    CERT_SHA1_DIGEST(DEPRECATED),
    /**
     * The signature uses BER instead of DER encoding.
     * Authenticode_PE does not require DER and PKCS #7 permits BER, so this is not forbidden.
     */
    CERT_BER_ENCODING(NON_DEFAULT),
    /**
     * The signer certificate is self-signed
     */
    CERT_SELF_SIGNED_SIGNER(NON_DEFAULT),
    /**
     * The signer certificate was not valid at the signing time (RFC 5280
     * section 6.1.3 (a)(2): the validity period must include the time)
     */
    CERT_SIGNER_NOT_VALID_AT_SIGNING_TIME(WRONG),
    /**
     * An unauthenticated attribute has an unknown type
     */
    CERT_UNKNOWN_UNAUTH_ATTRIBUTE(NON_DEFAULT),
    /**
     * An unauthenticated attribute has a type that Authenticode does not use
     * there, e.g. any unauthenticated attribute of a timestamp signer or a
     * signed attribute type, data that the signature does not cover.
     * Authenticode_PE (2008): the unauthenticated attributes of the signer contain "only one Attribute object, which
     * contains an Authenticode timestamp", the SignerInfo of a timestamp has authenticatedAttributes only. Nested
     * signatures of the signer are parsed and not reported here. Runtime: not tested.
     */
    CERT_UNEXPECTED_UNAUTH_ATTRIBUTE(WRONG),
    /**
     * The SpcRelaxedPEMarkerCheck attribute is present
     */
    CERT_RELAXED_PE_MARKER_CHECK(NON_DEFAULT),
    /**
     * An algorithm of the signature is not supported
     */
    CERT_UNSUPPORTED_ALGORITHM(NON_DEFAULT);

    private final AnomalyType superType;

    AnomalySubType(AnomalyType superType) {
        this.superType = superType;
    }

    public AnomalyType getSuperType() {
        return superType;
    }
}
