/*******************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
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
package io.github.struppigel.tools.layout;

import io.github.struppigel.tools.visualizer.ColorableItem;

import static io.github.struppigel.tools.layout.PaintMode.*;

/**
 * The kinds of structures a {@link StructureMap} knows.
 * <p>
 * Each type has a description, the {@link ColorableItem} that gives its base
 * color, the {@link PaintMode} renderers use for it and a priority that breaks
 * ties when two regions are equally specific.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum RegionType {

    /* Headers */
    /** all headers up to SizeOfHeaders */
    HEADERS("Headers", null, NONE, 0),
    /** the formatted MS-DOS header, 0x40 bytes */
    MSDOS_HEADER("MSDOS Header", ColorableItem.MSDOS_HEADER, FILL, 2),
    /** the bytes between the MS-DOS header and the PE signature */
    MSDOS_STUB("MSDOS Stub", ColorableItem.MSDOS_STUB, FILL, 1),
    /** the Rich header including its XOR key */
    RICH_HEADER("Rich Header", ColorableItem.RICH_HEADER, FILL, 2),
    /** the 4 byte PE signature */
    PE_SIGNATURE("PE Signature", ColorableItem.PE_SIGNATURE, MARKER, 3),
    /** the COFF file header */
    COFF_FILE_HEADER("COFF File Header", ColorableItem.COFF_FILE_HEADER, FILL, 2),
    /** the optional header, SizeOfOptionalHeader bytes */
    OPTIONAL_HEADER("Optional Header", ColorableItem.OPTIONAL_HEADER, FILL, 2),
    /** the standard fields of the optional header */
    STANDARD_FIELDS("Standard Fields", ColorableItem.OPTIONAL_HEADER, NONE, 1),
    /** the Windows specific fields of the optional header */
    WINDOWS_FIELDS("Windows Fields", ColorableItem.OPTIONAL_HEADER, NONE, 1),
    /** the data directory of the optional header */
    DATA_DIRECTORY("Data Directory", ColorableItem.OPTIONAL_HEADER, NONE, 1),
    /** one 8 byte entry of the data directory */
    DATA_DIRECTORY_ENTRY("Data Directory Entry", ColorableItem.OPTIONAL_HEADER, NONE, 1),
    /** the section table */
    SECTION_TABLE("Section Table", ColorableItem.SECTION_TABLE, FILL, 2),
    /** one 40 byte section header */
    SECTION_HEADER("Section Header", ColorableItem.SECTION_TABLE, NONE, 1),

    /* Sections */
    /** the raw data of a section */
    SECTION("Section", ColorableItem.SECTION_START, FILL, 1),

    /* Special sections */
    /** the import directory with lookup tables and hint/name entries */
    IMPORT_SECTION("Imports", ColorableItem.IMPORT_SECTION, INSET, 1),
    /** the import structures of one DLL */
    IMPORT_DLL("Import DLL", ColorableItem.IMPORT_SECTION, INSET, 2),
    /** the delay-load import structures */
    DELAY_IMPORT_SECTION("Delay Imports", ColorableItem.DELAY_IMPORT_SECTION, INSET, 1),
    /** the bound import descriptors */
    BOUND_IMPORT_SECTION("Bound Imports", ColorableItem.BOUND_IMPORT_SECTION, INSET, 1),
    /** the export directory and its tables */
    EXPORT_SECTION("Exports", ColorableItem.EXPORT_SECTION, INSET, 1),
    /** all base relocation blocks */
    RELOCATION("Relocations", ColorableItem.RELOC_SECTION, INSET, 1),
    /** one base relocation block */
    RELOCATION_BLOCK("Relocation Block", ColorableItem.RELOC_SECTION, INSET, 2),
    /** the debug directory */
    DEBUG_DIRECTORY("Debug Directory", ColorableItem.DEBUG_SECTION, INSET, 1),
    /** the raw data of a debug directory entry */
    DEBUG_DATA("Debug Data", ColorableItem.DEBUG_SECTION, INSET, 2),
    /** the CodeView information of a debug entry */
    CODEVIEW("CodeView", ColorableItem.DEBUG_SECTION, INSET, 3),
    /** the resource table: directories, entries and resource data */
    RESOURCE_DIRECTORY("Resources", ColorableItem.RESOURCE_SECTION, INSET, 1),
    /** the raw data of one resource */
    RESOURCE("Resource", ColorableItem.RESOURCE_SECTION, INSET, 2),

    /* .NET */
    /** the CLR runtime header (CLI header) */
    CLR_HEADER("CLR Header", ColorableItem.CLR_SECTION, FILL, 2),
    /** the .NET metadata, META_DATA_SIZE bytes from the metadata root */
    CLR_METADATA(".NET Metadata", ColorableItem.CLR_SECTION, FILL, 1),
    /** the metadata root with its stream headers */
    METADATA_ROOT("Metadata Root", ColorableItem.CLR_SECTION, FILL, 2),
    /** one .NET metadata stream */
    CLR_STREAM(".NET Stream", ColorableItem.NET_STREAMS, FILL, 2),

    /* Data directories without parser, the ranges are only declared */
    /** the TLS directory */
    TLS_DIRECTORY("TLS Directory", ColorableItem.TLS_SECTION, INSET, 1),
    /** the load configuration directory */
    LOAD_CONFIG("Load Config", ColorableItem.LOAD_CONFIG_SECTION, INSET, 1),
    /** the exception table */
    EXCEPTION_TABLE("Exception Table", ColorableItem.EXCEPTION_SECTION, INSET, 1),
    /** the import address table as declared by the data directory */
    IAT_DIRECTORY("Import Address Table", ColorableItem.IMPORT_SECTION, INSET, 1),
    /** the architecture data directory, reserved */
    ARCHITECTURE("Architecture", null, NONE, 0),
    /** the global pointer data directory */
    GLOBAL_PTR("Global Pointer", null, NONE, 0),

    /* Certificate table, its address is a file offset */
    /** the certificate table with the Authenticode signatures */
    CERTIFICATE_TABLE("Certificate Table", ColorableItem.CERTIFICATE_TABLE, FILL, 2),
    /** one WIN_CERTIFICATE entry of the certificate table */
    WIN_CERTIFICATE("WIN_CERTIFICATE", ColorableItem.CERTIFICATE_TABLE, NONE, 3),
    /** a PKCS#7 SignedData structure, an Authenticode signature */
    PKCS7_SIGNED_DATA("PKCS#7 Signed Data", ColorableItem.CERTIFICATE_TABLE, NONE, 3),
    /** an X.509 certificate embedded in a signature */
    CERTIFICATE("Certificate", ColorableItem.CERTIFICATE_TABLE, INSET, 3),
    /** padding or other data after a signature that the signature does not cover */
    CERTIFICATE_PADDING("Certificate Padding", ColorableItem.CERTIFICATE_TABLE, NONE, 3),

    /* Fine detail, see Detail.FINE; never drawn */
    /** one field of a header */
    HEADER_FIELD("Header Field", null, NONE, 2),
    /** the 20 byte import descriptor of a DLL */
    IMPORT_DESCRIPTOR("Import Descriptor", ColorableItem.IMPORT_SECTION, NONE, 3),
    /** the import lookup table of a DLL */
    IMPORT_LOOKUP_TABLE("Import Lookup Table", ColorableItem.IMPORT_SECTION, NONE, 3),
    /** the import address table of a DLL, derived from its RVA and the number of imports */
    IMPORT_ADDRESS_TABLE("Import Address Table", ColorableItem.IMPORT_SECTION, NONE, 3),
    /** the name of an imported DLL */
    IMPORT_DLL_NAME("DLL Name", ColorableItem.IMPORT_SECTION, NONE, 3),
    /** the hint and name of an imported function */
    IMPORT_HINT_NAME("Hint/Name", ColorableItem.IMPORT_SECTION, NONE, 3),
    /** the 40 byte export directory */
    EXPORT_DIRECTORY("Export Directory", ColorableItem.EXPORT_SECTION, NONE, 2),
    /** the export address table */
    EXPORT_ADDRESS_TABLE("Export Address Table", ColorableItem.EXPORT_SECTION, NONE, 2),
    /** the export name pointer table */
    EXPORT_NAME_POINTER_TABLE("Export Name Pointer Table", ColorableItem.EXPORT_SECTION, NONE, 2),
    /** the export ordinal table */
    EXPORT_ORDINAL_TABLE("Export Ordinal Table", ColorableItem.EXPORT_SECTION, NONE, 2),
    /** the name of an exported function */
    EXPORT_NAME("Export Name", ColorableItem.EXPORT_SECTION, NONE, 3),
    /** a resource directory table with its entries */
    RESOURCE_DIRECTORY_TABLE("Resource Directory Table", ColorableItem.RESOURCE_SECTION, NONE, 2),
    /** a 16 byte resource data entry */
    RESOURCE_DATA_ENTRY("Resource Data Entry", ColorableItem.RESOURCE_SECTION, NONE, 3),
    /** the name string of a resource directory entry */
    RESOURCE_NAME("Resource Name", ColorableItem.RESOURCE_SECTION, NONE, 3),
    /** a table of the #~ stream */
    CLR_TABLE("Metadata Table", ColorableItem.NET_STREAMS, NONE, 3),
    /** the SignerInfo of a signature */
    SIGNER_INFO("Signer Info", ColorableItem.CERTIFICATE_TABLE, NONE, 4),

    /* Other */
    /** the overlay */
    OVERLAY("Overlay", ColorableItem.OVERLAY, FILL, 1),
    /** bytes that are neither headers, nor section data, nor overlay */
    UNMAPPED("Unmapped", ColorableItem.UNMAPPED, FILL, 0),

    /* Markers */
    /** the entry point, one byte */
    ENTRY_POINT("Entry Point", ColorableItem.ENTRY_POINT, MARKER, 4),
    /** a signature match */
    SIGNATURE_MATCH("Signature Match", ColorableItem.SIGNATURE_MATCH, MARKER, 4),
    /** an anomaly */
    ANOMALY("Anomaly", ColorableItem.ANOMALY, MARKER, 4),
    /** a region added by the user, e.g. read chunks */
    CUSTOM("Custom Region", ColorableItem.VISOVERLAY, MARKER, 4);

    private final String description;
    private final ColorableItem colorable;
    private final PaintMode paintMode;
    private final int priority;

    RegionType(String description, ColorableItem colorable, PaintMode paintMode, int priority) {
        this.description = description;
        this.colorable = colorable;
        this.paintMode = paintMode;
        this.priority = priority;
    }

    /**
     * @return a short description of the structure, e.g. "PE Signature"
     */
    public String getDescription() {
        return description;
    }

    /**
     * Returns the item that gives the base color of this type. Types that are
     * never drawn may have none.
     *
     * @return the colorable item, null if the type has no own color
     */
    public ColorableItem getColorableItem() {
        return colorable;
    }

    /**
     * @return how renderers draw regions of this type
     */
    public PaintMode getPaintMode() {
        return paintMode;
    }

    /**
     * Returns the tie-break priority. If two regions have the same size and
     * depth, the one with the higher priority is more specific.
     *
     * @return the priority, higher is more specific
     */
    public int getPriority() {
        return priority;
    }

    /**
     * @return true if the range of this type is only declared by a data
     *         directory entry and not parsed
     */
    public boolean isDeclaredDirectory() {
        switch (this) {
            case TLS_DIRECTORY:
            case LOAD_CONFIG:
            case EXCEPTION_TABLE:
            case IAT_DIRECTORY:
            case ARCHITECTURE:
            case GLOBAL_PTR:
                return true;
            default:
                return false;
        }
    }
}
