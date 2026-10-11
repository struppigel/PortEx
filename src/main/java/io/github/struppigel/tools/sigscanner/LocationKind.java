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
package io.github.struppigel.tools.sigscanner;

import java.util.EnumSet;
import java.util.Optional;

/**
 * The kinds of scan locations a signature can refer to. See docs/SIGNATURES.md
 * for the regions each location covers.
 */
public enum LocationKind {
    /** the whole file */
    FILE("file", false),
    /** the file without its overlay */
    IMAGE("image", true),
    /** the end of the file */
    EOF("eof", false),
    /** the first 0x40 bytes of the file */
    MSDOS_HEADER("msdos_header", true),
    /** from the end of the MS-DOS header to the PE signature */
    MSDOS_STUB("msdos_stub", true),
    /** the Rich header */
    RICH_HEADER("rich_header", true),
    /** all headers up to SizeOfHeaders */
    HEADERS("headers", true),
    /** the overlay */
    OVERLAY("overlay", true),
    /** the entry point up to the end of its section */
    ENTRY_POINT("entrypoint", true),
    /** each exported function up to the end of its section */
    EXPORT("export", true),
    /** the raw data of sections */
    SECTION("section", true),
    /** the raw data of resources */
    RESOURCE("resource", true),
    /** the range a data directory entry declares */
    DATA_DIRECTORY("datadir", true),
    /** the Authenticode certificate table */
    CERTIFICATE("certificate", true),
    /** the raw data of debug directory entries */
    DEBUG_DATA("debug_data", true),
    /** the .NET metadata */
    DOTNET("dotnet", true),
    /** a stream of the .NET metadata */
    DOTNET_STREAM("dotnet_stream", true),
    /** no location, used for matches of signatures that only have conditions */
    METADATA("metadata", true);

    private final String keyword;
    private final boolean peOnly;

    LocationKind(String keyword, boolean peOnly) {
        this.keyword = keyword;
        this.peOnly = peOnly;
    }

    /**
     * @return the keyword of the location in signature databases
     */
    public String keyword() {
        return keyword;
    }

    /**
     * @return true iff the location only exists in PE files
     */
    public boolean isPEOnly() {
        return peOnly;
    }

    /**
     * The locations that are scanned for PE files by default: all except FILE,
     * because every PE file matches the file type signature of PE files at
     * offset 0.
     *
     * @return the default location kinds for PE files
     */
    public static EnumSet<LocationKind> peDefaults() {
        EnumSet<LocationKind> kinds = EnumSet.allOf(LocationKind.class);
        kinds.remove(FILE);
        return kinds;
    }

    /**
     * @param keyword the keyword of a location in a signature database
     * @return the location kind for the keyword
     */
    public static Optional<LocationKind> byKeyword(String keyword) {
        // a plain loop, this runs while signature databases are loaded
        for (LocationKind kind : values()) {
            if (kind != METADATA && kind.keyword.equals(keyword)) {
                return Optional.of(kind);
            }
        }
        return Optional.empty();
    }
}
