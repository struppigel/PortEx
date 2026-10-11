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

import com.google.common.base.Optional;
import io.github.struppigel.parser.AnalysisInterruptedException;
import io.github.struppigel.parser.Interruption;
import io.github.struppigel.parser.Location;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.RichHeader;
import io.github.struppigel.parser.StandardField;
import io.github.struppigel.parser.coffheader.COFFFileHeader;
import io.github.struppigel.parser.optheader.DataDirEntry;
import io.github.struppigel.parser.optheader.DataDirectoryKey;
import io.github.struppigel.parser.optheader.OptionalHeader;
import io.github.struppigel.parser.optheader.StandardFieldEntryKey;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.parser.sections.SectionCharacteristic;
import io.github.struppigel.parser.sections.SectionHeader;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.parser.sections.SectionTable;
import io.github.struppigel.parser.sections.cert.AuthenticodeCertificate;
import io.github.struppigel.parser.sections.cert.AuthenticodeSignature;
import io.github.struppigel.parser.sections.cert.CertificateIssue;
import io.github.struppigel.parser.sections.cert.CertificateIssueType;
import io.github.struppigel.parser.sections.cert.CertificateTable;
import io.github.struppigel.parser.sections.cert.SignerInfo;
import io.github.struppigel.parser.sections.cert.WinCertificate;
import io.github.struppigel.parser.sections.clr.CLIHeaderKey;
import io.github.struppigel.parser.sections.clr.CLRSection;
import io.github.struppigel.parser.sections.clr.CLRTable;
import io.github.struppigel.parser.sections.clr.CLRTableEntry;
import io.github.struppigel.parser.sections.clr.MetadataRoot;
import io.github.struppigel.parser.sections.clr.MetadataRootKey;
import io.github.struppigel.parser.sections.clr.StreamHeader;
import io.github.struppigel.parser.sections.debug.DebugDirectoryEntry;
import io.github.struppigel.parser.sections.debug.DebugDirectoryKey;
import io.github.struppigel.parser.sections.debug.DebugSection;
import io.github.struppigel.parser.sections.edata.ExportDirectory;
import io.github.struppigel.parser.sections.edata.ExportDirectoryKey;
import io.github.struppigel.parser.sections.edata.ExportSection;
import io.github.struppigel.parser.sections.idata.BoundImportSection;
import io.github.struppigel.parser.sections.idata.DelayLoadSection;
import io.github.struppigel.parser.sections.idata.DirectoryEntry;
import io.github.struppigel.parser.sections.idata.DirectoryEntryKey;
import io.github.struppigel.parser.sections.idata.ImportSection;
import io.github.struppigel.parser.sections.idata.LookupTableEntry;
import io.github.struppigel.parser.sections.idata.NameEntry;
import io.github.struppigel.parser.sections.idata.NullEntry;
import io.github.struppigel.parser.sections.reloc.BaseRelocBlock;
import io.github.struppigel.parser.sections.reloc.RelocationSection;
import io.github.struppigel.parser.sections.rsrc.DataEntry;
import io.github.struppigel.parser.sections.rsrc.ID;
import io.github.struppigel.parser.sections.rsrc.IDOrName;
import io.github.struppigel.parser.sections.rsrc.Level;
import io.github.struppigel.parser.sections.rsrc.Name;
import io.github.struppigel.parser.sections.rsrc.Resource;
import io.github.struppigel.parser.sections.rsrc.ResourceDirectory;
import io.github.struppigel.parser.sections.rsrc.ResourceDirectoryEntry;
import io.github.struppigel.parser.sections.rsrc.ResourceSection;
import io.github.struppigel.parser.sections.rsrc.SubDirEntry;
import io.github.struppigel.tools.Overlay;
import io.github.struppigel.tools.anomalies.Anomaly;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builds a {@link StructureMap} of a PE file.
 * <p>
 * The builder reads the structures from the PEData and its section loader. It
 * cleans the locations it gets: locations outside the file are dropped,
 * locations that exceed the file are cut and flagged as clipped, and the
 * locations of each region are sorted and merged. Failures while mapping one
 * group of structures are logged and only drop that group.
 * <p>
 * Building is not thread-safe because PEData caches are not. Build the map on
 * the thread that owns the PEData; the built map can be shared.
 * <p>
 * Building checks for thread interruption and throws
 * {@link AnalysisInterruptedException} if the thread was interrupted.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class StructureMapBuilder {

    private static final Logger logger = LogManager.getLogger(StructureMapBuilder.class.getName());

    /** default maximum number of regions of a map */
    public static final int DEFAULT_MAX_REGIONS = 250_000;
    /** maximum number of regions of one type */
    static final int MAX_REGIONS_PER_TYPE = 100_000;

    private static final int CHECK_INTERVAL = 1024;
    private static final int CLI_HEADER_SIZE = 0x48;
    private static final int MSDOS_HEADER_SIZE = 0x40;
    private static final int PE_SIGNATURE_SIZE = 4;
    private static final int RICH_XOR_KEY_SIZE = 4;
    private static final int SECTION_HEADER_SIZE = 40;
    private static final int DATA_DIR_ENTRY_SIZE = 8;
    private static final int RELOC_BLOCK_HEADER_SIZE = 8;
    private static final int RESOURCE_DATA_ENTRY_SIZE = 16;

    private final PEData data;
    private Detail detail = Detail.COARSE;
    private List<Anomaly> anomalies = Collections.emptyList();
    private List<SignatureHit> signatureHits = Collections.emptyList();
    private final List<CustomRegion> customRegions = new ArrayList<>();
    private int maxRegions = DEFAULT_MAX_REGIONS;

    /**
     * Creates a builder for the structure map of a PE file.
     *
     * @param data the parsed PE file
     */
    public StructureMapBuilder(PEData data) {
        this.data = Objects.requireNonNull(data);
    }

    /**
     * Sets the level of detail, default is {@link Detail#COARSE}.
     *
     * @param detail the level of detail
     * @return this builder
     */
    public StructureMapBuilder withDetail(Detail detail) {
        this.detail = Objects.requireNonNull(detail);
        return this;
    }

    /**
     * Adds anomalies as {@link RegionType#ANOMALY} markers. Anomalies without
     * location are left out.
     *
     * @param anomalies the anomalies, e.g. from
     *            {@link io.github.struppigel.tools.anomalies.PEAnomalyScanner}
     * @return this builder
     */
    public StructureMapBuilder withAnomalies(List<Anomaly> anomalies) {
        this.anomalies = new ArrayList<>(anomalies);
        return this;
    }

    /**
     * Adds signature matches as {@link RegionType#SIGNATURE_MATCH} markers.
     *
     * @param hits the matches, see {@link SignatureHit#fromMatches(List)}
     * @return this builder
     */
    public StructureMapBuilder withSignatureMatches(List<SignatureHit> hits) {
        this.signatureHits = new ArrayList<>(hits);
        return this;
    }

    /**
     * Adds one {@link RegionType#CUSTOM} region. Can be called several times.
     *
     * @param name the name of the region, e.g. "Read Chunks"
     * @param locations the file ranges of the region
     * @return this builder
     */
    public StructureMapBuilder withCustomRegions(String name, List<PhysicalLocation> locations) {
        customRegions.add(new CustomRegion(Objects.requireNonNull(name), new ArrayList<>(locations)));
        return this;
    }

    /**
     * Limits the number of regions, default is {@link #DEFAULT_MAX_REGIONS}.
     * If a file has more structures, the map is truncated and summary regions
     * stand in for the left out ones.
     *
     * @param maxRegions the maximum number of regions, at least 1
     * @return this builder
     */
    public StructureMapBuilder withMaxRegions(int maxRegions) {
        if (maxRegions < 1) {
            throw new IllegalArgumentException("maxRegions must be at least 1, but was " + maxRegions);
        }
        this.maxRegions = maxRegions;
        return this;
    }

    /**
     * Builds the structure map.
     *
     * @return the structure map
     * @throws AnalysisInterruptedException if the thread was interrupted
     */
    public StructureMap build() {
        return new Build().run();
    }

    private static final class CustomRegion {
        final String name;
        final List<PhysicalLocation> locations;

        CustomRegion(String name, List<PhysicalLocation> locations) {
            this.name = name;
            this.locations = locations;
        }
    }

    /** a group of structures that is mapped as a whole or not at all */
    private interface Group {
        void map() throws Exception;
    }

    /** state of one build */
    private final class Build {

        private final long fileLength = data.getFile().length();
        private final SectionLoader loader = new SectionLoader(data);
        private final List<FileRegion> regions = new ArrayList<>();
        private final int[] typeCounts = new int[RegionType.values().length];
        private final Map<RegionType, Dropped> dropped = new EnumMap<>(RegionType.class);
        private boolean truncated = false;
        private boolean certificateTableMapped = false;

        StructureMap run() {
            group("headers", this::mapHeaders);
            group("sections", this::mapSections);
            group("overlay", this::mapOverlay);
            group("imports", this::mapImports);
            group("delay-load imports", this::mapDelayImports);
            group("bound imports", this::mapBoundImports);
            group("exports", this::mapExports);
            group("relocations", this::mapRelocations);
            group("debug directory", this::mapDebug);
            group("resources", this::mapResources);
            group(".NET metadata", this::mapClr);
            group("certificates", this::mapCertificates);
            group("data directories", this::mapDeclaredDirectories);
            group("unmapped gaps", this::mapUnmapped);
            group("entry point", this::mapEntryPoint);
            group("signature matches", this::mapSignatureHits);
            group("anomalies", this::mapAnomalies);
            group("custom regions", this::mapCustomRegions);
            addSummaries();
            Interruption.checkInterrupt();
            return new StructureMap(fileLength, regions, truncated);
        }

        private void group(String name, Group group) {
            Interruption.checkInterrupt();
            try {
                group.map();
            } catch (AnalysisInterruptedException e) {
                throw e;
            } catch (Exception e) {
                logger.warn("could not map " + name + " of " + data.getFile().getName() + ": " + e);
            }
        }

        /* ---------------------------------------------------------------- */
        /* headers                                                          */
        /* ---------------------------------------------------------------- */

        private void mapHeaders() {
            OptionalHeader opt = data.getOptionalHeader();
            SectionTable table = data.getSectionTable();
            long tableEnd = table.getOffset() + table.getSize();
            long sizeOfHeaders = opt.get(WindowsEntryKey.SIZE_OF_HEADERS);
            long headersEnd = sizeOfHeaders > 0 ? sizeOfHeaders : tableEnd;
            FileRegion headers = add(null, RegionType.HEADERS, "Headers", range(0, headersEnd));

            FileRegion msdos = add(headers, RegionType.MSDOS_HEADER, "MSDOS Header", range(0, MSDOS_HEADER_SIZE));
            if (fine()) {
                mapFields(msdos, data.getMSDOSHeader().getHeaderEntries(), 0);
            }
            long peSig = data.getPESignature().getOffset();
            FileRegion stub = add(headers, RegionType.MSDOS_STUB, "MSDOS Stub", range(MSDOS_HEADER_SIZE, peSig));
            java.util.Optional<RichHeader> rich = data.maybeGetRichHeader();
            if (rich.isPresent()) {
                PhysicalLocation loc = rich.get().getPhysicalLocation();
                // the location ends after "Rich", the XOR key follows
                add(stub != null ? stub : headers, RegionType.RICH_HEADER, "Rich Header",
                        range(loc.from(), loc.from() + loc.size() + RICH_XOR_KEY_SIZE));
            }
            add(headers, RegionType.PE_SIGNATURE, "PE Signature", range(peSig, peSig + PE_SIGNATURE_SIZE));

            COFFFileHeader coff = data.getCOFFFileHeader();
            FileRegion coffRegion = add(headers, RegionType.COFF_FILE_HEADER, "COFF File Header",
                    range(coff.getOffset(), coff.getOffset() + COFFFileHeader.HEADER_SIZE));
            if (fine()) {
                mapFields(coffRegion, coff.getHeaderEntries(), 0);
            }
            mapOptionalHeader(headers, opt, coff);

            FileRegion tableRegion = add(headers, RegionType.SECTION_TABLE, "Section Table",
                    range(table.getOffset(), tableEnd));
            int i = 0;
            for (SectionHeader header : table.getSectionHeaders()) {
                checkInterrupt(i++);
                // SectionHeader.getOffset() is relative to the section table
                long offset = table.getOffset() + header.getOffset();
                FileRegion headerRegion = add(tableRegion, RegionType.SECTION_HEADER, "Section Header "
                                + header.getNumber() + nameSuffix(header.getName()),
                        range(offset, offset + SECTION_HEADER_SIZE), sectionAttributes(header));
                if (fine()) {
                    // the field offsets of all section headers are those of the first one
                    mapFields(headerRegion, header.getEntryMap().values(), header.getOffset());
                }
            }
        }

        private boolean fine() {
            return detail == Detail.FINE;
        }

        /** adds one region per field, shifted by the given number of bytes */
        private void mapFields(FileRegion parent, Collection<StandardField> fields, long shift) {
            if (parent == null) {
                return;
            }
            List<StandardField> sorted = new ArrayList<>(fields);
            Collections.sort(sorted, new Comparator<StandardField>() {
                @Override
                public int compare(StandardField a, StandardField b) {
                    return Long.compare(a.getOffset(), b.getOffset());
                }
            });
            for (StandardField field : sorted) {
                if (field.getSize() <= 0) {
                    continue;
                }
                long start = field.getOffset() + shift;
                Map<String, String> attributes = attributes(FileRegion.ATTR_VALUE, StructureMap.hex(field.getValue()));
                attributes.put(FileRegion.ATTR_DESCRIPTION, field.getDescription());
                add(parent, RegionType.HEADER_FIELD, String.valueOf(field.getKey()),
                        range(start, start + field.getSize()), attributes);
            }
        }

        private void mapOptionalHeader(FileRegion headers, OptionalHeader opt, COFFFileHeader coff) {
            long offset = opt.getOffset();
            // OptionalHeader.getSize() is the number of bytes read, not SizeOfOptionalHeader
            FileRegion optRegion = add(headers, RegionType.OPTIONAL_HEADER, "Optional Header",
                    range(offset, offset + coff.getSizeOfOptionalHeader()));
            FileRegion parent = optRegion != null ? optRegion : headers;
            long standardSize;
            long dataDirOffset;
            switch (opt.getMagicNumber()) {
                case PE32:
                    standardSize = 28;
                    dataDirOffset = 96;
                    break;
                case PE32_PLUS:
                    standardSize = 24;
                    dataDirOffset = 112;
                    break;
                default:
                    return;
            }
            FileRegion standard = add(parent, RegionType.STANDARD_FIELDS, "Standard Fields",
                    range(offset, offset + standardSize));
            FileRegion windows = add(parent, RegionType.WINDOWS_FIELDS, "Windows Fields",
                    range(offset + standardSize, offset + dataDirOffset));
            if (fine()) {
                mapFields(standard, opt.getStandardFields().values(), 0);
                mapFields(windows, opt.getWindowsSpecificFields().values(), 0);
            }
            long entries = Math.max(0, Math.min(16, opt.get(WindowsEntryKey.NUMBER_OF_RVA_AND_SIZES)));
            long dirStart = offset + dataDirOffset;
            FileRegion dir = add(parent, RegionType.DATA_DIRECTORY, "Data Directory",
                    range(dirStart, dirStart + entries * DATA_DIR_ENTRY_SIZE));
            List<DataDirEntry> dirEntries = new ArrayList<>(opt.getDataDirectory().values());
            Collections.sort(dirEntries, new Comparator<DataDirEntry>() {
                @Override
                public int compare(DataDirEntry a, DataDirEntry b) {
                    return a.getKey().compareTo(b.getKey());
                }
            });
            for (DataDirEntry entry : dirEntries) {
                long entryOffset = entry.getTableEntryOffset();
                add(dir != null ? dir : parent, RegionType.DATA_DIRECTORY_ENTRY,
                        entry.getKey().toString(), range(entryOffset, entryOffset + DATA_DIR_ENTRY_SIZE),
                        attributes(FileRegion.ATTR_DATA_DIRECTORY, entry.getKey().toString()));
            }
        }

        /* ---------------------------------------------------------------- */
        /* sections and overlay                                             */
        /* ---------------------------------------------------------------- */

        private void mapSections() {
            boolean lowAlign = data.getOptionalHeader().isLowAlignmentMode();
            int i = 0;
            for (SectionHeader header : data.getSectionTable().getSectionHeaders()) {
                checkInterrupt(i++);
                long start = header.getAlignedPointerToRaw(lowAlign);
                long size = loader.getReadSize(header);
                add(null, RegionType.SECTION, "Section " + header.getNumber() + nameSuffix(header.getName()),
                        range(start, start + size), sectionAttributes(header));
            }
        }

        private Map<String, String> sectionAttributes(SectionHeader header) {
            Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put(FileRegion.ATTR_SECTION_NUMBER, String.valueOf(header.getNumber()));
            attributes.put(FileRegion.ATTR_SECTION_NAME, header.getName());
            StringBuilder characteristics = new StringBuilder();
            for (SectionCharacteristic c : header.getCharacteristics()) {
                if (characteristics.length() > 0) {
                    characteristics.append(", ");
                }
                characteristics.append(c.name());
            }
            attributes.put(FileRegion.ATTR_CHARACTERISTICS, characteristics.toString());
            return attributes;
        }

        private void mapOverlay() throws Exception {
            Overlay overlay = new Overlay(data);
            if (overlay.exists()) {
                add(null, RegionType.OVERLAY, "Overlay", range(overlay.getOffset(), fileLength));
            }
        }

        /* ---------------------------------------------------------------- */
        /* special sections                                                 */
        /* ---------------------------------------------------------------- */

        private void mapImports() throws Exception {
            Optional<ImportSection> maybe = loader.maybeLoadImportSection();
            if (!maybe.isPresent() || maybe.get().isEmpty()) {
                return;
            }
            ImportSection section = maybe.get();
            FileRegion imports = add(null, RegionType.IMPORT_SECTION, "Imports", section.getPhysicalLocations());
            int i = 0;
            for (DirectoryEntry entry : section.getDirectory()) {
                checkInterrupt(i);
                String name = entry.name() != null ? entry.name() : "DLL #" + i;
                FileRegion dll = add(imports, RegionType.IMPORT_DLL, name, fromScala(entry.getPhysicalLocations()),
                        attributes(FileRegion.ATTR_DLL_NAME, name));
                if (fine() && dll != null) {
                    mapImportDetails(dll, entry, name);
                }
                i++;
            }
        }

        /** descriptor, lookup table, address table, DLL name and hint/name entries of one DLL */
        private void mapImportDetails(FileRegion dll, DirectoryEntry entry, String name) {
            add(dll, RegionType.IMPORT_DESCRIPTOR, "Descriptor", range(entry.offset(), entry.offset() + entry.size()));
            List<LookupTableEntry> lookups = entry.getLookupTableEntries();
            int entrySize = data.getOptionalHeader().getMagicNumber() == OptionalHeader.MagicNumber.PE32_PLUS ? 8 : 4;
            int functions = 0;
            List<PhysicalLocation> lookupLocations = new ArrayList<>();
            for (LookupTableEntry lookup : lookups) {
                lookupLocations.add(new PhysicalLocation(lookup.offset(), lookup.size()));
                if (!(lookup instanceof NullEntry)) {
                    functions++;
                }
                entrySize = lookup.size();
            }
            long iltRva = entry.get(DirectoryEntryKey.I_LOOKUP_TABLE_RVA);
            if (iltRva != 0) {
                // without lookup table RVA the entries were read from the address table
                add(dll, RegionType.IMPORT_LOOKUP_TABLE, "ILT", lookupLocations);
            }
            long iatRva = entry.get(DirectoryEntryKey.I_ADDR_TABLE_RVA);
            Optional<Long> iat = iatRva == 0 ? Optional.<Long>absent() : loader.maybeGetFileOffset(iatRva);
            if (iat.isPresent()) {
                // the address table has one entry per import plus the terminating zero entry
                long size = (functions + 1L) * entrySize;
                addRegion(dll, RegionType.IMPORT_ADDRESS_TABLE, "IAT", range(iat.get(), iat.get() + size),
                        Collections.<String, String>emptyMap(), true);
            }
            long nameRva = entry.get(DirectoryEntryKey.NAME_RVA);
            Optional<Long> nameOffset = nameRva == 0 ? Optional.<Long>absent() : loader.maybeGetFileOffset(nameRva);
            if (nameOffset.isPresent() && entry.name() != null) {
                add(dll, RegionType.IMPORT_DLL_NAME, "DLL Name",
                        range(nameOffset.get(), nameOffset.get() + name.length() + 1));
            }
            int k = 0;
            for (LookupTableEntry lookup : lookups) {
                checkInterrupt(k++);
                if (lookup instanceof NameEntry) {
                    NameEntry nameEntry = (NameEntry) lookup;
                    String function = nameEntry.hintNameEntry().name();
                    long offset = nameEntry.hintNameEntry().fileOffset();
                    // two byte hint, the name and its terminating zero
                    add(dll, RegionType.IMPORT_HINT_NAME, function, range(offset, offset + 2 + function.length() + 1),
                            attributes(FileRegion.ATTR_FUNCTION, function));
                }
            }
        }

        private void mapDelayImports() throws Exception {
            Optional<DelayLoadSection> maybe = loader.maybeLoadDelayLoadSection();
            if (maybe.isPresent() && !maybe.get().isEmpty()) {
                add(null, RegionType.DELAY_IMPORT_SECTION, "Delay Imports", maybe.get().getPhysicalLocations());
            }
        }

        private void mapBoundImports() throws Exception {
            Optional<BoundImportSection> maybe = loader.maybeLoadBoundImportSection();
            if (maybe.isPresent()) {
                add(null, RegionType.BOUND_IMPORT_SECTION, "Bound Imports", maybe.get().getPhysicalLocations());
            }
        }

        private void mapExports() throws Exception {
            Optional<ExportSection> maybe = loader.maybeLoadExportSection();
            if (maybe.isPresent() && !maybe.get().isEmpty()) {
                FileRegion exports = add(null, RegionType.EXPORT_SECTION, "Exports",
                        maybe.get().getPhysicalLocations());
                if (fine() && exports != null) {
                    mapExportDetails(exports, maybe.get());
                }
            }
        }

        /** directory, address table, name pointer table, ordinal table and names */
        private void mapExportDetails(FileRegion exports, ExportSection section) {
            ExportDirectory directory = section.getExportDirectory();
            long offset = section.getOffset();
            add(exports, RegionType.EXPORT_DIRECTORY, "Export Directory", range(offset, offset + directory.size()));
            addTable(exports, RegionType.EXPORT_ADDRESS_TABLE, "EAT",
                    directory.get(ExportDirectoryKey.EXPORT_ADDR_TABLE_RVA),
                    directory.get(ExportDirectoryKey.ADDR_TABLE_ENTRIES) * 4);
            addTable(exports, RegionType.EXPORT_NAME_POINTER_TABLE, "Name Pointer Table",
                    directory.get(ExportDirectoryKey.NAME_POINTER_RVA),
                    directory.get(ExportDirectoryKey.NR_OF_NAME_POINTERS) * 4);
            addTable(exports, RegionType.EXPORT_ORDINAL_TABLE, "Ordinal Table",
                    directory.get(ExportDirectoryKey.ORDINAL_TABLE_RVA),
                    directory.get(ExportDirectoryKey.NR_OF_NAME_POINTERS) * 2);
            int k = 0;
            // a Scala map of Long keys, which Java sees as Object
            for (Map.Entry<?, String> e : section.getPointerNameMap().entrySet()) {
                checkInterrupt(k++);
                Optional<Long> nameOffset = loader.maybeGetFileOffset(((Number) e.getKey()).longValue());
                if (nameOffset.isPresent()) {
                    String function = e.getValue();
                    add(exports, RegionType.EXPORT_NAME, function,
                            range(nameOffset.get(), nameOffset.get() + function.length() + 1),
                            attributes(FileRegion.ATTR_FUNCTION, function));
                }
            }
        }

        /** a table at an RVA with a size computed from its declared number of entries */
        private void addTable(FileRegion parent, RegionType type, String name, long rva, long size) {
            if (rva == 0 || size <= 0) {
                return;
            }
            Optional<Long> offset = loader.maybeGetFileOffset(rva);
            if (offset.isPresent()) {
                add(parent, type, name, range(offset.get(), offset.get() + size));
            }
        }

        private void mapRelocations() throws Exception {
            Optional<RelocationSection> maybe = loader.maybeLoadRelocSection();
            if (!maybe.isPresent() || maybe.get().isEmpty()) {
                return;
            }
            RelocationSection section = maybe.get();
            // the 8 byte block header is read even if the block size is smaller
            List<List<PhysicalLocation>> blocks = new ArrayList<>();
            List<PhysicalLocation> all = new ArrayList<>();
            for (BaseRelocBlock block : section.getRelocBlocks()) {
                List<PhysicalLocation> locations = range(block.fileOffset(),
                        block.fileOffset() + Math.max(RELOC_BLOCK_HEADER_SIZE, block.blockSize()));
                blocks.add(locations);
                all.addAll(locations);
            }
            FileRegion relocs = add(null, RegionType.RELOCATION, "Relocations", all);
            int i = 0;
            for (BaseRelocBlock block : section.getRelocBlocks()) {
                checkInterrupt(i);
                add(relocs, RegionType.RELOCATION_BLOCK, "Block " + StructureMap.hex(block.pageRVA()), blocks.get(i));
                i++;
            }
        }

        private void mapDebug() throws Exception {
            Optional<DebugSection> maybe = loader.maybeLoadDebugSection();
            if (!maybe.isPresent()) {
                return;
            }
            DebugSection debug = maybe.get();
            FileRegion directory = add(null, RegionType.DEBUG_DIRECTORY, "Debug Directory",
                    range(debug.getOffset(), debug.getOffset() + debug.getSize()));
            int i = 0;
            for (DebugDirectoryEntry entry : debug.getEntries()) {
                checkInterrupt(i++);
                String type = entry.getDebugType() != null ? entry.getDebugType().toString()
                        : entry.getTypeDescription();
                Map<String, String> attributes = attributes(FileRegion.ATTR_DEBUG_TYPE, type);
                long pointer = entry.get(DebugDirectoryKey.POINTER_TO_RAW_DATA);
                long size = entry.get(DebugDirectoryKey.SIZE_OF_DATA);
                FileRegion raw = null;
                if (pointer != 0 && size != 0) {
                    raw = add(directory, RegionType.DEBUG_DATA, "Debug Data (" + type + ")",
                            range(pointer, pointer + size), attributes);
                }
                if (entry.hasCodeView()) {
                    add(raw != null ? raw : directory, RegionType.CODEVIEW, "CodeView",
                            entry.getCodeView().getPhysicalLocations(), attributes);
                }
            }
        }

        private void mapResources() throws Exception {
            Optional<ResourceSection> maybe = loader.maybeLoadResourceSection();
            if (!maybe.isPresent()) {
                return;
            }
            ResourceSection rsrc = maybe.get();
            FileRegion table = add(null, RegionType.RESOURCE_DIRECTORY, "Resources", rsrc.getPhysicalLocations());
            int i = 0;
            for (Resource resource : rsrc.getResources()) {
                checkInterrupt(i++);
                PhysicalLocation loc = resource.rawBytesLocation();
                if (loc.from() <= 0) {
                    continue;
                }
                Map<Level, IDOrName> ids = resource.getLevelIDs();
                String type = idString(ids.get(Level.typeLevel()), true);
                String name = idString(ids.get(Level.nameLevel()), false);
                String language = idString(ids.get(Level.languageLevel()), false);
                Map<String, String> attributes = new LinkedHashMap<>();
                StringBuilder label = new StringBuilder();
                if (type != null) {
                    attributes.put(FileRegion.ATTR_RESOURCE_TYPE, type);
                    label.append(type);
                }
                if (name != null) {
                    attributes.put(FileRegion.ATTR_RESOURCE_NAME, name);
                    label.append(label.length() > 0 ? "/" : "").append(name);
                }
                if (language != null) {
                    attributes.put(FileRegion.ATTR_RESOURCE_LANGUAGE, language);
                    label.append(label.length() > 0 ? "/" : "").append(language);
                }
                add(table, RegionType.RESOURCE, label.length() > 0 ? label.toString() : "Resource",
                        Collections.singletonList(loc), attributes);
            }
            if (fine() && table != null) {
                mapResourceTree(table, rsrc.getResourceTree(), "Root", 0);
            }
        }

        /** directory tables, data entries and name strings of the resource tree */
        private void mapResourceTree(FileRegion parent, ResourceDirectory directory, String path, int depth) {
            Interruption.checkInterrupt();
            add(parent, RegionType.RESOURCE_DIRECTORY_TABLE, "Directory " + path,
                    Collections.singletonList(directory.getPhysicalLocation()));
            Level level = depth == 0 ? Level.typeLevel() : depth == 1 ? Level.nameLevel() : Level.languageLevel();
            for (ResourceDirectoryEntry entry : directory.getEntries()) {
                IDOrName id;
                long rsrcOffset;
                if (entry instanceof SubDirEntry) {
                    id = ((SubDirEntry) entry).id();
                    rsrcOffset = ((SubDirEntry) entry).rsrcOffset();
                } else if (entry instanceof DataEntry) {
                    id = ((DataEntry) entry).id();
                    rsrcOffset = ((DataEntry) entry).rsrcOffset();
                } else {
                    continue;
                }
                String idString = idString(id, level.equals(Level.typeLevel()));
                String entryPath = depth == 0 ? idString : path + "/" + idString;
                if (id instanceof Name) {
                    // the name RVA has the high bit set, the string starts with a 2 byte length
                    Name name = (Name) id;
                    long offset = (name.rva() & 0x7FFFFFFFL) + rsrcOffset;
                    add(parent, RegionType.RESOURCE_NAME, "Name " + name.name(),
                            range(offset, offset + 2 + 2L * name.name().length()));
                }
                if (entry instanceof SubDirEntry) {
                    mapResourceTree(parent, ((SubDirEntry) entry).table(), entryPath, depth + 1);
                } else {
                    long offset = ((DataEntry) entry).data().getOffset();
                    add(parent, RegionType.RESOURCE_DATA_ENTRY, "Data Entry " + entryPath,
                            range(offset, offset + RESOURCE_DATA_ENTRY_SIZE));
                }
            }
        }

        private String idString(IDOrName id, boolean symbolic) {
            if (id instanceof ID) {
                return symbolic ? ((ID) id).idString() : String.valueOf(((ID) id).id());
            }
            if (id instanceof Name) {
                return ((Name) id).name();
            }
            return null;
        }

        private void mapClr() {
            if (!data.getOptionalHeader().maybeGetDataDirEntry(DataDirectoryKey.CLR_RUNTIME_HEADER).isPresent()) {
                return;
            }
            java.util.Optional<CLRSection> maybe = data.loadClrSection();
            if (!maybe.isPresent()) {
                return;
            }
            CLRSection clr = maybe.get();
            add(null, RegionType.CLR_HEADER, "CLR Header",
                    range(clr.getOffset(), clr.getOffset() + CLI_HEADER_SIZE));
            long rva = clr.getCliHeaderEntries().get(CLIHeaderKey.META_DATA_RVA).getValue();
            long size = clr.getCliHeaderEntries().get(CLIHeaderKey.META_DATA_SIZE).getValue();
            Optional<Long> maybeOffset = loader.maybeGetFileOffset(rva);
            if (!maybeOffset.isPresent()) {
                return;
            }
            long offset = maybeOffset.get();
            FileRegion metadata = add(null, RegionType.CLR_METADATA, ".NET Metadata", range(offset, offset + size));
            FileRegion parent = metadata;
            MetadataRoot root = clr.getMetadataRoot();
            long versionLength = root.getMetaDataEntries().get(MetadataRootKey.LENGTH).getValue();
            // signature, versions, reserved, length, version string, flags, number of streams
            long rootSize = 16 + alignToFour(versionLength) + 4;
            for (StreamHeader header : root.getStreamHeaders()) {
                // StreamHeader.getHeaderSize does not count the terminating zero
                rootSize += 8 + alignToFour(header.name().length() + 1);
            }
            add(parent, RegionType.METADATA_ROOT, "Metadata Root", range(offset, offset + rootSize));
            for (StreamHeader header : root.getStreamHeaders()) {
                Optional<Long> streamOffset = loader.maybeGetFileOffset(rva + header.offset());
                if (!streamOffset.isPresent()) {
                    continue;
                }
                long start = streamOffset.get();
                FileRegion stream = add(parent, RegionType.CLR_STREAM, header.name(),
                        range(start, start + header.size()), attributes(FileRegion.ATTR_STREAM_NAME, header.name()));
                if (fine() && stream != null && (header.name().equals("#~") || header.name().equals("#-"))) {
                    mapClrTables(stream);
                }
            }
        }

        /** the tables of the #~ stream, each as large as its rows */
        private void mapClrTables(FileRegion stream) {
            for (CLRTable table : data.getCLRTables()) {
                List<CLRTableEntry> rows = table.getEntries();
                if (rows.isEmpty()) {
                    continue;
                }
                long rowSize = 0;
                for (StandardField field : rows.get(0).getCLRFieldsAsStandardFields()) {
                    rowSize += field.getSize();
                }
                long start = table.getRawOffset();
                add(stream, RegionType.CLR_TABLE, table.getTableName(), range(start, start + rowSize * rows.size()),
                        attributes(FileRegion.ATTR_ROWS, String.valueOf(rows.size())));
            }
        }

        private long alignToFour(long value) {
            return (value + 3) & ~3L;
        }

        /* ---------------------------------------------------------------- */
        /* certificate table                                                */
        /* ---------------------------------------------------------------- */

        private void mapCertificates() {
            java.util.Optional<CertificateTable> maybe = data.loadCertificateTable();
            if (!maybe.isPresent() || maybe.get().getPhysicalLocations().isEmpty()) {
                return;
            }
            CertificateTable table = maybe.get();
            FileRegion root = addRegion(null, RegionType.CERTIFICATE_TABLE, RegionType.CERTIFICATE_TABLE.getDescription(),
                    table.getPhysicalLocations(),
                    attributes(FileRegion.ATTR_DATA_DIRECTORY, DataDirectoryKey.CERTIFICATE_TABLE.toString()), false);
            if (root == null) {
                return;
            }
            certificateTableMapped = true;
            int i = 0;
            for (WinCertificate entry : table.getEntries()) {
                checkInterrupt(i++);
                String type = entry.getCertificateType().isPresent() ? entry.getCertificateType().get().name()
                        : StructureMap.hex(entry.getCertificateTypeValue());
                FileRegion region = add(root, RegionType.WIN_CERTIFICATE, "WIN_CERTIFICATE " + entry.getIndex(),
                        Collections.singletonList(entry.getPhysicalLocation()),
                        attributes(FileRegion.ATTR_CERTIFICATE_TYPE, type));
                if (fine()) {
                    mapFields(region, entry.getHeaderFields().values(), 0);
                }
                if (entry.getSignature().isPresent()) {
                    mapSignature(region != null ? region : root, entry.getSignature().get());
                }
                if (entry.getX509Certificate().isPresent()) {
                    mapCertificate(region != null ? region : root, entry.getX509Certificate().get());
                }
                if (entry.getPaddingLocation().isPresent()) {
                    add(region != null ? region : root, RegionType.CERTIFICATE_PADDING, "Padding",
                            Collections.singletonList(entry.getPaddingLocation().get()));
                }
            }
            for (CertificateIssue issue : table.getIssues()) {
                if (issue.getType() == CertificateIssueType.DATA_AFTER_PKCS7
                        || issue.getType() == CertificateIssueType.TABLE_EXTRA_DATA) {
                    add(root, RegionType.CERTIFICATE_PADDING, issue.getType().getDescription(), issue.getLocations());
                }
            }
        }

        private void mapSignature(FileRegion parent, AuthenticodeSignature signature) {
            String name = (signature.getNestingLevel() > 0 ? "Nested Signature " : "Signature ") + signature.getNumber();
            FileRegion region = add(parent, RegionType.PKCS7_SIGNED_DATA, name,
                    Collections.singletonList(signature.getLocation()));
            FileRegion owner = region != null ? region : parent;
            int i = 0;
            for (AuthenticodeCertificate certificate : signature.getCertificates()) {
                checkInterrupt(i++);
                mapCertificate(owner, certificate);
            }
            if (fine()) {
                for (SignerInfo signer : signature.getSigners()) {
                    add(owner, RegionType.SIGNER_INFO, "Signer Info", Collections.singletonList(signer.getLocation()));
                }
            }
            for (AuthenticodeSignature nested : signature.getNestedSignatures()) {
                mapSignature(owner, nested);
            }
        }

        private void mapCertificate(FileRegion parent, AuthenticodeCertificate certificate) {
            Map<String, String> attributes = attributes(FileRegion.ATTR_CERTIFICATE_SUBJECT, certificate.getSubjectName());
            attributes.put(FileRegion.ATTR_CERTIFICATE_ISSUER, certificate.getIssuerName());
            add(parent, RegionType.CERTIFICATE, certificate.getSubjectCommonName().orElse(certificate.getSubjectName()),
                    Collections.singletonList(certificate.getLocation()), attributes);
        }

        /* ---------------------------------------------------------------- */
        /* data directories without parser                                  */
        /* ---------------------------------------------------------------- */

        private void mapDeclaredDirectories() {
            Map<DataDirectoryKey, RegionType> declared = new EnumMap<>(DataDirectoryKey.class);
            declared.put(DataDirectoryKey.EXCEPTION_TABLE, RegionType.EXCEPTION_TABLE);
            declared.put(DataDirectoryKey.CERTIFICATE_TABLE, RegionType.CERTIFICATE_TABLE);
            declared.put(DataDirectoryKey.ARCHITECTURE, RegionType.ARCHITECTURE);
            declared.put(DataDirectoryKey.GLOBAL_PTR, RegionType.GLOBAL_PTR);
            declared.put(DataDirectoryKey.TLS_TABLE, RegionType.TLS_DIRECTORY);
            declared.put(DataDirectoryKey.LOAD_CONFIG_TABLE, RegionType.LOAD_CONFIG);
            declared.put(DataDirectoryKey.IAT, RegionType.IAT_DIRECTORY);
            OptionalHeader opt = data.getOptionalHeader();
            for (Map.Entry<DataDirectoryKey, RegionType> e : declared.entrySet()) {
                if (e.getKey() == DataDirectoryKey.CERTIFICATE_TABLE && certificateTableMapped) {
                    continue;
                }
                Optional<DataDirEntry> entry = opt.maybeGetDataDirEntry(e.getKey());
                if (!entry.isPresent()) {
                    continue;
                }
                long va = entry.get().getVirtualAddress();
                long size = entry.get().getDirectorySize();
                if (va == 0 || size == 0) {
                    continue;
                }
                long offset;
                if (e.getKey() == DataDirectoryKey.CERTIFICATE_TABLE) {
                    // the address of the certificate table is a file offset
                    offset = va;
                } else {
                    Optional<Long> maybeOffset = loader.maybeGetFileOffset(va);
                    if (!maybeOffset.isPresent()) {
                        continue;
                    }
                    offset = maybeOffset.get();
                }
                addRegion(null, e.getValue(), e.getValue().getDescription(), range(offset, offset + size),
                        attributes(FileRegion.ATTR_DATA_DIRECTORY, e.getKey().toString()), true);
            }
        }

        /* ---------------------------------------------------------------- */
        /* gaps and markers                                                 */
        /* ---------------------------------------------------------------- */

        /** bytes not covered by headers, sections or overlay */
        private void mapUnmapped() {
            List<PhysicalLocation> covered = new ArrayList<>();
            for (FileRegion region : regions) {
                RegionType type = region.getType();
                if (type == RegionType.SECTION || type == RegionType.OVERLAY || isInHeaders(region)) {
                    covered.addAll(region.getLocations());
                }
            }
            Normalized union = normalize(covered);
            long position = 0;
            int i = 0;
            for (PhysicalLocation loc : union.locations) {
                checkInterrupt(i++);
                if (loc.from() > position) {
                    add(null, RegionType.UNMAPPED, "Unmapped", range(position, loc.from()));
                }
                position = Math.max(position, loc.from() + loc.size());
            }
            if (position < fileLength) {
                add(null, RegionType.UNMAPPED, "Unmapped", range(position, fileLength));
            }
        }

        private boolean isInHeaders(FileRegion region) {
            FileRegion r = region;
            while (r.getParent().isPresent()) {
                r = r.getParent().get();
            }
            return r.getType() == RegionType.HEADERS;
        }

        private void mapEntryPoint() {
            long rva = data.getOptionalHeader().get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT);
            if (rva == 0) {
                return;
            }
            Optional<Long> offset = loader.maybeGetFileOffset(rva);
            if (offset.isPresent()) {
                add(null, RegionType.ENTRY_POINT, "Entry Point", range(offset.get(), offset.get() + 1));
            }
        }

        private void mapSignatureHits() {
            int i = 0;
            for (SignatureHit hit : signatureHits) {
                checkInterrupt(i++);
                Map<String, String> attributes = attributes(FileRegion.ATTR_SIGNATURE_NAME, hit.getName());
                if (!hit.getLocationLabel().isEmpty()) {
                    attributes.put(FileRegion.ATTR_SIGNATURE_LOCATION, hit.getLocationLabel());
                }
                add(null, RegionType.SIGNATURE_MATCH, hit.getName(),
                        range(hit.getOffset(), hit.getOffset() + Math.max(1, hit.getLength())), attributes);
            }
        }

        private void mapAnomalies() {
            int i = 0;
            for (Anomaly anomaly : anomalies) {
                checkInterrupt(i++);
                Map<String, String> attributes = new LinkedHashMap<>();
                attributes.put(FileRegion.ATTR_ANOMALY_TYPE, String.valueOf(anomaly.subtype()));
                attributes.put(FileRegion.ATTR_ANOMALY_KEY, String.valueOf(anomaly.key()));
                attributes.put(FileRegion.ATTR_DESCRIPTION, anomaly.description());
                add(null, RegionType.ANOMALY, anomaly.description(), anomaly.locations(), attributes);
            }
        }

        private void mapCustomRegions() {
            for (CustomRegion custom : customRegions) {
                add(null, RegionType.CUSTOM, custom.name, custom.locations);
            }
        }

        /* ---------------------------------------------------------------- */
        /* region creation                                                  */
        /* ---------------------------------------------------------------- */

        private FileRegion add(FileRegion parent, RegionType type, String name,
                               List<? extends Location> locations) {
            return addRegion(parent, type, name, locations, Collections.<String, String>emptyMap(), false);
        }

        private FileRegion add(FileRegion parent, RegionType type, String name,
                               List<? extends Location> locations, Map<String, String> attributes) {
            return addRegion(parent, type, name, locations, attributes, false);
        }

        /**
         * Adds a region with cleaned locations. Returns null if no location is
         * within the file or if the region limit is reached.
         */
        private FileRegion addRegion(FileRegion parent, RegionType type, String name,
                                     List<? extends Location> locations, Map<String, String> attributes,
                                     boolean declaredOnly) {
            Normalized normalized = normalize(locations);
            if (normalized.locations.isEmpty()) {
                return null;
            }
            if (regions.size() >= maxRegions || typeCounts[type.ordinal()] >= MAX_REGIONS_PER_TYPE) {
                Dropped d = dropped.get(type);
                if (d == null) {
                    d = new Dropped();
                    dropped.put(type, d);
                }
                d.add(normalized.locations);
                truncated = true;
                return null;
            }
            typeCounts[type.ordinal()]++;
            FileRegion region = new FileRegion(regions.size(), name, type, normalized.locations, parent,
                    attributes, normalized.clipped, declaredOnly);
            regions.add(region);
            return region;
        }

        /** adds one region per type that stands in for the left out regions */
        private void addSummaries() {
            for (Map.Entry<RegionType, Dropped> e : dropped.entrySet()) {
                Dropped d = e.getValue();
                RegionType type = e.getKey();
                List<PhysicalLocation> span = Collections.singletonList(
                        new PhysicalLocation(d.start, d.end - d.start));
                regions.add(new FileRegion(regions.size(),
                        d.count + " more " + type.getDescription() + " regions (truncated)", type, span, null,
                        attributes(FileRegion.ATTR_TRUNCATED, String.valueOf(d.count)), false, false));
            }
        }

        /**
         * Drops locations outside the file, cuts locations that exceed the file,
         * then sorts and merges the rest.
         */
        private Normalized normalize(List<? extends Location> locations) {
            List<long[]> ranges = new ArrayList<>(locations.size());
            boolean clipped = false;
            for (Location loc : locations) {
                long from = loc.from();
                long size = loc.size();
                if (from < 0 || from >= fileLength || size <= 0) {
                    continue;
                }
                long end;
                if (size > fileLength - from) {
                    end = fileLength;
                    clipped = true;
                } else {
                    end = from + size;
                }
                ranges.add(new long[]{from, end});
            }
            Collections.sort(ranges, new Comparator<long[]>() {
                @Override
                public int compare(long[] a, long[] b) {
                    return Long.compare(a[0], b[0]);
                }
            });
            List<PhysicalLocation> merged = new ArrayList<>(ranges.size());
            long start = -1;
            long end = -1;
            for (long[] r : ranges) {
                if (start >= 0 && r[0] <= end) {
                    end = Math.max(end, r[1]);
                } else {
                    if (start >= 0) {
                        merged.add(new PhysicalLocation(start, end - start));
                    }
                    start = r[0];
                    end = r[1];
                }
            }
            if (start >= 0) {
                merged.add(new PhysicalLocation(start, end - start));
            }
            return new Normalized(merged, clipped);
        }

        private void checkInterrupt(int counter) {
            if (counter % CHECK_INTERVAL == 0) {
                Interruption.checkInterrupt();
            }
        }
    }

    /** locations from start to end, or none if the range is empty */
    private static List<PhysicalLocation> range(long start, long endExclusive) {
        if (endExclusive <= start) {
            return Collections.emptyList();
        }
        return Collections.singletonList(new PhysicalLocation(start, endExclusive - start));
    }

    private static Map<String, String> attributes(String key, String value) {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put(key, value);
        return attributes;
    }

    private static String nameSuffix(String sectionName) {
        return sectionName == null || sectionName.isEmpty() ? "" : " (" + sectionName + ")";
    }

    private static <T> List<T> fromScala(scala.collection.immutable.List<T> list) {
        List<T> result = new ArrayList<>(list.size());
        scala.collection.Iterator<T> it = list.iterator();
        while (it.hasNext()) {
            result.add(it.next());
        }
        return result;
    }

    private static final class Normalized {
        final List<PhysicalLocation> locations;
        final boolean clipped;

        Normalized(List<PhysicalLocation> locations, boolean clipped) {
            this.locations = locations;
            this.clipped = clipped;
        }
    }

    /** the left out regions of one type */
    private static final class Dropped {
        long count = 0;
        long start = Long.MAX_VALUE;
        long end = Long.MIN_VALUE;

        void add(List<PhysicalLocation> locations) {
            count++;
            start = Math.min(start, locations.get(0).from());
            PhysicalLocation last = locations.get(locations.size() - 1);
            end = Math.max(end, last.from() + last.size());
        }
    }
}
