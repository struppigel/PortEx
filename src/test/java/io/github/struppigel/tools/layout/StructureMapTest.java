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

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.FileFormatException;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PhysicalLocation;
import io.github.struppigel.parser.optheader.StandardFieldEntryKey;
import io.github.struppigel.parser.sections.SectionHeader;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.parser.sections.idata.Import;
import io.github.struppigel.parser.sections.idata.ImportFunctionExpectations;
import io.github.struppigel.parser.sections.idata.NameImport;
import io.github.struppigel.parser.sections.rsrc.Resource;
import io.github.struppigel.tools.Overlay;
import io.github.struppigel.tools.anomalies.PEAnomalyScanner;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

import static org.testng.Assert.*;

public class StructureMapTest {

    private static final String TESTFILES = TestreportsReader.RESOURCE_DIR + TestreportsReader.TEST_FILE_DIR + "/";

    private static final String[] SAMPLES = {"WinRar.exe", "HelloWorld.exe", "embedded_exe_overlay",
            "embedded_exe_resources", "upx.exe", "Lab11-02dll", "NetCoreConsole.dll", "smallest-pe.exe",
            "TestCetCompatAndEhCont.exe", "strings.exe"};

    private static PEData load(String name) throws IOException {
        return PELoader.loadPE(new File(TESTFILES + name));
    }

    @Test
    public void peSignatureIsInnermost() throws IOException {
        for (String name : new String[]{"WinRar.exe", "HelloWorld.exe", "embedded_exe_overlay"}) {
            PEData data = load(name);
            StructureMap map = StructureMap.of(data);
            long peSig = data.getPESignature().getOffset();
            assertEquals(map.innermostAt(peSig).get().getType(), RegionType.PE_SIGNATURE, name);
            assertEquals(map.innermostAt(peSig + 3).get().getType(), RegionType.PE_SIGNATURE, name);
            assertNotEquals(map.innermostAt(peSig + 4).get().getType(), RegionType.PE_SIGNATURE, name);
            assertEquals(map.innermostAt(peSig).get().getPath(), "Headers > PE Signature");
        }
    }

    @Test
    public void lfanewIsInMsdosHeader() throws IOException {
        StructureMap map = StructureMap.of(load("WinRar.exe"));
        List<FileRegion> regions = map.regionsAt(0x3c);
        assertEquals(regions.size(), 2);
        assertEquals(regions.get(0).getType(), RegionType.MSDOS_HEADER);
        assertEquals(regions.get(1).getType(), RegionType.HEADERS);
    }

    @Test
    public void lfanewIsAFieldInFineDetail() throws IOException {
        StructureMap map = new StructureMapBuilder(load("WinRar.exe")).withDetail(Detail.FINE).build();
        List<FileRegion> regions = map.regionsAt(0x3c);
        assertEquals(regions.size(), 3);
        assertEquals(regions.get(0).getType(), RegionType.HEADER_FIELD);
        assertEquals(regions.get(0).getName(), "E_LFANEW");
        assertEquals(regions.get(0).getAttributes().get(FileRegion.ATTR_VALUE), "0x200");
        assertEquals(regions.get(1).getType(), RegionType.MSDOS_HEADER);
        assertEquals(regions.get(2).getType(), RegionType.HEADERS);
        assertEquals(regions.get(0).getPath(), "Headers > MSDOS Header > E_LFANEW");
    }

    @Test
    public void sectionHeaderFieldsAreAtTheirHeader() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap map = new StructureMapBuilder(data).withDetail(Detail.FINE).build();
        for (FileRegion header : map.getRegions(RegionType.SECTION_HEADER)) {
            assertFalse(header.getChildren().isEmpty());
            for (FileRegion field : header.getChildren()) {
                assertTrue(field.getStart() >= header.getStart() && field.getEnd() <= header.getEnd(),
                        field + " outside of " + header);
            }
        }
    }

    @Test
    public void importAddressTablesPerDll() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap map = new StructureMapBuilder(data).withDetail(Detail.FINE).build();
        SectionLoader loader = new SectionLoader(data);
        List<FileRegion> dlls = map.getRegions(RegionType.IMPORT_DLL);
        assertFalse(dlls.isEmpty());
        for (FileRegion dll : dlls) {
            FileRegion iat = null;
            for (FileRegion child : dll.getChildren()) {
                if (child.getType() == RegionType.IMPORT_ADDRESS_TABLE) {
                    iat = child;
                }
            }
            assertNotNull(iat, "no IAT for " + dll);
            assertTrue(iat.isDeclaredOnly());
            assertEquals(iat.getPath(), "Imports > " + dll.getName() + " > IAT (" + dll.getName() + ")");
            io.github.struppigel.parser.sections.idata.ImportDLL importDll = null;
            for (io.github.struppigel.parser.sections.idata.ImportDLL candidate : data.loadImports()) {
                if (candidate.getName().equals(dll.getName())) {
                    importDll = candidate;
                }
            }
            assertNotNull(importDll);
            long iatRva = importDll.getAllImports().get(0).getDirEntryValue(
                    io.github.struppigel.parser.sections.idata.DirectoryEntryKey.I_ADDR_TABLE_RVA);
            assertEquals(iat.getStart(), (long) loader.maybeGetFileOffset(iatRva).get());
            int entrySize = data.getOptionalHeader().getMagicNumber()
                    == io.github.struppigel.parser.optheader.OptionalHeader.MagicNumber.PE32_PLUS ? 8 : 4;
            assertEquals(iat.getEnd() - iat.getStart(), (importDll.getAllImports().size() + 1L) * entrySize);
        }
    }

    @Test
    public void importStructuresAreNotListedTwice() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap map = new StructureMapBuilder(data).withDetail(Detail.FINE).build();
        // the hint/name is part of the import function, not a structure of its own
        assertTrue(map.getRegions(RegionType.IMPORT_HINT_NAME).isEmpty());
        assertFalse(map.getRegions(RegionType.IMPORT_FUNCTION).isEmpty());
        for (FileRegion iat : map.getRegions(RegionType.IMPORT_ADDRESS_TABLE)) {
            for (FileRegion directory : map.getRegions(RegionType.IAT_DIRECTORY)) {
                assertFalse(directory.getStart() == iat.getStart() && directory.getEnd() == iat.getEnd(),
                        directory + " repeats " + iat);
            }
        }
    }

    @Test
    public void importFunctionsAreRegionsOfTheirOwn() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap map = new StructureMapBuilder(data).withDetail(Detail.FINE).build();
        SectionLoader loader = new SectionLoader(data);
        int checked = 0;
        for (io.github.struppigel.parser.sections.idata.ImportDLL dll : data.loadImports()) {
            for (Import function : dll.getAllImports()) {
                long entryOffset = function.getLocations().get(0).from();
                FileRegion region = map.bestRegionStartingAt(entryOffset).get();
                String what = dll.getName() + " " + function;
                // lookup table entry, hint and name, address table slot, not the whole lookup table of the DLL
                assertEquals(ImportFunctionExpectations.keys(region.getLocations()),
                        ImportFunctionExpectations.locations(loader, function), what);
                assertEquals(map.innermostAt(entryOffset).get(), region, what);
                if (function instanceof NameImport) {
                    assertEquals(region.getAttributes().get(FileRegion.ATTR_FUNCTION),
                            ((NameImport) function).getName(), what);
                }
                checked++;
            }
        }
        assertTrue(checked > 50, "checked " + checked);
    }

    @Test
    public void delayImportFunctionsAreRegionsOfTheirOwn() throws IOException {
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/corkami/delay_imports.exe"));
        StructureMap map = new StructureMapBuilder(data).withDetail(Detail.FINE).build();
        SectionLoader loader = new SectionLoader(data);
        List<io.github.struppigel.parser.sections.idata.ImportDLL> dlls = data.loadDelayLoadImports();
        assertFalse(dlls.isEmpty());
        int checked = 0;
        for (io.github.struppigel.parser.sections.idata.ImportDLL dll : dlls) {
            for (NameImport function : dll.getNameImports()) {
                PhysicalLocation entry = function.getLocations().get(0);
                FileRegion region = map.bestRegionStartingAt(entry.from()).get();
                String what = dll.getName() + " " + function;
                Set<String> locations = ImportFunctionExpectations.keys(region.getLocations());
                // not the whole delay import section: the lookup table entry and the hint and name of the function
                assertTrue(locations.size() <= 3, what + " " + locations);
                assertTrue(locations.contains(ImportFunctionExpectations.key(entry.from(), entry.size())), what);
                long nameOffset = loader.maybeGetFileOffset(function.getNameRVA()).get();
                assertTrue(locations.contains(ImportFunctionExpectations.key(nameOffset,
                        2 + function.getName().length() + 1)), what + " " + locations);
                checked++;
            }
        }
        assertTrue(checked > 0);
    }

    @Test
    public void resourceTreeInFineDetail() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap map = new StructureMapBuilder(data).withDetail(Detail.FINE).build();
        List<FileRegion> tables = map.getRegions(RegionType.RESOURCE_DIRECTORY_TABLE);
        assertFalse(tables.isEmpty());
        io.github.struppigel.parser.sections.rsrc.ResourceDirectory root =
                new SectionLoader(data).loadResourceSection().getResourceTree();
        FileRegion rootTable = tables.get(0);
        assertEquals(rootTable.getStart(), root.getFileOffset());
        assertEquals(rootTable.getEnd() - rootTable.getStart(), 16 + 8L * root.getEntries().size());
        assertEquals(map.getRegions(RegionType.RESOURCE_DATA_ENTRY).size(), data.loadResources().size());
        for (FileRegion name : map.getRegions(RegionType.RESOURCE_NAME)) {
            // names are UTF-16 strings in the resource section after a 2 byte length
            assertTrue(name.getStart() >= rootTable.getStart(), name.toString());
            assertTrue(name.getStart() < map.getRegions(RegionType.RESOURCE_DIRECTORY).get(0).getEnd());
        }
    }

    @Test
    public void resourceTreeIsInsideTheResourceDirectory() throws IOException {
        int names = 0;
        for (String sample : new String[]{"autoit", "batch2exe", "WinRar.exe", "HelloWorld.exe"}) {
            StructureMap map = new StructureMapBuilder(load(sample)).withDetail(Detail.FINE).build();
            for (FileRegion directory : map.getRegions(RegionType.RESOURCE_DIRECTORY)) {
                for (FileRegion child : directory.getChildren()) {
                    if (child.getType() == RegionType.RESOURCE) {
                        continue;
                    }
                    for (PhysicalLocation loc : child.getLocations()) {
                        for (long offset : new long[]{loc.from(), loc.from() + loc.size() - 1}) {
                            assertTrue(directory.contains(offset), sample + " " + child + " at " + offset);
                        }
                    }
                    names += child.getType() == RegionType.RESOURCE_NAME ? 1 : 0;
                }
            }
        }
        assertTrue(names > 0, "no named resource entries in the samples");
    }

    @Test
    public void resourceNamesAreLimitedToTheMaximumLength() throws IOException {
        PEData data = load("batch2exe");
        byte[] bytes = java.nio.file.Files.readAllBytes(data.getFile().toPath());
        StructureMap map = new StructureMapBuilder(data).withDetail(Detail.FINE).build();
        List<FileRegion> names = map.getRegions(RegionType.RESOURCE_NAME);
        assertFalse(names.isEmpty());
        int max = io.github.struppigel.parser.sections.rsrc.ResourceDirectoryEntry.maxNameLength();
        boolean longer = false;
        for (FileRegion name : names) {
            int start = (int) name.getStart();
            int characters = (bytes[start] & 0xff) | (bytes[start + 1] & 0xff) << 8;
            longer |= characters > max;
            // the 2 byte length and at most max characters, longer names are cut off and reported as anomaly
            assertEquals(name.getEnd() - name.getStart(), 2 + 2L * Math.min(characters, max), name.toString());
        }
        assertTrue(longer, "batch2exe has names longer than the maximum");
    }

    @Test
    public void exportTablesInFineDetail() throws IOException {
        StructureMap map = new StructureMapBuilder(load("Lab11-02dll")).withDetail(Detail.FINE).build();
        assertEquals(map.getRegions(RegionType.EXPORT_DIRECTORY).size(), 1);
        assertEquals(map.getRegions(RegionType.EXPORT_ADDRESS_TABLE).size(), 1);
        assertEquals(map.getRegions(RegionType.EXPORT_NAME_POINTER_TABLE).size(), 1);
        assertEquals(map.getRegions(RegionType.EXPORT_ORDINAL_TABLE).size(), 1);
        assertEquals(map.getRegions(RegionType.EXPORT_NAME).get(0).getName(), "installer");
    }

    @Test
    public void clrTablesInFineDetail() throws IOException {
        StructureMap map = new StructureMapBuilder(load("HelloWorld.exe")).withDetail(Detail.FINE).build();
        List<FileRegion> tables = map.getRegions(RegionType.CLR_TABLE);
        assertFalse(tables.isEmpty());
        for (FileRegion table : tables) {
            assertEquals(table.getParent().get().getName(), "#~");
            assertTrue(Integer.parseInt(table.getAttributes().get(FileRegion.ATTR_ROWS)) > 0);
        }
    }

    @Test
    public void fineDetailOnlyAddsRegionsThatAreNotDrawn() throws IOException {
        for (String name : SAMPLES) {
            PEData data = load(name);
            StructureMap coarse = StructureMap.of(data);
            StructureMap fine = new StructureMapBuilder(data).withDetail(Detail.FINE).build();
            assertTrue(fine.getRegions().size() >= coarse.getRegions().size(), name);
            int painted = 0;
            for (FileRegion region : fine.getRegions()) {
                if (region.getType().getPaintMode() != PaintMode.NONE) {
                    painted++;
                }
            }
            int coarsePainted = 0;
            for (FileRegion region : coarse.getRegions()) {
                if (region.getType().getPaintMode() != PaintMode.NONE) {
                    coarsePainted++;
                }
            }
            assertEquals(painted, coarsePainted, name);
            assertClean(fine, name);
        }
    }

    @Test
    public void sectionsMatchReadSize() throws IOException {
        for (String name : SAMPLES) {
            PEData data = load(name);
            StructureMap map = StructureMap.of(data);
            SectionLoader loader = new SectionLoader(data);
            boolean lowAlign = data.getOptionalHeader().isLowAlignmentMode();
            long length = data.getFile().length();
            for (SectionHeader header : data.getSectionTable().getSectionHeaders()) {
                long start = header.getAlignedPointerToRaw(lowAlign);
                long size = loader.getReadSize(header);
                FileRegion region = findSection(map, header.getNumber());
                if (size <= 0 || start >= length) {
                    assertNull(region, name + " section " + header.getNumber());
                } else {
                    assertNotNull(region, name + " section " + header.getNumber());
                    assertEquals(region.getStart(), start);
                    assertEquals(region.getEnd(), Math.min(start + size, length));
                    assertEquals(region.getAttributes().get(FileRegion.ATTR_SECTION_NAME), header.getName());
                }
            }
        }
    }

    private static FileRegion findSection(StructureMap map, int number) {
        for (FileRegion region : map.getRegions(RegionType.SECTION)) {
            if (region.getAttributes().get(FileRegion.ATTR_SECTION_NUMBER).equals(String.valueOf(number))) {
                return region;
            }
        }
        return null;
    }

    @Test
    public void resourcesMatchRawBytes() throws IOException {
        PEData data = load("embedded_exe_resources");
        StructureMap map = StructureMap.of(data);
        long length = data.getFile().length();
        List<Resource> resources = data.loadResources();
        assertFalse(resources.isEmpty());
        List<FileRegion> regions = map.getRegions(RegionType.RESOURCE);
        int expected = 0;
        for (Resource resource : resources) {
            PhysicalLocation loc = resource.rawBytesLocation();
            if (loc.from() <= 0 || loc.from() >= length || loc.size() <= 0) {
                continue;
            }
            expected++;
            boolean found = false;
            for (FileRegion region : regions) {
                if (region.getStart() == loc.from() && region.getEnd() == Math.min(loc.from() + loc.size(), length)
                        && region.getAttributes().get(FileRegion.ATTR_RESOURCE_TYPE).equals(resource.getType())) {
                    found = true;
                    assertEquals(region.getParent().get().getType(), RegionType.RESOURCE_DIRECTORY);
                }
            }
            assertTrue(found, "no region for resource " + resource);
        }
        assertEquals(regions.size(), expected);
    }

    @Test
    public void overlayMatches() throws IOException {
        PEData data = load("embedded_exe_overlay");
        StructureMap map = StructureMap.of(data);
        Overlay overlay = new Overlay(data);
        assertTrue(overlay.exists());
        List<FileRegion> regions = map.getRegions(RegionType.OVERLAY);
        assertEquals(regions.size(), 1);
        assertEquals(regions.get(0).getStart(), overlay.getOffset());
        assertEquals(regions.get(0).getEnd(), data.getFile().length());
        assertEquals(map.innermostAt(data.getFile().length() - 1).get().getType(), RegionType.OVERLAY);
    }

    @Test
    public void clrStreamsExist() throws IOException {
        StructureMap map = StructureMap.of(load("HelloWorld.exe"));
        Set<String> names = new HashSet<>();
        for (FileRegion region : map.getRegions(RegionType.CLR_STREAM)) {
            names.add(region.getAttributes().get(FileRegion.ATTR_STREAM_NAME));
            assertEquals(region.getParent().get().getType(), RegionType.CLR_METADATA);
        }
        assertTrue(names.containsAll(java.util.Arrays.asList("#~", "#Strings", "#US", "#GUID", "#Blob")), names.toString());
        assertEquals(map.getRegions(RegionType.CLR_HEADER).size(), 1);
        assertEquals(map.getRegions(RegionType.METADATA_ROOT).size(), 1);
        FileRegion root = map.getRegions(RegionType.METADATA_ROOT).get(0);
        // the metadata root ends where the first stream starts
        long firstStream = Long.MAX_VALUE;
        for (FileRegion region : map.getRegions(RegionType.CLR_STREAM)) {
            firstStream = Math.min(firstStream, region.getStart());
        }
        assertEquals(root.getEnd(), firstStream);
    }

    @Test
    public void tlsIsDeclaredOnly() throws IOException {
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/Haus/TLSCallback_x86.exe"));
        StructureMap map = StructureMap.of(data);
        List<FileRegion> tls = map.getRegions(RegionType.TLS_DIRECTORY);
        assertEquals(tls.size(), 1);
        assertTrue(tls.get(0).isDeclaredOnly());
        assertEquals(tls.get(0).getAttributes().get(FileRegion.ATTR_DATA_DIRECTORY), "TLS table");
    }

    @Test
    public void entryPointIsMarked() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap map = StructureMap.of(data);
        long rva = data.getOptionalHeader().get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT);
        long offset = new SectionLoader(data).maybeGetFileOffset(rva).get();
        List<FileRegion> ep = map.getRegions(RegionType.ENTRY_POINT);
        assertEquals(ep.size(), 1);
        assertEquals(ep.get(0).getStart(), offset);
        assertEquals(ep.get(0).getEnd(), offset + 1);
        assertEquals(map.innermostAt(offset).get().getType(), RegionType.ENTRY_POINT);
    }

    @Test
    public void importDllsArePerDll() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap map = StructureMap.of(data);
        List<FileRegion> dlls = map.getRegions(RegionType.IMPORT_DLL);
        assertEquals(dlls.size(), data.loadImports().size());
        for (FileRegion dll : dlls) {
            assertEquals(dll.getParent().get().getType(), RegionType.IMPORT_SECTION);
            assertEquals(dll.getPath(), "Imports > " + dll.getName());
            // the import descriptor of the DLL is the first location
            assertEquals(map.bestRegionStartingAt(dll.getStart()).get(), dll);
        }
    }

    @Test
    public void unmappedFillsTheGaps() throws IOException {
        for (String name : SAMPLES) {
            PEData data = load(name);
            StructureMap map = StructureMap.of(data);
            long length = map.getFileLength();
            boolean[] covered = new boolean[(int) length];
            for (FileRegion region : map.getRegions()) {
                RegionType type = region.getType();
                if (type == RegionType.SECTION || type == RegionType.OVERLAY || type == RegionType.UNMAPPED
                        || type == RegionType.HEADERS) {
                    for (PhysicalLocation loc : region.getLocations()) {
                        for (long i = loc.from(); i < loc.from() + loc.size(); i++) {
                            covered[(int) i] = true;
                        }
                    }
                }
            }
            for (FileRegion unmapped : map.getRegions(RegionType.UNMAPPED)) {
                for (FileRegion other : map.regionsAt(unmapped.getStart())) {
                    assertFalse(other.getType() == RegionType.SECTION || other.getType() == RegionType.OVERLAY,
                            name + ": unmapped overlaps " + other);
                }
            }
            for (int i = 0; i < covered.length; i++) {
                if (!covered[i]) {
                    // bytes outside of headers, sections, overlay and gaps can only be header children
                    assertFalse(map.regionsAt(i).isEmpty(), name + ": offset " + i + " has no region");
                }
            }
        }
    }

    @Test
    public void locationsAreClean() throws IOException {
        File[] files = new File(TESTFILES).listFiles();
        assertNotNull(files);
        for (File file : files) {
            if (file.isDirectory() || file.length() > 20_000_000) {
                continue;
            }
            PEData data;
            try {
                data = PELoader.loadPE(file);
            } catch (FileFormatException e) {
                continue;
            }
            assertClean(StructureMap.of(data), file.getName());
            assertClean(new StructureMapBuilder(data).withDetail(Detail.FINE).build(), file.getName());
        }
    }

    private static FileRegion child(FileRegion parent, RegionType type) {
        for (FileRegion c : parent.getChildren()) {
            if (c.getType() == type) {
                return c;
            }
        }
        throw new AssertionError(parent + " has no " + type);
    }

    @Test
    public void certificateRegions() throws IOException {
        StructureMap map = new StructureMapBuilder(load("strings.exe")).withDetail(Detail.FINE).build();
        List<FileRegion> tables = map.getRegions(RegionType.CERTIFICATE_TABLE);
        assertEquals(tables.size(), 1);
        FileRegion table = tables.get(0);
        assertEquals(table.getStart(), 0x52800);
        assertEquals(table.getEnd(), 0x54b88);
        assertFalse(table.isDeclaredOnly());
        assertFalse(RegionType.CERTIFICATE_TABLE.isDeclaredDirectory());
        FileRegion entry = child(table, RegionType.WIN_CERTIFICATE);
        assertEquals(entry.getAttributes().get(FileRegion.ATTR_CERTIFICATE_TYPE), "PKCS_SIGNED_DATA");
        assertTrue(entry.getChildren().stream().filter(c -> c.getType() == RegionType.HEADER_FIELD).count() == 3);
        FileRegion signature = child(entry, RegionType.PKCS7_SIGNED_DATA);
        List<FileRegion> certificates = new ArrayList<>();
        for (FileRegion c : signature.getChildren()) {
            if (c.getType() == RegionType.CERTIFICATE) {
                certificates.add(c);
            }
        }
        assertEquals(certificates.size(), 2);
        assertTrue(certificates.stream().anyMatch(c -> c.getName().equals("Microsoft Corporation")));
        assertTrue(certificates.get(0).getAttributes().containsKey(FileRegion.ATTR_CERTIFICATE_ISSUER));
        child(signature, RegionType.SIGNER_INFO);
        child(entry, RegionType.CERTIFICATE_PADDING);
        // the regions at an offset inside a certificate, innermost first
        List<FileRegion> at = map.regionsAt(certificates.get(0).getStart() + 4);
        assertTrue(at.stream().anyMatch(r -> r.getType() == RegionType.CERTIFICATE_TABLE));
        assertTrue(at.stream().anyMatch(r -> r.getType() == RegionType.CERTIFICATE));
    }

    @Test
    public void brokenCertificateTablesGiveCleanMaps() throws IOException {
        for (String path : new String[]{"Haus/DRWUI.exe", "Haus/cff-chrome_elf.dll", "corkami/maxvals.exe", "ose",
                "Haus/pidgin_manipulated_Icons.exe"}) {
            PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/" + path));
            assertClean(StructureMap.of(data), path);
            assertClean(new StructureMapBuilder(data).withDetail(Detail.FINE).build(), path);
        }
    }

    /** checks the invariants every map must satisfy */
    public static void assertClean(StructureMap map, String name) {
        long length = map.getFileLength();
        List<FileRegion> regions = map.getRegions();
        for (int i = 0; i < regions.size(); i++) {
            FileRegion region = regions.get(i);
            assertEquals(region.getId(), i, name);
            List<PhysicalLocation> locations = region.getLocations();
            assertFalse(locations.isEmpty(), name + " " + region);
            long previousEnd = -1;
            for (PhysicalLocation loc : locations) {
                assertTrue(loc.from() >= 0 && loc.size() > 0, name + " " + region);
                assertTrue(loc.from() + loc.size() <= length, name + " " + region + " exceeds file");
                assertTrue(loc.from() > previousEnd, name + " " + region + " unsorted or touching locations");
                previousEnd = loc.from() + loc.size();
            }
            assertEquals(region.getStart(), locations.get(0).from());
            assertEquals(region.getEnd(), previousEnd);
            if (region.getParent().isPresent()) {
                assertTrue(region.getParent().get().getChildren().contains(region));
                assertEquals(region.getDepth(), region.getParent().get().getDepth() + 1);
            } else {
                assertTrue(map.getRoots().contains(region));
            }
        }
        assertNotNull(map.getReport());
    }

    @Test
    public void queriesMatchBruteForce() throws IOException {
        Random random = new Random(7);
        for (String name : SAMPLES) {
            PEData data = load(name);
            StructureMap map = new StructureMapBuilder(data)
                    .withAnomalies(PEAnomalyScanner.newInstance(data).getAnomalies())
                    .withSignatureMatches(SignatureHit.fromMatches(data.getSignatureMatches()))
                    .build();
            long length = map.getFileLength();
            for (int i = 0; i < 2000; i++) {
                long offset = i < 200 ? random.nextInt((int) Math.min(length, 0x1000)) : (long) (random.nextDouble() * length);
                List<FileRegion> actual = map.regionsAt(offset);
                Set<FileRegion> expected = new HashSet<>();
                for (FileRegion region : map.getRegions()) {
                    if (region.contains(offset)) {
                        expected.add(region);
                    }
                }
                assertEquals(new HashSet<>(actual), expected, name + " at " + offset);
                assertEquals(actual.size(), expected.size(), name + " duplicates at " + offset);
                assertSortedBySpecificity(map, actual);

                long to = offset + 1 + random.nextInt(0x2000);
                List<FileRegion> overlapping = map.regionsOverlapping(offset, to);
                Set<FileRegion> expectedOverlapping = new HashSet<>();
                for (FileRegion region : map.getRegions()) {
                    for (PhysicalLocation loc : region.getLocations()) {
                        if (loc.from() < to && loc.from() + loc.size() > offset) {
                            expectedOverlapping.add(region);
                        }
                    }
                }
                assertEquals(new HashSet<>(overlapping), expectedOverlapping, name + " range " + offset);
                assertEquals(overlapping.size(), expectedOverlapping.size());
                assertSortedBySpecificity(map, overlapping);

                final List<FileRegion> visited = new ArrayList<>();
                map.forEachInterval(offset, to, new IntervalVisitor() {
                    @Override
                    public void visit(FileRegion region, long start, long end) {
                        visited.add(region);
                    }
                });
                assertEquals(new HashSet<>(visited), expectedOverlapping);
                for (int k = 1; k < visited.size(); k++) {
                    // least specific first
                    assertTrue(map.getSpecificityRank(visited.get(k - 1)) >= map.getSpecificityRank(visited.get(k)));
                }
            }
            assertTrue(map.regionsAt(-1).isEmpty());
            assertTrue(map.regionsAt(length).isEmpty());
            assertTrue(map.regionsOverlapping(10, 10).isEmpty());
        }
    }

    private static void assertSortedBySpecificity(StructureMap map, List<FileRegion> regions) {
        for (int k = 1; k < regions.size(); k++) {
            assertTrue(map.getSpecificityRank(regions.get(k - 1)) < map.getSpecificityRank(regions.get(k)));
            // a region comes before the regions around it, however many bytes it covers
            FileRegion first = regions.get(k - 1);
            FileRegion later = regions.get(k);
            assertFalse(isAncestor(first, later), first + " is an ancestor of " + later);
        }
    }

    private static boolean isAncestor(FileRegion ancestor, FileRegion region) {
        for (FileRegion r = region; r.getParent().isPresent(); r = r.getParent().get()) {
            if (r.getParent().get().equals(ancestor)) {
                return true;
            }
        }
        return false;
    }

    @Test
    public void markersAreAdded() throws IOException {
        PEData data = load("upx.exe");
        List<SignatureHit> hits = SignatureHit.fromMatches(data.getSignatureMatches());
        assertFalse(hits.isEmpty());
        List<PhysicalLocation> chunks = new ArrayList<>();
        chunks.add(new PhysicalLocation(0x10, 0x20));
        chunks.add(new PhysicalLocation(0x20, 0x20)); // overlaps and is merged
        StructureMap map = new StructureMapBuilder(data)
                .withSignatureMatches(hits)
                .withAnomalies(PEAnomalyScanner.newInstance(data).getAnomalies())
                .withCustomRegions("Read Chunks", chunks)
                .build();
        List<FileRegion> matches = map.getRegions(RegionType.SIGNATURE_MATCH);
        assertEquals(matches.size(), hits.size());
        assertEquals(matches.get(0).getStart(), hits.get(0).getOffset());
        assertEquals(matches.get(0).getAttributes().get(FileRegion.ATTR_SIGNATURE_NAME), hits.get(0).getName());
        assertFalse(map.getRegions(RegionType.ANOMALY).isEmpty());
        List<FileRegion> custom = map.getRegions(RegionType.CUSTOM);
        assertEquals(custom.size(), 1);
        assertEquals(custom.get(0).getLocations().size(), 1);
        assertEquals(custom.get(0).getStart(), 0x10);
        assertEquals(custom.get(0).getEnd(), 0x40);
        // markers are not chosen for table rows if a structure starts there
        assertNotEquals(map.bestRegionStartingAt(0x0).get().getType(), RegionType.CUSTOM);
        assertEquals(map.bestRegionStartingAt(0x10).get().getType(), RegionType.CUSTOM);
    }

    @Test
    public void emptySignatureHitIsOneByte() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap map = new StructureMapBuilder(data)
                .withSignatureMatches(Collections.singletonList(new SignatureHit("test", 0x100, 0)))
                .build();
        FileRegion hit = map.getRegions(RegionType.SIGNATURE_MATCH).get(0);
        assertEquals(hit.getStart(), 0x100);
        assertEquals(hit.getEnd(), 0x101);
    }

    @Test
    public void outOfFileLocationsAreDroppedOrClipped() throws IOException {
        PEData data = load("WinRar.exe");
        long length = data.getFile().length();
        List<PhysicalLocation> locations = new ArrayList<>();
        locations.add(new PhysicalLocation(-5, 10));
        locations.add(new PhysicalLocation(length, 10));
        locations.add(new PhysicalLocation(length - 4, Long.MAX_VALUE));
        StructureMap map = new StructureMapBuilder(data).withCustomRegions("bad", locations).build();
        FileRegion custom = map.getRegions(RegionType.CUSTOM).get(0);
        assertTrue(custom.isClipped());
        assertEquals(custom.getStart(), length - 4);
        assertEquals(custom.getEnd(), length);
        StructureMap none = new StructureMapBuilder(data)
                .withCustomRegions("none", Collections.singletonList(new PhysicalLocation(length + 1, 4))).build();
        assertTrue(none.getRegions(RegionType.CUSTOM).isEmpty());
    }

    @Test
    public void truncatesAtRegionLimit() throws IOException {
        PEData data = load("WinRar.exe");
        StructureMap full = StructureMap.of(data);
        StructureMap map = new StructureMapBuilder(data).withMaxRegions(10).build();
        assertFalse(full.isTruncated());
        assertTrue(map.isTruncated());
        int summaries = 0;
        for (FileRegion region : map.getRegions()) {
            if (region.getAttributes().containsKey(FileRegion.ATTR_TRUNCATED)) {
                summaries++;
            }
        }
        assertTrue(summaries > 0);
        assertEquals(map.getRegions().size(), 10 + summaries);
        assertClean(map, "truncated");
    }

    @Test
    public void emptyMapHasNoRegions() {
        StructureMap map = StructureMap.empty(100);
        assertEquals(map.getFileLength(), 100);
        assertTrue(map.regionsAt(5).isEmpty());
        assertFalse(map.innermostAt(5).isPresent());
        assertFalse(map.bestRegionStartingAt(0).isPresent());
        assertTrue(map.regionsOverlapping(0, 100).isEmpty());
        assertTrue(map.getRoots().isEmpty());
        assertFalse(map.isTruncated());
        assertTrue(map.getReport().contains("0 regions"));
    }

    @Test
    public void reportShowsHalfOpenRanges() throws IOException {
        PEData data = load("WinRar.exe");
        String report = StructureMap.of(data).getReport();
        long peSig = data.getPESignature().getOffset();
        assertTrue(report.contains("  PE Signature " + StructureMap.hexRange(peSig, peSig + 4)), report);
        assertTrue(report.contains("Overlay ["), report);
    }

    @Test
    public void bestRegionStartingAtSection() throws IOException {
        PEData data = load("embedded_exe_overlay");
        StructureMap map = StructureMap.of(data);
        for (FileRegion section : map.getRegions(RegionType.SECTION)) {
            Optional<FileRegion> best = map.bestRegionStartingAt(section.getStart());
            assertTrue(best.isPresent());
            assertTrue(best.get().getLocations().get(0).from() == section.getStart()
                    || best.get().contains(section.getStart()));
        }
        assertFalse(map.bestRegionStartingAt(1).isPresent());
    }
}
