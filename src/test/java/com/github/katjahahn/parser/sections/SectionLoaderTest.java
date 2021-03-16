package com.github.katjahahn.parser.sections;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.TestreportsReader.TestData;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.PELoaderTest;
import com.github.katjahahn.parser.optheader.DataDirEntry;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.github.katjahahn.parser.sections.edata.ExportSection;
import com.github.katjahahn.parser.sections.idata.ImportSection;
import com.github.katjahahn.parser.sections.rsrc.ResourceSection;
import com.google.common.base.Optional;

public class SectionLoaderTest {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(SectionLoaderTest.class.getName());
    private List<TestData> testdata;
    private Map<String, PEData> pedata = new HashMap<>();

    @BeforeClass
    public void prepare() throws IOException {
        testdata = PELoaderTest.getTestData();
        pedata = PELoaderTest.getPEData();
    }

    @Test
    public void emptyImportSection() throws IOException {
        File file = Paths.get(TestreportsReader.RESOURCE_DIR, TestreportsReader.TEST_FILE_DIR, "baed21297974b6adf3298585baa78691").toFile();
        PEData data = PELoader.loadPE(file);
        SectionLoader loader = new SectionLoader(data);
        Optional<ImportSection> idata = loader.maybeLoadImportSection();
        assertTrue(idata.get().isEmpty());
    }

    @Test
    public void unableToLoadResources() throws IOException {
        File file = Paths.get(TestreportsReader.RESOURCE_DIR, TestreportsReader.TEST_FILE_DIR, "baed21297974b6adf3298585baa78691").toFile();
        PEData data = PELoader.loadPE(file);
        SectionLoader loader = new SectionLoader(data);
        Optional<ResourceSection> rsrc = loader.maybeLoadResourceSection();
        assertTrue(rsrc.get().isEmpty());
    }

    @Test
    public void getSectionEntryByRVA() {
        for (PEData datum : pedata.values()) {
            SectionTable table = datum.getSectionTable();
            SectionLoader loader = new SectionLoader(datum);
            //overlapping sections here, ignore!
            if(datum.getFile().getName().equals("baed21297974b6adf3298585baa78691")) continue;
            if(datum.getFile().getName().equals("Lab05-01")) continue;
            if(datum.getFile().getName().equals("Lab03-01")) continue;
            for (SectionHeader entry : table.getSectionHeaders()) {
                long start = entry.getAlignedVirtualAddress();
                long size = entry.getAlignedVirtualSize();
                SectionHeader actual = loader.maybeGetSectionHeaderByRVA(start)
                        .get();
                assertEquals(actual, entry);
                actual = loader.maybeGetSectionHeaderByRVA(start + size - 1)
                        .get();
                assertEquals(actual, entry);
                actual = loader.maybeGetSectionHeaderByRVA(size / 2 + start)
                        .get();
                assertEquals(actual, entry);
            }
        }
    }

    @Test
    public void loadExportSection() throws IOException {
        for (TestData testdatum : testdata) {
            List<DataDirEntry> testDirs = testdatum.dataDir;
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            for (DataDirEntry testDir : testDirs) {
                if (testDir.getKey().equals(DataDirectoryKey.EXPORT_TABLE)) {
                    Optional<ExportSection> edata = new SectionLoader(pedatum)
                            .maybeLoadExportSection();
                    assertTrue(edata.isPresent());
                }
            }
        }
    }

    @Test
    public void loadImportSection() throws IOException {
        for (TestData testdatum : testdata) {
            List<DataDirEntry> testDirs = testdatum.dataDir;
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            for (DataDirEntry testDir : testDirs) {
                if (testDir.getKey().equals(DataDirectoryKey.IMPORT_TABLE)) {
                    Optional<ImportSection> idata = new SectionLoader(pedatum)
                            .maybeLoadImportSection();
                    assertTrue(idata.isPresent());
                }
            }
        }
    }

    @Test
    public void loadResourceSection() throws IOException {
        for (TestData testdatum : testdata) {
            List<DataDirEntry> testDirs = testdatum.dataDir;
            PEData pedatum = pedata.get(testdatum.filename.replace(".txt", ""));
            for (DataDirEntry testDir : testDirs) {
                if (testDir.getKey().equals(DataDirectoryKey.RESOURCE_TABLE)) {
                    ResourceSection rsrc = new SectionLoader(pedatum)
                            .loadResourceSection();
                    assertNotNull(rsrc);
                }
            }
        }
    }

    @Test
    public void loadSectionWithSizeAnomaly() throws IOException {
        PEData datum = pedata.get("Lab05-01");
        new SectionLoader(datum).maybeLoadSection(".reloc");
    }

    @Test
    public void loadSectionByName() throws IOException {
        for (PEData datum : pedata.values()) {
            SectionLoader loader = new SectionLoader(datum);
            SectionTable table = datum.getSectionTable();
            // ignore!
            if(datum.getFile().getName().equals("baed21297974b6adf3298585baa78691")) continue;
            for (SectionHeader header : table.getSectionHeaders()) {
                String name = header.getName();
                Optional<PESection> section = loader.maybeLoadSection(name);
                assertTrue(section.isPresent());
                assertEquals(section.get().getBytes().length,
                        (int) loader.getReadSize(header));
            }
        }
    }

    @Test
    public void loadSectionByNumber() throws IOException {
        for (PEData datum : pedata.values()) {
            SectionLoader loader = new SectionLoader(datum);
            SectionTable table = datum.getSectionTable();
            for (SectionHeader header : table.getSectionHeaders()) {
                PESection section = loader.loadSection(header.getNumber());
                assertNotNull(section);
                assertEquals(section.getBytes().length,
                        (int) loader.getReadSize(header));
            }
        }
    }
}
