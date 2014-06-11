package com.github.katjahahn.sections;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.FileFormatException;
import com.github.katjahahn.PEData;
import com.github.katjahahn.PELoader;
import com.github.katjahahn.PELoaderTest;
import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.TestreportsReader.TestData;
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.sections.edata.ExportSection;
import com.github.katjahahn.sections.idata.ImportSection;
import com.github.katjahahn.sections.rsrc.ResourceSection;
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
    public void constructorTest() throws FileFormatException {
        PEData datum = pedata.get("strings.exe");
        SectionLoader loader1 = new SectionLoader(datum);
        SectionLoader loader2 = new SectionLoader(datum.getSectionTable(),
                datum.getOptionalHeader(), datum.getCOFFFileHeader(),
                datum.getFile());
        for (DataDirectoryKey key : DataDirectoryKey.values()) {
            Optional<Long> offset1 = loader1.maybeGetFileOffsetFor(key);
            Optional<Long> offset2 = loader2.maybeGetFileOffsetFor(key);
            assertEquals(offset1, offset2);
        }
    }

    @Test
    public void unableToLoadImports() throws IOException {
        File file = new File(TestreportsReader.RESOURCE_DIR
                + "/x64viruses/VirusShare_baed21297974b6adf3298585baa78691");
        PEData data = PELoader.loadPE(file);
        SectionLoader loader = new SectionLoader(data);
        Optional<ImportSection> idata = loader.maybeLoadImportSection();
        if (idata.isPresent()) {
            System.out.println(idata.get().getInfo());
        }
        assertFalse(idata.isPresent());
    }

    @Test
    public void unableToLoadResources() throws IOException {
        File file = new File(TestreportsReader.RESOURCE_DIR
                + "/x64viruses/VirusShare_baed21297974b6adf3298585baa78691");
        PEData data = PELoader.loadPE(file);
        SectionLoader loader = new SectionLoader(data);
        assertFalse(loader.maybeLoadResourceSection().isPresent());
    }

    @Test
    public void getSectionEntryByRVA() {
        for (PEData datum : pedata.values()) {
            SectionTable table = datum.getSectionTable();
            SectionLoader loader = new SectionLoader(datum);
            for (SectionHeader entry : table.getSectionHeaders()) {
                long start = entry.get(SectionHeaderKey.VIRTUAL_ADDRESS);
                long size = entry.get(SectionHeaderKey.VIRTUAL_SIZE);
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
                if (testDir.key.equals(DataDirectoryKey.EXPORT_TABLE)) {
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
                if (testDir.key.equals(DataDirectoryKey.IMPORT_TABLE)) {
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
                if (testDir.key.equals(DataDirectoryKey.RESOURCE_TABLE)) {
                    ResourceSection rsrc = new SectionLoader(pedatum)
                            .loadResourceSection();
                    assertNotNull(rsrc);
                }
            }
        }
    }

    @Test
    public void loadSectionWithSizeAnomaly() throws IOException {
        PEData datum = pedata.get("Lab05-01.dll");
        new SectionLoader(datum).maybeLoadSection(".reloc");
    }

    @Test
    public void loadSectionByName() throws IOException {
        for (PEData datum : pedata.values()) {
            SectionLoader loader = new SectionLoader(datum);
            SectionTable table = datum.getSectionTable();
            for (SectionHeader header : table.getSectionHeaders()) {
                String name = header.getName();
                Optional<PESection> section = loader.maybeLoadSection(name);
                assertTrue(section.isPresent());
                assertEquals(section.get().getDump().length,
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
                assertEquals(section.getDump().length,
                        (int) loader.getReadSize(header));
            }
        }
    }
}
