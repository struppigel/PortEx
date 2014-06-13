package com.github.katjahahn.tools.anomalies;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.parser.HeaderKey;
import com.github.katjahahn.parser.StandardField;
import com.github.katjahahn.parser.coffheader.COFFHeaderKey;
import com.github.katjahahn.parser.optheader.WindowsEntryKey;
import com.github.katjahahn.parser.sections.SectionHeaderKey;
import com.github.katjahahn.tools.anomalies.Anomaly;
import com.github.katjahahn.tools.anomalies.AnomalyType;
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner;

public class PEAnomalyScannerTest {

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(PEAnomalyScannerTest.class.getName());
    private static final String RESOURCE_FOLDER = TestreportsReader.RESOURCE_DIR;
    private static final String UNUSUAL_FOLDER = TestreportsReader.RESOURCE_DIR
            + "/unusualfiles/";
    private List<Anomaly> tinyAnomalies;
    private List<Anomaly> maxSecXPAnomalies;
    private List<Anomaly> sectionlessAnomalies;
    private List<Anomaly> dupe;
    private List<Anomaly> zeroImageBase;

    @BeforeClass
    public void prepare() {
        File file = new File(UNUSUAL_FOLDER + "tinype/tinyest.exe");
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(file);
        tinyAnomalies = scanner.getAnomalies();
        file = Paths.get(UNUSUAL_FOLDER, "corkami", "max_secXP.exe").toFile();
        scanner = PEAnomalyScanner.newInstance(file);
        maxSecXPAnomalies = scanner.getAnomalies();
        file = Paths.get(UNUSUAL_FOLDER, "corkami", "sectionless.exe").toFile();
        scanner = PEAnomalyScanner.newInstance(file);
        sectionlessAnomalies = scanner.getAnomalies();
        file = Paths.get(UNUSUAL_FOLDER, "corkami", "duplicate_section.exe")
                .toFile();
        scanner = PEAnomalyScanner.newInstance(file);
        dupe = scanner.getAnomalies();
        file = Paths.get(UNUSUAL_FOLDER, "corkami", "imagebase_null.exe")
                .toFile();
        scanner = PEAnomalyScanner.newInstance(file);
        zeroImageBase = scanner.getAnomalies();
    }

    @Test
    public void collapsedOptionalHeader() throws IOException {
        performTest(tinyAnomalies, COFFHeaderKey.SIZE_OF_OPT_HEADER,
                "SizeOfOptionalHeader");
        performTest(tinyAnomalies, AnomalyType.STRUCTURE,
                "Collapsed Optional Header");
    }

    private void performTest(List<Anomaly> anomalies, HeaderKey key,
            String... descriptions) {
        for (String description : descriptions) {
            boolean containsDescription = false;
            for (Anomaly anomaly : filterByKey(key, anomalies)) {
                if (anomaly.description().contains(description)) {
                    containsDescription = true;
                    break;
                }
            }
            assertTrue(containsDescription);
        }
    }

    private List<Anomaly> filterByKey(HeaderKey key, List<Anomaly> anomalies) {
        List<Anomaly> list = new ArrayList<>();
        for (Anomaly anomaly : anomalies) {
            StandardField field = anomaly.field();
            if (field != null && key != null) {
                if (key.equals(field.key)) {
                    list.add(anomaly);
                }
            }
        }
        return list;
    }

    private void performTest(List<Anomaly> anomalies, AnomalyType type,
            String description) {
        boolean containsType = false;
        for (Anomaly anomaly : anomalies) {
            if (anomaly.getType() == type
                    && anomaly.description().contains(description)) {
                containsType = true;
                break;
            }
        }
        assertTrue(containsType);
    }

    @Test
    public void collapsedMSDOSHeader() {
        performTest(tinyAnomalies, AnomalyType.STRUCTURE,
                "Collapsed MSDOS Header");
    }

    @Test
    public void noDataDirs() {
        performTest(tinyAnomalies, AnomalyType.STRUCTURE, "No data directory");
        performTest(tinyAnomalies, AnomalyType.NON_DEFAULT,
                "NumberOfRVAAndSizes");
    }

    @Test
    public void nonZeroSectionHeaderFields() {
        performTest(tinyAnomalies, SectionHeaderKey.POINTER_TO_RELOCATIONS,
                "POINTER_TO_RELOCATIONS");
        performTest(tinyAnomalies, SectionHeaderKey.NUMBER_OF_RELOCATIONS,
                "NUMBER_OF_RELOCATIONS");
        performTest(tinyAnomalies, SectionHeaderKey.POINTER_TO_LINE_NUMBERS,
                "POINTER_TO_LINE_NUMBERS");
    }

    @Test
    public void reservedSectionHeaderFields() {
        performTest(tinyAnomalies, AnomalyType.RESERVED,
                "Reserved characteristic used: RESERVED_4");
    }

    @Test
    public void sectionNrAnomaly() {
        File file = Paths.get(UNUSUAL_FOLDER, "corkami", "max_secW7.exe")
                .toFile();
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(file);
        List<Anomaly> anomalies = scanner.getAnomalies();
        performTest(anomalies, AnomalyType.WRONG, "Section Number");
    }

    @Test
    public void deprecated() {
        performTest(maxSecXPAnomalies, AnomalyType.DEPRECATED,
                "IMAGE_FILE_LINE_NUMS_STRIPPED");
        performTest(maxSecXPAnomalies, AnomalyType.DEPRECATED,
                "IMAGE_FILE_LOCAL_SYMS_STRIPPED");
        performTest(sectionlessAnomalies, AnomalyType.DEPRECATED,
                "IMAGE_FILE_LOCAL_SYMS_STRIPPED");
        performTest(sectionlessAnomalies, AnomalyType.DEPRECATED,
                "IMAGE_FILE_LINE_NUMS_STRIPPED");
    }

    @Test
    public void fileAlignment() {
        performTest(tinyAnomalies, WindowsEntryKey.FILE_ALIGNMENT,
                "File Alignment must be between 512 and 64 K");
        performTest(sectionlessAnomalies, WindowsEntryKey.FILE_ALIGNMENT,
                "File Alignment must be between 512 and 64 K");
    }

    @Test
    public void unusualSectionNames() {
        File file = Paths.get(RESOURCE_FOLDER, "x64viruses",
                "VirusShare_6fdfdffeb4b1be2d0036bac49cb0d590").toFile();
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(file);
        List<Anomaly> anomalies = scanner.getAnomalies();
        performTest(anomalies, SectionHeaderKey.NAME,
                "control symbols in name", "name is unusual");
    }

    @Test
    public void sectionAlignment() {
        performTest(maxSecXPAnomalies, AnomalyType.WRONG, "Size of Image");
        performTest(maxSecXPAnomalies, AnomalyType.WRONG, "Size of Headers");
        performTest(sectionlessAnomalies, AnomalyType.WRONG, "Size of Image");
        performTest(sectionlessAnomalies, AnomalyType.WRONG, "Size of Headers");
    }

    @Test
    public void overlappingSections() {
        performTest(dupe, AnomalyType.STRUCTURE, "duplicate of section");
        // TODO overlap
        // TODO use customized section table structure --> section table
        // factory?
    }

    @Test
    public void imageBaseConstraints() {
        String description = "image base is 0";
        performTest(zeroImageBase, AnomalyType.NON_DEFAULT, description);
    }

    // @Test
    // public void getAnomalies() {
    // throw new RuntimeException("Test not implemented");
    // }
    //
    // @Test
    // public void scan() {
    // throw new RuntimeException("Test not implemented");
    // }
    //
    // @Test
    // public void scanReport() {
    // throw new RuntimeException("Test not implemented");
    // }
}
