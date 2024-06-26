package com.github.struppigel.tools.anomalies;

import com.github.struppigel.TestreportsReader;
import com.github.struppigel.parser.HeaderKey;
import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.optheader.WindowsEntryKey;
import com.github.struppigel.parser.sections.SectionHeaderKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.testng.Assert.assertTrue;

public class PEAnomalyScannerTest {
    
    //TODO use the new subtypes for tests instead of description strings

    @SuppressWarnings("unused")
    private static final Logger logger = LogManager
            .getLogger(PEAnomalyScannerTest.class.getName());
    private static final String RESOURCE_FOLDER = TestreportsReader.RESOURCE_DIR;
    private static final String TEST_FILE_PATH = RESOURCE_FOLDER + TestreportsReader.TEST_FILE_DIR;
    public static final String UNUSUAL_FOLDER = RESOURCE_FOLDER;
    private List<Anomaly> tinyAnomalies;
    private List<Anomaly> maxSecXPAnomalies;
    private List<Anomaly> sectionlessAnomalies;
    private List<Anomaly> dupe;
    private List<Anomaly> zeroImageBase;

    private static Map<String, List<Anomaly>> fileToAnomalies = new HashMap<>();

    @BeforeClass
    public void prepare() {
        File file = Paths.get(TEST_FILE_PATH, "smallest-pe.exe").toFile();
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(file);
        tinyAnomalies = scanner.getAnomalies();
        file = Paths.get(RESOURCE_FOLDER, "corkami", "maxsecXP.exe").toFile();
        scanner = PEAnomalyScanner.newInstance(file);
        maxSecXPAnomalies = scanner.getAnomalies();
        file = Paths.get(RESOURCE_FOLDER, "corkami", "nosectionXP.exe").toFile();
        scanner = PEAnomalyScanner.newInstance(file);
        sectionlessAnomalies = scanner.getAnomalies();
        file = Paths.get(RESOURCE_FOLDER, "corkami", "dupsec.exe")
                .toFile();
        scanner = PEAnomalyScanner.newInstance(file);
        dupe = scanner.getAnomalies();
        file = Paths.get(RESOURCE_FOLDER, "corkami", "ibnullXP.exe")
                .toFile();
        scanner = PEAnomalyScanner.newInstance(file);
        zeroImageBase = scanner.getAnomalies();
    }

    @Test
    public void collapsedOptionalHeader() throws IOException {
        performTest(tinyAnomalies, AnomalyType.STRUCTURE,
                "Collapsed Optional Header");
    }

    private static void performTest(List<Anomaly> anomalies, HeaderKey key,
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

    private static List<Anomaly> filterByKey(HeaderKey key, List<Anomaly> anomalies) {
        List<Anomaly> list = new ArrayList<>();
        for (Anomaly anomaly : anomalies) {
            FieldOrStructureKey aKey = anomaly.key();
            if (key != null) {
                if (key.equals(aKey)) {
                    list.add(anomaly);
                }
            }
        }
        return list;
    }

    private static void performTest(List<Anomaly> anomalies, AnomalyType type,
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
    public void sectionNrAnomaly() {
        File file = Paths.get(RESOURCE_FOLDER, "corkami", "maxsecXP.exe")
                .toFile();
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(file);
        List<Anomaly> anomalies = scanner.getAnomalies();
        performTest(anomalies, AnomalyType.STRUCTURE, "Section Number");
    }

    @Test
    public void deprecated() {
        performTest(maxSecXPAnomalies, AnomalyType.DEPRECATED,
                "POINTER_TO_LINE_NUMBERS");
        performTest(maxSecXPAnomalies, AnomalyType.DEPRECATED,
                "IMAGE_SCN_TYPE_NO_PAD");
    }

    @Test
    public void fileAlignment() {
        performTest(tinyAnomalies, WindowsEntryKey.FILE_ALIGNMENT,
                "File Alignment must be between 0x200 and 0xFA00 (64 K)");
        performTest(sectionlessAnomalies, WindowsEntryKey.FILE_ALIGNMENT,
                "File Alignment must be between 0x200 and 0xFA00 (64 K)");
    }

    @Test
    public void unusualSectionNames() {
        File file = Paths.get(TEST_FILE_PATH,
                "6fdfdffeb4b1be2d0036bac49cb0d590").toFile();
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(file);
        List<Anomaly> anomalies = scanner.getAnomalies();
        performTest(anomalies, SectionHeaderKey.NAME,
                "control symbols in name", "name is unusual");
    }

    @Test
    public void sectionAlignment() {
        // TODO add something like: performTest(maxSecXPAnomalies, AnomalyType.WRONG, "Size of Image");
        // but need to find such sample first, samples below have low alignment mode which seems a valid reason for no alignment?
        performTest(maxSecXPAnomalies, AnomalyType.NON_DEFAULT, "Size of Headers");
        performTest(sectionlessAnomalies, AnomalyType.NON_DEFAULT, "Size of Headers");
    }

    @Test
    public void overlappingSections() {
        performTest(dupe, AnomalyType.STRUCTURE, "same physical location as");
        // TODO overlap
        // TODO use customized section table structure --> section table
        // factory?
    }

    @Test
    public void imageBaseConstraints() {
        String description = "image base is 0";
        performTest(zeroImageBase, AnomalyType.NON_DEFAULT, description);
    }

    public static List<Anomaly> getAnomaliesOfTestFile(PEData pe) {
        String filename = pe.getFile().getName();
        if(fileToAnomalies.containsKey(filename)) {
            return fileToAnomalies.get(filename);
        }
        PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(pe);
        return scanner.getAnomalies();
    }

    public static void assertHasAnomalySubTypeWithDescription(PEData pe, AnomalySubType atype, String description) {
        List<Anomaly> anomalies = getAnomaliesOfTestFile(pe);
        List<Anomaly> found = anomalies.stream()
                .filter(a -> a.subtype() == atype && a.description().contains(description))
                .collect(Collectors.toList());
        assertTrue(found.size() > 0);
    }

    public static void assertHasAnomalyType(PEData pe, AnomalyType atype) {
        List<Anomaly> anomalies = getAnomaliesOfTestFile(pe);
        List<Anomaly> found = anomalies.stream()
                .filter(a -> a.getType() == atype)
                .collect(Collectors.toList());
        assertTrue(found.size() > 0);
    }

    public static void assertHasAnomalySubType(PEData pe, AnomalySubType atype) {
        List<Anomaly> anomalies = getAnomaliesOfTestFile(pe);
        List<Anomaly> found = anomalies.stream()
                .filter(a -> a.subtype() == atype)
                .collect(Collectors.toList());
        assertTrue(found.size() > 0);
    }

    public static void assertHasNotAnomalySubType(PEData pe, AnomalySubType atype) {
        List<Anomaly> anomalies = getAnomaliesOfTestFile(pe);
        List<Anomaly> found = anomalies.stream()
                .filter(a -> a.subtype() == atype)
                .collect(Collectors.toList());
        assertTrue(found.isEmpty());
    }

}
