package com.github.katjahahn;

import static com.github.katjahahn.tools.anomalies.AnomalyType.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.FileFormatException;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.PESignature;
import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.coffheader.FileCharacteristic;
import com.github.katjahahn.parser.optheader.DataDirEntry;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.github.katjahahn.parser.optheader.OptionalHeader.MagicNumber;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.tools.Overlay;
import com.github.katjahahn.tools.anomalies.Anomaly;
import com.github.katjahahn.tools.anomalies.AnomalyType;
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner;

public class PortexStats {

    private static final Logger logger = LogManager.getLogger(PELoader.class
            .getName());

    private static final String BASE_MALW_FOLDER = "/home/deque/virusshare128";
    @SuppressWarnings("unused")
    private static final String ANOMALY_FOLDER = "/home/deque/portextestfiles/unusualfiles/corkami";
    private static final String PE_FOLDER = BASE_MALW_FOLDER + "/pe/";
    private static final String NO_PE_FOLDER = BASE_MALW_FOLDER + "/nope/";
    private static final String STATS_FOLDER = "portexstats/";

    public static void main(String[] args) throws IOException {
        anomalyStats();
    }

    public static void anomalyStats() {
        File folder = new File(PE_FOLDER);
        File[] files = folder.listFiles();
        final int ANOMALY_TYPE_NR = AnomalyType.values().length;
        int[] anomalies = new int[ANOMALY_TYPE_NR];
        int[] anPerFile = new int[ANOMALY_TYPE_NR];
        boolean[] occured = new boolean[ANOMALY_TYPE_NR];
        int notLoaded = 0;
        int total = 0;
        for (File file : files) {
            try {
                total++;
                PEData data = PELoader.loadPE(file);
                PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(data);
                List<Anomaly> list = scanner.getAnomalies();
                for (Anomaly a : list) {
                    int ordinal = a.getType().ordinal();
                    anomalies[ordinal] += 1;
                    occured[ordinal] = true;

                }
                for (int i = 0; i < ANOMALY_TYPE_NR; i++) {
                    if (occured[i]) {
                        anPerFile[i] += 1;
                    }
                    occured[i] = false;
                }
                if (total % 1000 == 0) {
                    System.out.println("Files read: " + total + "/"
                            + files.length);
                }
            } catch (Exception e) {
                logger.error(e);
                notLoaded++;
            }
        }
        double[] averages = new double[ANOMALY_TYPE_NR];
        double[] occPerFile = new double[ANOMALY_TYPE_NR];
        try {
            for (int i = 0; i < ANOMALY_TYPE_NR; i++) {
                averages[i] = anomalies[i] / (double) total;
                occPerFile[i] = anPerFile[i] / (double) total;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        String stats1 = "Averages anomaly count\n\ntotal files: " + total
                + "\nstructural: " + averages[STRUCTURE.ordinal()]
                + "\nwrong value: " + averages[WRONG.ordinal()]
                + "\nreserved: " + averages[RESERVED.ordinal()]
                + "\ndeprecated: " + averages[DEPRECATED.ordinal()]
                + "\nnon default: " + averages[NON_DEFAULT.ordinal()];

        String stats2 = "Absolute anomaly count (all files)\n\ntotal files: " + total
                + "\nstructural: " + anomalies[STRUCTURE.ordinal()]
                + "\nwrong value: " + anomalies[WRONG.ordinal()]
                + "\nreserved: " + anomalies[RESERVED.ordinal()]
                + "\ndeprecated: " + anomalies[DEPRECATED.ordinal()]
                + "\nnon default: " + anomalies[NON_DEFAULT.ordinal()];
        
        String stats3 = "Anomaly occurance per file (absolute) \n\ntotal files: " + total
                + "\nstructural: " + anPerFile[STRUCTURE.ordinal()]
                + "\nwrong value: " + anPerFile[WRONG.ordinal()]
                + "\nreserved: " + anPerFile[RESERVED.ordinal()]
                + "\ndeprecated: " + anPerFile[DEPRECATED.ordinal()]
                + "\nnon default: " + anPerFile[NON_DEFAULT.ordinal()];
        
        String stats4 = "Anomaly occurance per file in percent \n\ntotal files: " + total
                + "\nstructural: " + occPerFile[STRUCTURE.ordinal()]
                + "\nwrong value: " + occPerFile[WRONG.ordinal()]
                + "\nreserved: " + occPerFile[RESERVED.ordinal()]
                + "\ndeprecated: " + occPerFile[DEPRECATED.ordinal()]
                + "\nnon default: " + occPerFile[NON_DEFAULT.ordinal()]
                + "\nNot loaded: " + notLoaded + "\nDone\n";
        String report = stats1 + "\n\n" + stats2 + "\n\n" + stats3 + "\n\n" + stats4;
        System.out.println(report);
        writeStats(report);
    }

    public static void overlayPrevalence() {
        File folder = new File(PE_FOLDER);
        File[] files = folder.listFiles();
        int hasOverlay = 0;
        int hasNoOverlay = 0;
        int notLoaded = 0;
        int total = 0;
        for (File file : files) {
            try {
                total++;
                PEData data = PELoader.loadPE(file);
                Overlay overlay = new Overlay(data);
                if (overlay.exists()) {
                    hasOverlay++;
                } else {
                    hasNoOverlay++;
                }
                if (total % 1000 == 0) {
                    System.out.println("Files read: " + total + "/"
                            + files.length);
                }
            } catch (Exception e) {
                logger.error(e);
                notLoaded++;
            }
        }
        String stats = "total: " + total + "\nhas overlay: " + hasOverlay
                + "\nno overlay: " + hasNoOverlay + "\nNot loaded: "
                + notLoaded + "\nDone\n";
        System.out.println(stats);
        writeStats(stats);
    }

    public static void fileTypeCount() {
        File folder = new File(PE_FOLDER);
        File[] files = folder.listFiles();
        int dllCount = 0;
        int pe32PlusCount = 0;
        int pe32Count = 0;
        int sysCount = 0;
        int exeCount = 0;
        int notLoaded = 0;
        int total = 0;
        for (File file : files) {
            try {
                total++;
                PEData data = PELoader.loadPE(file);
                COFFFileHeader coff = data.getCOFFFileHeader();
                if (coff.hasCharacteristic(FileCharacteristic.IMAGE_FILE_DLL)) {
                    dllCount++;
                }
                if (coff.hasCharacteristic(FileCharacteristic.IMAGE_FILE_SYSTEM)) {
                    sysCount++;
                }
                if (coff.hasCharacteristic(FileCharacteristic.IMAGE_FILE_EXECUTABLE_IMAGE)) {
                    exeCount++;
                }
                MagicNumber magic = data.getOptionalHeader().getMagicNumber();
                if (magic.equals(MagicNumber.PE32)) {
                    pe32Count++;
                }
                if (magic.equals(MagicNumber.PE32_PLUS)) {
                    pe32PlusCount++;
                }
                if (total % 1000 == 0) {
                    System.out.println("Files read: " + total + "/"
                            + files.length);
                }
            } catch (Exception e) {
                logger.error(e);
                notLoaded++;
            }
        }
        String stats = "total: " + total + "\nPE32 files: " + pe32Count
                + "\nPE32+ files: " + pe32PlusCount + "\nDLL files: "
                + dllCount + "\nSystem files: " + sysCount + "\nExe files: "
                + exeCount + "\nNot loaded: " + notLoaded + "\nDone\n";
        System.out.println(stats);
        writeStats(stats);
    }

    private static void writeStats(String stats) {
        Date date = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat(
                "yyyy-MM-dd_HH-mm-ss");
        String filename = dateFormat.format(date) + ".stat";
        Path path = Paths.get(STATS_FOLDER, filename);
        writeToFile(path, stats);
        System.out.println("stats written to " + filename);
    }

    private static void writeToFile(Path path, String str) {
        Charset charset = Charset.forName("UTF-8");
        try (BufferedWriter writer = Files.newBufferedWriter(path, charset)) {
            writer.write(str, 0, str.length());
        } catch (IOException x) {
            logger.error(x);
        }
    }

    public static int ableToLoadSections() {
        int ableToLoad = 0;
        int unableToLoad = 0;
        int filesReadCounter = 0;
        File folder = new File(PE_FOLDER);
        File[] files = folder.listFiles();
        for (File file : files) {
            try {
                PEData data = PELoader.loadPE(file);
                SectionLoader loader = new SectionLoader(data);
                Map<DataDirectoryKey, DataDirEntry> map = data
                        .getOptionalHeader().getDataDirEntries();
                if (map.containsKey(DataDirectoryKey.RESOURCE_TABLE)) {
                    loader.loadResourceSection();
                }
                if (map.containsKey(DataDirectoryKey.IMPORT_TABLE)) {
                    loader.loadImportSection();
                }
                if (map.containsKey(DataDirectoryKey.EXPORT_TABLE)) {
                    loader.loadExportSection();
                }
                ableToLoad++;
            } catch (Exception e) {
                System.out.println(e.getMessage());
                unableToLoad++;
            }
            filesReadCounter++;
            if (filesReadCounter % 100 == 0) {
                System.out.println("Files read: " + filesReadCounter);
                System.out.println("Able to load: " + ableToLoad);
                System.out.println("Unable to load: " + unableToLoad);
                System.out.println();
            }
        }
        System.out.println("Files read: " + filesReadCounter);
        System.out.println("Able to load: " + ableToLoad);
        System.out.println("Unable to load: " + unableToLoad);
        return ableToLoad;
    }

    public static int ableToLoad() {
        int ableToLoad = 0;
        int unableToLoad = 0;
        int filesReadCounter = 0;
        File folder = new File(PE_FOLDER);
        File[] files = folder.listFiles();
        for (File file : files) {
            try {
                PELoader.loadPE(file);
                ableToLoad++;
            } catch (Exception e) {
                System.out.println(e.getMessage());
                e.printStackTrace();
                unableToLoad++;
            }
            filesReadCounter++;
            if (filesReadCounter % 100 == 0) {
                System.out.println("Files read: " + filesReadCounter);
                System.out.println("Able to load: " + ableToLoad);
                System.out.println("Unable to load: " + unableToLoad);
                System.out.println();
            }
        }
        System.out.println("Files read: " + filesReadCounter);
        System.out.println("Able to load: " + ableToLoad);
        System.out.println("Unable to load: " + unableToLoad);
        return ableToLoad;
    }

    public static void sortPEFiles() throws IOException {
        File folder = new File(BASE_MALW_FOLDER);
        int peCount = 0;
        int noPECount = 0;
        int filesReadCounter = 0;
        System.out.println("reading ...");
        for (File file : folder.listFiles()) {
            if (file.isDirectory())
                continue;
            try {
                PESignature signature = new PESignature(file);
                signature.read();
                peCount++;
                file.renameTo(new File(PE_FOLDER + file.getName()));
            } catch (FileFormatException e) {
                noPECount++;
                file.renameTo(new File(NO_PE_FOLDER + file.getName()));
            }
            filesReadCounter++;
            if (filesReadCounter % 100 == 0) {
                System.out.println("Files read: " + filesReadCounter);
                System.out.println("PEs found: " + peCount);
                System.out.println("No PEs: " + noPECount);
                System.out.println();
            }
        }
        System.out.println("PEs found: " + peCount);
        System.out.println("No PEs: " + noPECount);
    }
}
