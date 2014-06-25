package com.github.katjahahn;

import static com.github.katjahahn.tools.anomalies.AnomalyType.*;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

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
import com.github.katjahahn.tools.ShannonEntropy;
import com.github.katjahahn.tools.anomalies.Anomaly;
import com.github.katjahahn.tools.anomalies.AnomalySubType;
import com.github.katjahahn.tools.anomalies.AnomalyType;
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner;

public class PortexStats {

    // TODO add D:\\ partition files from Win 7 machine!

    private static final Logger logger = LogManager.getLogger(PortexStats.class
            .getName());

    private static final String BASE_MALW_FOLDER = "/home/deque/virusshare128";
    @SuppressWarnings("unused")
    private static final String ANOMALY_FOLDER = "/home/deque/portextestfiles/unusualfiles/corkami";
    private static final String PE_FOLDER = BASE_MALW_FOLDER + "/pe/";
    private static final String NO_PE_FOLDER = BASE_MALW_FOLDER + "/nope/";
    private static final String STATS_FOLDER = "portexstats/";
    private static final String GOOD_FILES = "/home/deque/portextestfiles/goodfiles/";
    private static final String BAD_FILES = "/home/deque/portextestfiles/badfiles/";
    private static int noPE = 0;
    private static int notLoaded = 0;
    private static int dirsRead = 0;
    private static int total = 0;
    private static int prevTotal = 0;
    private static int written = 0;

    public static void main(String[] args) throws IOException {
        ableToLoadSections();
    }

    public static void entropies(File[] files) {
        int total = 0;
        int hasHighE = 0;
        int hasLowE = 0;
        double entAverage = 0;
        for (File file : files) {
            try {
                PEData data = PELoader.loadPE(file);
                Map<Integer, Double> entropies = new ShannonEntropy(data)
                        .forSections();
                double entSum = 0;
                boolean hasHighEFlag = false;
                boolean hasLowEFlag = false;
                for (Entry<Integer, Double> entry : entropies.entrySet()) {
                    double entropy = entry.getValue();
                    entSum += entropy;
                    if (entropy > 0.9) {
                        hasHighEFlag = true;
                    }
                    if (entropy < 0.1) {
                        hasLowEFlag = true;
                    }
                }
                if (entropies.size() != 0) {
                    entAverage += (entSum / entropies.size());
                }
                if (hasHighEFlag)
                    hasHighE++;
                if (hasLowEFlag)
                    hasLowE++;
                total++;
                if (total % 1000 == 0) {
                    double highPercent = hasHighE / (double) total;
                    double lowPercent = hasLowE / (double) total;
                    System.out.println("files read: " + total);
                    System.out.println("has high entropy: " + hasHighE + " "
                            + highPercent);
                    System.out.println("has low entropy: " + hasLowE + " "
                            + lowPercent);
                    System.out.println();
                }
            } catch (Exception e) {
                System.err.println(e.getMessage());
            }
        }
        double highPercent = hasHighE / (double) total;
        double lowPercent = hasLowE / (double) total;
        System.out.println("files read: " + total);
        System.out.println("has high entropy: " + hasHighE + " " + highPercent);
        System.out.println("has low entropy: " + hasLowE + " " + lowPercent);
        System.out.println("entropy average: " + (entAverage / (double) total));
    }

    public static void fileTypeCountForFileList() throws IOException {
        List<File> files = readFileList();
        fileTypeCount(files.toArray((new File[files.size()])));
    }

    public static List<File> readFileList() throws IOException {
        System.out.println("reading file list");
        Path filelist = Paths.get(STATS_FOLDER, "pefilelist");
        List<File> files = new ArrayList<File>();
        Charset charset = Charset.forName("US-ASCII");
        try (BufferedReader reader = Files.newBufferedReader(filelist, charset)) {
            String line = null;
            while ((line = reader.readLine()) != null) {
                files.add(new File(line));
            }
        }
        System.out.println("Done reading");
        return files;
    }

    public static void overlayPrevalenceForFileList() throws IOException {
        List<File> files = readFileList();
        overlayPrevalence(files.toArray((new File[files.size()])));
    }

    public static void anomalyStatsForFileList() throws IOException {
        List<File> files = readFileList();
        anomalyStats(files.toArray((new File[files.size()])));
    }

    public static void createPEFileList(File startFolder) {
        Charset charset = Charset.forName("UTF-8");
        Path out = Paths.get("pefilelist");
        try (BufferedWriter writer = Files.newBufferedWriter(out, charset)) {
            createPEFileList(writer, startFolder);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            System.out.println("Files read: " + total);
            System.out.println("No PE: " + noPE);
            System.out.println("PE files not loaded: " + notLoaded);
            System.out.println("PE files successfully written: " + written);
        }
    }

    public static void createPEFileList(BufferedWriter writer, File startFolder)
            throws IOException {
        File[] files = startFolder.listFiles();
        if (files == null) {
            System.out.println("Skipped unreadable file: "
                    + startFolder.getCanonicalPath());
            return;
        }
        for (File file : files) {
            total++;
            if (file.isDirectory()) {
                createPEFileList(writer, file);
            } else {
                try {
                    new PESignature(file).read();
                    String str = file.getAbsolutePath() + "\n";
                    writer.write(str, 0, str.length());
                    written++;
                } catch (FileFormatException e) {
                    noPE++;
                } catch (Exception e) {
                    System.err.println(e.getMessage());
                    notLoaded++;
                }
                if (total != prevTotal && total % 1000 == 0) {
                    prevTotal = total;
                    System.out.println("Files read: " + total);
                    System.out.println("PE Files read: " + written);
                }
            }
        }
        dirsRead++;
        if (dirsRead % 500 == 0) {
            System.out.println("Directories read: " + dirsRead);
            System.out.println("Current Directory finished: "
                    + startFolder.getAbsolutePath());
        }
    }

    public static void anomalyStats(File[] files) {
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
                logger.error("problem with file " + file.getAbsolutePath()
                        + " file was not loaded!");
                e.printStackTrace();
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

        String stats2 = "Absolute anomaly count (all files)\n\ntotal files: "
                + total + "\nstructural: " + anomalies[STRUCTURE.ordinal()]
                + "\nwrong value: " + anomalies[WRONG.ordinal()]
                + "\nreserved: " + anomalies[RESERVED.ordinal()]
                + "\ndeprecated: " + anomalies[DEPRECATED.ordinal()]
                + "\nnon default: " + anomalies[NON_DEFAULT.ordinal()];

        String stats3 = "Anomaly occurance per file (absolute) \n\ntotal files: "
                + total
                + "\nstructural: "
                + anPerFile[STRUCTURE.ordinal()]
                + "\nwrong value: "
                + anPerFile[WRONG.ordinal()]
                + "\nreserved: "
                + anPerFile[RESERVED.ordinal()]
                + "\ndeprecated: "
                + anPerFile[DEPRECATED.ordinal()]
                + "\nnon default: " + anPerFile[NON_DEFAULT.ordinal()];

        String stats4 = "Anomaly occurance per file in percent \n\ntotal files: "
                + total
                + "\nstructural: "
                + occPerFile[STRUCTURE.ordinal()]
                + "\nwrong value: "
                + occPerFile[WRONG.ordinal()]
                + "\nreserved: "
                + occPerFile[RESERVED.ordinal()]
                + "\ndeprecated: "
                + occPerFile[DEPRECATED.ordinal()]
                + "\nnon default: "
                + occPerFile[NON_DEFAULT.ordinal()]
                + "\nNot loaded: " + notLoaded + "\nDone\n";
        String report = stats1 + "\n\n" + stats2 + "\n\n" + stats3 + "\n\n"
                + stats4;
        System.out.println(report);
        writeStats(report);
    }

    // TODO equality of anomalies is nuts, correct it. value differences
    // shouldn't count.
    public static void anomalyCount(File[] files, String base) {
        System.out.println("starting anomaly count");
        Map<AnomalySubType, Integer> counter = new HashMap<>();
        int total = 0;
        int notLoaded = 0;
        for (File file : files) {
            try {
                total++;
                PEData data = PELoader.loadPE(file);
                PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(data);
                List<Anomaly> list = scanner.getAnomalies();
                Set<AnomalySubType> set = new HashSet<>();
                for (Anomaly anomaly : list) {
                    set.add(anomaly.subtype());
                }
                for (AnomalySubType subtype : set) {
                    if (counter.containsKey(subtype)) {
                        Integer prev = counter.get(subtype);
                        counter.put(subtype, prev + 1);
                    } else {
                        counter.put(subtype, 1);
                    }
                }
                if (total % 1000 == 0) {
                    System.out.println("Files read: " + total + "/"
                            + files.length);
                }
            } catch (FileFormatException e) {
                if (!file.isDirectory()) {
                    file.delete();
                    logger.error("file " + file.getAbsolutePath()
                            + " deleted, no PE");
                } else {
                    logger.error("problem with file " + file.getAbsolutePath()
                            + " file was not loaded!");
                }
                notLoaded++;
            } catch (Exception e) {
                logger.error("problem with file " + file.getAbsolutePath()
                        + " file was not loaded!");
                e.printStackTrace();
                notLoaded++;
            }
        }
        String report = "Anomalies Counted: \n\nBase folder: " + base + "\n"
                + createReport(counter, total - notLoaded) + "\ntotal files: "
                + total + "\nnot loaded: " + notLoaded + "\nDone\n\n";
        System.out.println(report);
        writeStats(report);
        System.out.println("anomaly count done");
    }

    private static String createReport(Map<AnomalySubType, Integer> map,
            int total) {
        StringBuilder b = new StringBuilder();
        for (Entry<AnomalySubType, Integer> entry : map.entrySet()) {
            AnomalySubType type = entry.getKey();
            Integer counter = entry.getValue();
            double percent = counter * 100 / (double) total;
            b.append(type + ";" + counter + ";" + percent + "\n");
            // b.append(counter + " times / " + percent + "% " + type + "\n");
        }
        return b.toString();
    }

    public static void overlayPrevalence(File[] files) {
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
        double percentage = total / (double) hasOverlay;
        String stats = "total: " + total + "\nhas overlay: " + hasOverlay
                + "\nno overlay: " + hasNoOverlay
                + "\npercentage files with overlay: " + percentage
                + "\nNot loaded: " + notLoaded + "\nDone\n";
        System.out.println(stats);
        writeStats(stats);
    }

    public static void fileTypeCount(File[] files) {
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
        List<File> problemPEs = new ArrayList<>();
        File folder = new File(BAD_FILES);
        File[] files = folder.listFiles();
        for (File file : files) {
            try {
                PEData data = PELoader.loadPE(file);
                SectionLoader loader = new SectionLoader(data);
                Map<DataDirectoryKey, DataDirEntry> map = data
                        .getOptionalHeader().getDataDirEntries();
                // if (map.containsKey(DataDirectoryKey.RESOURCE_TABLE)) {
                // loader.loadResourceSection();
                // }
                if (map.containsKey(DataDirectoryKey.IMPORT_TABLE)
                        && loader
                                .pointsToValidSection(DataDirectoryKey.IMPORT_TABLE)) {
                    loader.loadImportSection();
                }
                // if (map.containsKey(DataDirectoryKey.EXPORT_TABLE)) {
                // loader.loadExportSection();
                // }
                ableToLoad++;
            } catch (Exception e) {
                System.err.println(e.getMessage() + " file: " + file.getName());
                problemPEs.add(file);
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
        String report = "Files read: " + filesReadCounter + "\nAble to load: "
                + ableToLoad + "\nUnable to load: " + unableToLoad;
        for (File file : problemPEs) {
            report += "\n" + file.getName();
        }
        System.out.println(report);
        writeStats(report);
        return ableToLoad;
    }

    public static int ableToLoad() {
        int ableToLoad = 0;
        int unableToLoad = 0;
        List<File> problemPEs = new ArrayList<>();
        int filesReadCounter = 0;
        File folder = new File(BAD_FILES);
        File[] files = folder.listFiles();
        for (File file : files) {
            try {
                PELoader.loadPE(file);
                ableToLoad++;
            } catch (Exception e) {
                e.printStackTrace();
                problemPEs.add(file);
                unableToLoad++;
            }
            filesReadCounter++;
            if (filesReadCounter % 1000 == 0) {
                System.out.println("Files read: " + filesReadCounter);
                System.out.println("Able to load: " + ableToLoad);
                System.out.println("Unable to load: " + unableToLoad);
                System.out.println();
            }
        }
        String report = "Files read: " + filesReadCounter + "\nAble to load: "
                + ableToLoad + "\nUnable to load: " + unableToLoad;
        for (File file : problemPEs) {
            report += "\n" + file.getName();
        }
        System.out.println(report);
        writeStats(report);
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
