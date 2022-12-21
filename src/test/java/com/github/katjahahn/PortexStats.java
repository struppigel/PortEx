package com.github.katjahahn;

import com.github.katjahahn.parser.FileFormatException;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.PESignature;
import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.coffheader.FileCharacteristic;
import com.github.katjahahn.parser.optheader.DataDirEntry;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.github.katjahahn.parser.optheader.OptionalHeader.MagicNumber;
import com.github.katjahahn.parser.sections.SectionHeader;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.github.katjahahn.tools.Overlay;
import com.github.katjahahn.tools.ShannonEntropy;
import com.github.katjahahn.tools.anomalies.Anomaly;
import com.github.katjahahn.tools.anomalies.AnomalySubType;
import com.github.katjahahn.tools.anomalies.AnomalyType;
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Map.Entry;

import static com.github.katjahahn.tools.anomalies.AnomalyType.*;

public class PortexStats {

	private static final Logger logger = LogManager.getLogger(PortexStats.class
			.getName());

	public static final String BASE_MALW_FOLDER = "/home/deque/virusshare128";
	public static final String ANOMALY_FOLDER = "/home/deque/portextestfiles/unusualfiles/corkami";
	public static final String PE_FOLDER = BASE_MALW_FOLDER + "/pe/";
	public static final String NO_PE_FOLDER = BASE_MALW_FOLDER + "/nope/";
	public static final String STATS_FOLDER = "/home/karsten/portexstats/";
	public static final String GOOD_FILES = "/home/karsten/git/PortEx/cleanlist.txt";
	public static final String BAD_FILES = "/home/karsten/git/PortEx/locatedmalware.txt";
	private static int noPE = 0;
	private static int notLoaded = 0;
	private static int dirsRead = 0;
	private static int total = 0;
	private static int prevTotal = 0;
	private static int written = 0;
	private static final int POWERMAX = 4;

	public static void main(String[] args) throws IOException {
		System.out.println();
		System.out.println("Locating samples ...");
		locateSamples(new File("/home/karsten/git/PortEx/bigmalwarelist.csv"), new File(BAD_FILES));
		System.out.println();
		System.out.println("Preparing anomaly stats ...");
		anomalyStats(malwareFilesGData());
		System.out.println();
		System.out.println("Preparing anomaly count ...");
		anomalyCount(malwareFilesGData(), "malware");
		System.out.println();
		System.out.println("Overlay prevalence analysis ...");
		overlayPrevalence(malwareFilesGData());
		System.out.println();
		System.out.println("Entropy analysis ...");
		entropies(malwareFilesGData());
		System.out.println("Section Name Counting ...");
		sectionNameCount(malwareFilesGData(), "malware");
		System.out.println();
		System.out.println("<3 ALL DONE! <3");
	}

	/**
	 * Turns hash list into list of sample pathes.
	 * Removes non-PE files.
	 * 
	 * @param hashList
	 * @param outList
	 * @throws IOException
	 */
	private static void locateSamples(File hashList, File outList)
			throws IOException {
		String samples = "";
		long nr = 0;
		long noPECounter = 0;
		try (BufferedReader reader = new BufferedReader(
				new FileReader(hashList))) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				nr++;
				ProcessBuilder pb = new ProcessBuilder(
						"/home/karsten/bin/samplelocator_client.py", line);
				Process process = pb.start();
				BufferedReader br = new BufferedReader(new InputStreamReader(
						process.getInputStream()));
				String located;
				while ((located = br.readLine()) != null) {
					try {
						File file = new File(located);
						PESignature signature = new PESignature(file);
						signature.read();
						samples += located + "\n";
					} catch (FileFormatException e) { 
						noPECounter++;
					}
				}
				if (nr % 100 == 0) {
					System.out.println("locating sample number " + nr);
					System.out.println("No PE: " + noPECounter);
				}
				// temp save after 1000 samples
				if (nr % 1000 == 0) {
					System.out.println("Saving results to " + outList.getPath()
							+ " ...");
					appendToFile(outList.toPath(), samples);
					samples = "";
				}
			}
		}
		appendToFile(outList.toPath(), samples);
	}

	@SuppressWarnings("unused")
	private static void convertToLatexTable() throws FileNotFoundException,
			IOException {
		File file = new File("/home/deque/git/Thesis/arbeit/plots/results.txt");
		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
			String line = null;
			int nr = 0;
			while ((line = reader.readLine()) != null) {
				String[] split = line.split("\\s+");
				System.out.print(nr);
				for (String element : split) {
					Double d = Double.valueOf(element);
					String percent = String.format("%.2f", (d * 100))
							+ "\\thinspace{}\\%";
					System.out.print(" & " + percent);
				}
				System.out.println("\\\\");
				nr++;
			}
		}
	}

	private static String percent(double value) {
		NumberFormat formatter = new DecimalFormat("##0.00");
		return formatter.format(value);
	}

	@SuppressWarnings("unused")
	private static String createXLetAnomalyStats(int badTotal, int goodTotal, int threshold)
			throws FileNotFoundException, IOException {
		double total = badTotal + goodTotal;
		Map<Set<AnomalySubType>, Integer> goodStats = readAnomalyXLetStats(new File(
				"goodfiles"));
		Map<Set<AnomalySubType>, Integer> badStats = readAnomalyXLetStats(new File(
				"badfiles"));
		StringBuffer buf = new StringBuffer(
				"anomalies;good;bad;boost;badprob\n");
		Map<String, Double> lines = new TreeMap<>();
		for (Entry<Set<AnomalySubType>, Integer> badEntry : badStats.entrySet()) {
			int badCount = badEntry.getValue();
			Set<AnomalySubType> types = badEntry.getKey();
			int goodCount = 0;
			if (goodStats.containsKey(types)) {
				goodCount = goodStats.get(types);
			}
			if (goodCount + badCount < threshold)
				continue; // Threshold
			double goodPercent = goodCount / (double) goodTotal;
			double badPercent = badCount / (double) badTotal;
			double badProb = badPercent
					* (badTotal / total)
					/ (double) (badPercent * (badTotal / total) + goodPercent
							* (goodTotal / total));
			double boost = (badPercent / (double) (badPercent + goodPercent)) * 20 - 10;
			// write stat report
			boolean first = true;
			String line = "";
			for (AnomalySubType type : types) {
				if (!first) {
					line += " & ";
				}
				first = false;
				line += type.toString();
			}
			line += "  " + percent(goodPercent * 100) + "  "
					+ percent(badPercent * 100) + "  " + percent(boost) + "  "
					+ percent(badProb * 100) + "\n";
			lines.put(line, boost);
		}
		for (Entry<String, Double> entry : entriesSortedByValues(lines)) {
			buf.append(entry.getKey());
		}
		writeStats(buf.toString(), "anomalyXletsanalysis");
		return buf.toString();
	}

	private static Map<Set<AnomalySubType>, Integer> readAnomalyXLetStats(
			File file) throws FileNotFoundException, IOException {
		Map<Set<AnomalySubType>, Integer> stats = new HashMap<>();
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			for (String line; (line = br.readLine()) != null;) {
				// evaluate line
				String[] elems = line.split(";");
				String[] keys = elems[0].split("&");
				// parse number of affected files
				Integer count = Integer.parseInt(elems[1]);
				// collect anomaly types
				Set<AnomalySubType> anomalyTypes = new HashSet<>();
				for (String key : keys) {
					AnomalySubType type = AnomalySubType.valueOf(key);
					anomalyTypes.add(type);
				}
				// put into stats
				stats.put(anomalyTypes, count);
			}
		}
		return stats;
	}

	private static void buildPowerSet(List<AnomalySubType> list, int count,
			Set<List<AnomalySubType>> powerSet) {
		if (list.size() > POWERMAX)
			return;
		powerSet.add(list);

		for (int i = 0; i < list.size(); i++) {
			List<AnomalySubType> temp = new ArrayList<AnomalySubType>(list);
			temp.remove(i);
			buildPowerSet(temp, temp.size(), powerSet);
		}
	}

	private static void countAnomalyXLets(Set<AnomalySubType> set,
			Map<Set<AnomalySubType>, Integer> counter) {
		List<AnomalySubType> mainList = new ArrayList<>(set);
		Set<List<AnomalySubType>> result = new HashSet<>();
		buildPowerSet(mainList, mainList.size(), result);
		for (List<AnomalySubType> subset : result) {
			Set<AnomalySubType> key = new HashSet<>(subset);
			if (counter.containsKey(key)) {
				int value = counter.get(key);
				counter.put(key, value + 1);
			} else {
				counter.put(key, 1);
			}
		}
	}

	private static String createXLetReport(
			Map<Set<AnomalySubType>, Integer> counter, int total) {
		StringBuilder b = new StringBuilder();
		b.append("\nAnomaly Types;Count;Percentage\n\n");
		for (Entry<Set<AnomalySubType>, Integer> entry : counter.entrySet()) {
			Set<AnomalySubType> types = entry.getKey();
			Integer count = entry.getValue();
			double percent = count * 100 / (double) total;
			boolean first = true;
			for (AnomalySubType type : types) {
				if (!first) {
					b.append("&");
				}
				first = false;
				b.append(type);
			}
			b.append(";" + count + ";" + percent + "\n");
		}
		return b.toString();
	}

	@SuppressWarnings("unused")
	private static void anomalyXlets(File[] files, String base) {
		System.out.println("starting anomaly xlets count");
		Map<Set<AnomalySubType>, Integer> counter = new HashMap<>();
		int total = 0;
		int notLoaded = 0;
		for (File file : files) {
			try {
				total++;
				PEData data = PELoader.loadPE(file);
				PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(data);
				List<Anomaly> list = scanner.getAnomalies();
				Set<AnomalySubType> set = new TreeSet<>();
				for (Anomaly anomaly : list) {
					set.add(anomaly.subtype());
				}
				countAnomalyXLets(set, counter);
				if (total % 1000 == 0) {
					System.out.println("Files read: " + total + "/"
							+ files.length);
				}
			} catch (Exception e) {
				logger.error(file.getAbsolutePath() + " not loaded! Message: "
						+ e.getMessage());
				// e.printStackTrace();
				notLoaded++;
			}
		}
		String report = "Anomalies Counted: \n\nBase folder: " + base + "\n"
				+ createXLetReport(counter, total - notLoaded)
				+ "\ntotal files: " + total + "\nnot loaded: " + notLoaded
				+ "\nDone\n\n";
		System.out.println(report);
		writeStats(report, "anomalycount");
		System.out.println("anomaly count done");
	}

	@SuppressWarnings("unused")
	private static void compareSecNames(String goodstats, String badstats, int threshold)
			throws FileNotFoundException, IOException {
		File good = new File(goodstats);
		File bad = new File(badstats);
		Map<String, Integer> goodCount = readSecCount(good);
		Map<String, Integer> badCount = readSecCount(bad);
		int goodtotal = getTotal(goodCount);
		int badtotal = getTotal(badCount);

		StringBuilder report = new StringBuilder();
		report.append("secname count comparison\n\n"
				+ "secname;goodpercent;badpercent;malwareprob\n\n");
		for (Entry<String, Integer> entry : goodCount.entrySet()) {
			String name = entry.getKey();
			int badValue = 0;
			if (badCount.containsKey(name)) {
				badValue = badCount.get(name);
			}
			int goodValue = entry.getValue();
			double goodPercent = goodValue / (double) goodtotal;
			double badPercent = badValue / (double) badtotal;
			double malProb = badPercent * 0.5
					/ (badPercent * 0.5 + goodPercent * 0.5);
			if (goodValue + badValue > threshold) {
				report.append(name + ";" + goodPercent + ";" + badPercent + ";"
						+ malProb + "\n");
			}
		}
		for (Entry<String, Integer> entry : badCount.entrySet()) {
			String name = entry.getKey();
			if (!goodCount.containsKey(name)) {
				int badValue = entry.getValue();
				int goodValue = 0;
				double badPercent = badValue / (double) badtotal;
				double goodPercent = 0;
				double malProb = badPercent * 0.5
						/ (badPercent * 0.5 + goodPercent * 0.5);
				if (goodValue + badValue > threshold) {
					report.append(name + ";" + goodPercent + ";" + badPercent
							+ ";" + malProb + "\n");
				}
			}
		}
		System.out.println(report);
		writeStats(report.toString(), "secnamecomparison");
		System.out.println("done");
	}

	private static int getTotal(Map<String, Integer> goodCount) {
		int total = 0;
		for (Integer i : goodCount.values()) {
			total += i;
		}
		return total;
	}

	private static Map<String, Integer> readSecCount(File file)
			throws FileNotFoundException, IOException {
		Map<String, Integer> map = new HashMap<>();
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			String line = null;
			while ((line = br.readLine()) != null) {
				String[] split = line.split(";");
				if (split.length == 2) {
					map.put(split[0], Integer.parseInt(split[1]));
				}
			}
		}
		return map;
	}

	private static <K, V extends Comparable<? super V>> SortedSet<Map.Entry<K, V>> entriesSortedByValues(
			Map<K, V> map) {
		SortedSet<Map.Entry<K, V>> sortedEntries = new TreeSet<Map.Entry<K, V>>(
				new Comparator<Map.Entry<K, V>>() {
					@Override
					public int compare(Map.Entry<K, V> e1, Map.Entry<K, V> e2) {
						return e2.getValue().compareTo(e1.getValue());
					}
				});
		sortedEntries.addAll(map.entrySet());
		return sortedEntries;
	}

	@SuppressWarnings("unused")
	private static void sectionNameCount(File[] files, String baseFolder)
			throws IOException {
		Map<String, Integer> nameCount = new HashMap<>();
		int total = 0;
		for (File file : files) {
			total++;
			try {
				PEData data = PELoader.loadPE(file);
				SectionTable table = data.getSectionTable();
				for (SectionHeader header : table.getSectionHeaders()) {
					String name = header.getName();
					if (nameCount.containsKey(name)) {
						int value = nameCount.get(name) + 1;
						nameCount.put(name, value);
					} else {
						nameCount.put(name, 1);
					}
				}
			} catch (Exception e) {
				logger.error(e);
			}
			if (total % 1000 == 0) {
				System.out.println("Files total: " + total);
				int entryNr = 0;
				for (Entry<String, Integer> entry : entriesSortedByValues(nameCount)) {
					entryNr++;
					System.out
							.println(entry.getKey() + ": " + entry.getValue());
					if (entryNr == 5) {
						break;
					}
				}
			}
		}
		System.out.println("Done counting, preparing stats");
		StringBuilder stats = new StringBuilder();
		stats.append(baseFolder + "\nSection name count\n\n");
		for (Entry<String, Integer> entry : entriesSortedByValues(nameCount)) {
			stats.append(entry.getKey() + ";" + entry.getValue() + "\n");
		}
		writeStats(stats.toString(), "sectionnames");
	}

	@SuppressWarnings("unused")
	private static File[] badFiles() {
		System.out.println("preparing file list...");
		File folder = new File(BAD_FILES);
		File[] allFiles = folder.listFiles();
		System.out.println("files listed: " + allFiles.length);
		return allFiles;
	}

	public static File[] goodFiles() {
		System.out.println("preparing file list...");
		File[] folders = new File(GOOD_FILES).listFiles();
		List<File[]> arrayList = new ArrayList<>();
		for (File folder : folders) {
			arrayList.add(folder.listFiles());
		}
		File[] allFiles = new File[0];
		for (File[] files : arrayList) {
			allFiles = concat(allFiles, files);
		}
		System.out.println("files listed: " + allFiles.length);
		return allFiles;
	}

	public static File[] cleanFilesGData() throws FileNotFoundException,
			IOException {
		ArrayList<File> fileList = new ArrayList<>();
		try (BufferedReader reader = new BufferedReader(new FileReader(
				new File(GOOD_FILES)))) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				fileList.add(new File(line));
			}
		}
		File[] files = Arrays.copyOf(fileList.toArray(), fileList.size(),
				File[].class);
		return files;
	}

	public static File[] malwareFilesGData() throws FileNotFoundException,
			IOException {
		ArrayList<File> fileList = new ArrayList<>();
		try (BufferedReader reader = new BufferedReader(new FileReader(
				new File(BAD_FILES)))) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				fileList.add(new File(line));
			}
		}
		File[] files = Arrays.copyOf(fileList.toArray(), fileList.size(),
				File[].class);
		return files;
	}

	private static File[] concat(File[] a, File[] b) {
		int aLen = a.length;
		int bLen = b.length;
		File[] c = new File[aLen + bLen];
		System.arraycopy(a, 0, c, 0, aLen);
		System.arraycopy(b, 0, c, aLen, bLen);
		return c;
	}

	public static void entropies(File[] files) {
		int total = 0;
		int hasHighE = 0;
		int highETotal = 0;
		int lowETotal = 0;
		int averageTotal = 0;
		int veryHighETotal = 0;
		int veryLowETotal = 0;
		int hasLowE = 0;
		int hasAverageE = 0;
		int hasVeryHighE = 0;
		int hasVeryLowE = 0;
		@SuppressWarnings("unused")
		double entAverage = 0;
		for (File file : files) {
			try {
				PEData data = PELoader.loadPE(file);
				Map<Integer, Double> entropies = new ShannonEntropy(data)
						.forSections();
				double entSum = 0;
				boolean hasHighEFlag = false;
				boolean hasLowEFlag = false;
				boolean hasVeryHighEFlag = false;
				boolean hasVeryLowEFlag = false;
				boolean hasAverageFlag = false;
				for (Entry<Integer, Double> entry : entropies.entrySet()) {
					double entropy = entry.getValue();
					entSum += entropy;
					if (entropy > 0.75) {
						highETotal++;
						hasHighEFlag = true;
						if (entropy > 0.90) {
							hasVeryHighEFlag = true;
							veryHighETotal++;
						}
					} else if (entropy < 0.25) {
						lowETotal++;
						hasLowEFlag = true;
						if (entropy < 0.10) {
							hasVeryLowEFlag = true;
							veryLowETotal++;
						}
					} else {
						averageTotal++;
						hasAverageFlag = true;
					}
				}
				if (entropies.size() != 0) {
					entAverage += (entSum / entropies.size());
				}
				if (hasAverageFlag)
					hasAverageE++;
				if (hasHighEFlag)
					hasHighE++;
				if (hasVeryHighEFlag)
					hasVeryHighE++;
				if (hasLowEFlag)
					hasLowE++;
				if (hasVeryLowEFlag)
					hasVeryLowE++;
				total++;
				if (total % 1000 == 0) {
					double veryHighPercent = hasVeryHighE / (double) total;
					double highPercent = hasHighE / (double) total;
					double lowPercent = hasLowE / (double) total;
					double averagePercent = hasAverageE / (double) total;
					double veryLowPercent = hasVeryLowE / (double) total;
					double highEPerFile = highETotal / (double) total;
					double veryHighEPerFile = veryHighETotal / (double) total;
					double veryLowEPerFile = veryLowETotal / (double) total;
					double lowEPerFile = lowETotal / (double) total;
					double averageEPerFile = averageTotal / (double) total;
					System.out.println("files read: " + total);
					System.out.println("has very high entropy: " + hasVeryHighE
							+ " " + veryHighPercent);
					System.out.println("has high entropy: " + hasHighE + " "
							+ highPercent);
					System.out.println("has average entropy: " + hasAverageE
							+ " " + averagePercent);
					System.out.println("has low entropy: " + hasLowE + " "
							+ lowPercent);
					System.out.println("has very low entropy: " + hasVeryLowE
							+ " " + veryLowPercent);
					System.out.println();
					System.out.println("average very high entropy sections: "
							+ veryHighEPerFile);
					System.out.println("average high entropy sections: "
							+ highEPerFile);
					System.out.println("average average entropy sections: "
							+ averageEPerFile);
					System.out.println("average low entropy sections: "
							+ lowEPerFile);
					System.out.println("average very low entropy sections: "
							+ veryLowEPerFile);
					System.out.println();
				}
			} catch (Exception e) {
				System.err.println(e.getMessage());
			}
		}
		double veryHighPercent = hasVeryHighE / (double) total;
		double highPercent = hasHighE / (double) total;
		double lowPercent = hasLowE / (double) total;
		double averagePercent = hasAverageE / (double) total;
		double veryLowPercent = hasVeryLowE / (double) total;
		double highEPerFile = highETotal / (double) total;
		double veryHighEPerFile = veryHighETotal / (double) total;
		double veryLowEPerFile = veryLowETotal / (double) total;
		double lowEPerFile = lowETotal / (double) total;
		double averageEPerFile = averageTotal / (double) total;
		String result = "files read: " + total + "\n"
				+ "has very high entropy: " + hasVeryHighE + " "
				+ veryHighPercent + "\n" + "has high entropy: " + hasHighE
				+ " " + highPercent + "\n" + "has average entropy: "
				+ hasAverageE + " " + averagePercent + "\n"
				+ "has low entropy: " + hasLowE + " " + lowPercent + "\n"
				+ "has very low entropy: " + hasVeryLowE + " " + veryLowPercent
				+ "\n\n" + "average very high entropy sections: "
				+ veryHighEPerFile + "\n" + "average high entropy sections: "
				+ highEPerFile + "\n" + "average average entropy sections: "
				+ averageEPerFile + "\n" + "average low entropy sections: "
				+ lowEPerFile + "\n" + "average very low entropy sections: "
				+ veryLowEPerFile + "\n\n";
		System.out.println(result);
		writeStats(result, "entropy");
	}

	public static void fileTypeCountForFileList() throws IOException {
		List<File> files = readFileList(Paths.get(STATS_FOLDER, "pefilelist"));
		fileTypeCount(files.toArray((new File[files.size()])));
	}

	public static List<File> readFileList(Path filelist) throws IOException {
		System.out.println("reading file list");
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
		List<File> files = readFileList(Paths.get(STATS_FOLDER, "pefilelist"));
		overlayPrevalence(files.toArray((new File[files.size()])));
	}

	public static void anomalyStatsForFileList() throws IOException {
		List<File> files = readFileList(Paths.get(STATS_FOLDER, "pefilelist"));
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
		int malformedFiles = 0;
		int malformationsTotal = 0;
		int[] moreThanNMalformationsTotal = new int[1000];
		int[] moreThanNAnomaliesTotal = new int[1000];
		for (File file : files) {
			try {
				total++;
				PEData data = PELoader.loadPE(file);
				PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(data);
				List<Anomaly> list = scanner.getAnomalies();
				boolean malformationFlag = false;
				int malformationsThisFile = 0;
				int anomaliesThisFile = 0;
				for (Anomaly a : list) {
					int ordinal = a.getType().ordinal();
					anomalies[ordinal] += 1;
					occured[ordinal] = true;
					anomaliesThisFile++;
					if (a.getType() != AnomalyType.NON_DEFAULT) {
						malformationFlag = true;
						malformationsTotal++;
						malformationsThisFile++;
					}

				}
				for (int i = 0; i <= malformationsThisFile; i++) {
					moreThanNMalformationsTotal[i]++;
				}
				for (int i = 0; i <= anomaliesThisFile; i++) {
					moreThanNAnomaliesTotal[i]++;
				}
				if (malformationFlag) {
					malformedFiles++;
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
		double malformationsPerMalformedFile = malformationsTotal
				/ (double) malformedFiles;
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

		String stats3 = "Anomaly occurrence per file (absolute) \n\ntotal files: "
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

		String stats4 = "Anomaly occurrence per file in percent \n\ntotal files: "
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
		String stats5 = "";
		for (int i = 0; i < moreThanNMalformationsTotal.length; i++) {
			int value = moreThanNMalformationsTotal[i];
			double percentage = value / (double) total * 100;
			if (value != 0) {
				stats5 += "more than " + i + " malformations: " + value + "("
						+ percentage + "% )\n";

			}
		}
		for (int i = 0; i < moreThanNAnomaliesTotal.length; i++) {
			int value = moreThanNAnomaliesTotal[i];
			double percentage = value / (double) total * 100;
			if (value != 0) {
				stats5 += "more than " + i + " anomalies: " + value + "("
						+ percentage + "% )\n";

			}
		}
		String report = stats1 + "\n\n" + stats2 + "\n\n" + stats3 + "\n\n"
				+ stats4 + "\n\n" + stats5 + "\n\n overall malformed files: "
				+ malformedFiles + "\n\n malformations per malformed file: "
				+ malformationsPerMalformedFile;
		System.out.println(report);
		writeStats(report, "anomalytype");
	}

	public static void anomalyCount(File[] files, String base) {
		System.out.println("starting anomaly count");
		Map<AnomalySubType, Integer> counter = new HashMap<>();
		int total = 0;
		int notLoaded = 0;
		for (File file : files) {
			try {
				// System.out.println(file.getName());
				total++;
				PEData data = PELoader.loadPE(file);
				PEAnomalyScanner scanner = PEAnomalyScanner.newInstance(data);
				List<Anomaly> list = scanner.getAnomalies();
				Set<AnomalySubType> set = new TreeSet<>();
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
			} catch (Exception e) {
				logger.error(file.getAbsolutePath() + " not loaded! Message: "
						+ e.getMessage());
				// e.printStackTrace();
				notLoaded++;
			}
		}
		String report = "Anomalies Counted: \n\nBase folder: " + base + "\n"
				+ createReport(counter, total - notLoaded) + "\ntotal files: "
				+ total + "\nnot loaded: " + notLoaded + "\nDone\n\n";
		System.out.println(report);
		writeStats(report, "anomalycount");
		System.out.println("anomaly count done");
	}

	private static String createReport(Map<AnomalySubType, Integer> map,
			int total) {
		StringBuilder b = new StringBuilder();
		b.append("\nAnomaly Type;Count;Percentage\n\n");
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
		long overlaySizeSum = 0;
		int total = 0;
		for (File file : files) {
			try {
				total++;
				PEData data = PELoader.loadPE(file);
				Overlay overlay = new Overlay(data);
				if (overlay.exists()) {
					hasOverlay++;
					overlaySizeSum += overlay.getSize();
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
		double percentage = hasOverlay / (double) total;
		long avgSize = overlaySizeSum / total;
		String stats = "total: " + total + "\nhas overlay: " + hasOverlay
				+ "\nno overlay: " + hasNoOverlay
				+ "\npercentage files with overlay: " + percentage
				+ "\n average overlay size: " + avgSize + "\nNot loaded: "
				+ notLoaded + "\nDone\n";
		System.out.println(stats);
		writeStats(stats, "overlay");
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
			} catch (FileFormatException e) {
				notLoaded++;
				System.out.println("removing file: " + file.getName());
				file.delete();
			} catch (Exception e) {
				e.printStackTrace();
				notLoaded++;
			}
		}
		String stats = "total: " + total + "\nPE32 files: " + pe32Count
				+ "\nPE32+ files: " + pe32PlusCount + "\nDLL files: "
				+ dllCount + "\nSystem files: " + sysCount + "\nExe files: "
				+ exeCount + "\nNot loaded: " + notLoaded + "\nDone\n";
		System.out.println(stats);
		writeStats(stats, "filetypecount");
	}

	private static void writeStats(String stats, String statname) {
		Date date = new Date();
		SimpleDateFormat dateFormat = new SimpleDateFormat(
				"yyyy-MM-dd_HH-mm-ss");
		String filename = statname + "-" + dateFormat.format(date) + ".stat";
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

	private static void appendToFile(Path path, String str) {
		try {
			Files.write(path, str.getBytes(), StandardOpenOption.APPEND,
					StandardOpenOption.CREATE);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static int ableToLoadSections(File folder) {
		int ableToLoad = 0;
		int unableToLoad = 0;
		int filesReadCounter = 0;
		List<String> problemPEs = new ArrayList<>();
		File[] files = folder.listFiles();
		for (File file : files) {
			try {
				PEData data = PELoader.loadPE(file);
				SectionLoader loader = new SectionLoader(data);
				Map<DataDirectoryKey, DataDirEntry> map = data
						.getOptionalHeader().getDataDirectory();
				if (map.containsKey(DataDirectoryKey.RESOURCE_TABLE)
						&& loader
								.hasValidPointer(DataDirectoryKey.RESOURCE_TABLE)) {
					loader.loadResourceSection();
				}
				if (map.containsKey(DataDirectoryKey.IMPORT_TABLE)
						&& loader
								.hasValidPointer(DataDirectoryKey.IMPORT_TABLE)) {
					loader.loadImportSection();
				}
				if (map.containsKey(DataDirectoryKey.EXPORT_TABLE)
						&& loader
								.hasValidPointer(DataDirectoryKey.EXPORT_TABLE)) {
					loader.loadExportSection();
				}
				ableToLoad++;
			} catch (Exception e) {
				System.err.println(e.getMessage() + " file: " + file.getName());
				problemPEs.add(file.getName() + ": " + e.getMessage());
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
		for (String message : problemPEs) {
			report += "\n" + message;
		}
		System.out.println(report);
		writeStats(report, "sectionload");
		return ableToLoad;
	}

	public static int ableToLoad(File[] files) {
		int ableToLoad = 0;
		int unableToLoad = 0;
		List<File> problemPEs = new ArrayList<>();
		int filesReadCounter = 0;
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
		writeStats(report, "peload");
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
