package com.github.katjahahn;

import java.io.File;
import java.io.IOException;

public class PortexStats {

	private static final String BASE_MALW_FOLDER = "/home/deque/virusshare128";
	private static final String PE_FOLDER = BASE_MALW_FOLDER + "/pe/";
	private static final String NO_PE_FOLDER = BASE_MALW_FOLDER + "/nope/";

	public static void main(String[] args) throws IOException {
		ableToLoad();
	}

	public static int ableToLoad() {
		int ableToLoad = 0;
		int filesReadCounter = 0;
		File folder = new File(PE_FOLDER);
		File[] files = folder.listFiles();
		for (File file : files) {
			try {
				PELoader.loadPE(file);
				ableToLoad++;
			} catch (Exception e) {
				System.err.println(e.getMessage());
			}
			filesReadCounter++;
			if (filesReadCounter % 100 == 0) {
				System.out.println("Files read: " + filesReadCounter);
				System.out.println("Able to load: " + ableToLoad);
				System.out.println();
			}
		}
		System.out.println("Able to load " + ableToLoad + "/"
				+ files.length + " successfully.");
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
