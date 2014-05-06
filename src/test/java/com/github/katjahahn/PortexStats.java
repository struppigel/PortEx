package com.github.katjahahn;

import java.io.File;
import java.io.IOException;

public class PortexStats {

	private static final String BASE_MALW_FOLDER = "/home/deque/git/PortEx/src/main/resources/virusshare128";
	private static final String PE_FOLDER = BASE_MALW_FOLDER + "/pevirus/";
	private static final String NO_PE_FOLDER = BASE_MALW_FOLDER + "/nope/";

	public void sortPEFiles() throws IOException {
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
