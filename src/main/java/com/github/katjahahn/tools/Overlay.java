package com.github.katjahahn.tools;

import static com.github.katjahahn.sections.SectionTableEntryKey.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.PELoader;
import com.github.katjahahn.sections.SectionTable;
import com.github.katjahahn.sections.SectionTableEntry;

/**
 * Recognizes and dumps overlay in a PE file.
 * 
 * @author Katja Hahn
 * 
 */
public class Overlay {

	private final File file;
	private final File outFile;
	private Long eof;

	/**
	 * @constructor Creates an Overlay instance with the input file and output
	 *              file specified
	 * @param file
	 *            the file to be scanned for overlay
	 * @param outFile
	 *            the file to dump the overlay to
	 */
	public Overlay(File file, File outFile) {
		this.file = file;
		this.outFile = outFile;
	}

	/**
	 * Calculates the end of the PE file based on the section table (last
	 * section plus its size)
	 * 
	 * @return the end of the PE file
	 * @throws IOException
	 */
	public long getEndOfPE() throws IOException {
		if (eof == null) {
			com.github.katjahahn.PEData data = PELoader.loadPE(file);
			SectionTable table = data.getSectionTable();
			eof = 0L;
			for (SectionTableEntry section : table.getSectionEntries()) {
				long endPoint = section.get(POINTER_TO_RAW_DATA)
						+ section.get(SIZE_OF_RAW_DATA);
				if (eof < endPoint) {
					eof = endPoint;
				}
			}
		}
		return eof;
	}

	/**
	 * Determines if the PE file has an overlay.
	 * 
	 * @return true iff the file has an overlay
	 * @throws IOException
	 */
	public boolean hasOverlay() throws IOException {
		return file.length() > getEndOfPE();
	}

	/**
	 * Writes a dump of the overlay to the specified output location.
	 * 
	 * @return true iff successfully dumped
	 * @throws IOException
	 */
	public boolean dump() throws IOException {
		if (hasOverlay()) {
			dump(getEndOfPE());
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Dumps the last part of the file beginning at the specified offset.
	 * 
	 * @param offset
	 * @throws IOException
	 */
	private void dump(long offset) throws IOException {
		try (RandomAccessFile raf = new RandomAccessFile(file, "r");
				FileOutputStream out = new FileOutputStream(outFile)) {
			raf.seek(offset);
			byte[] buffer = new byte[2048];
			int bytesRead;
			while ((bytesRead = raf.read(buffer)) != -1) {
				out.write(buffer, 0, bytesRead);
			}
		}
	}

}