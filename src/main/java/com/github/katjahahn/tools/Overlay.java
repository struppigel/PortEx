/*******************************************************************************
 * Copyright 2014 Katja Hahn
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package com.github.katjahahn.tools;

import static com.github.katjahahn.sections.SectionTableEntryKey.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.PEData;
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
	private Long offset;

	/**
	 * @constructor Creates an Overlay instance with the input file and output
	 *              file specified
	 * @param file
	 *            the file to be scanned for overlay
	 */
	public Overlay(File file) {
		this.file = file;
	}

	/**
	 * Calculates the end of the PE file based on the section table (last
	 * section plus its size)
	 * 
	 * @return the end of the PE file
	 * @throws IOException
	 */
	public long getOverlayOffset() throws IOException {
		if (offset == null) {
			PEData data = PELoader.loadPE(file);
			SectionTable table = data.getSectionTable();
			offset = 0L;
			for (SectionTableEntry section : table.getSectionEntries()) {
				long pointerToRaw = section.get(POINTER_TO_RAW_DATA);
			    long sizeOfRaw = section.get(SIZE_OF_RAW_DATA);
			    long virtSize = section.get(VIRTUAL_SIZE);
			    //see https://code.google.com/p/corkami/wiki/PE#section_table: "if bigger than virtual size, then virtual size is taken. "
			    //and: "a section can have a null VirtualSize: in this case, only the SizeOfRawData is taken into consideration. "
			    if(virtSize != 0 && sizeOfRaw > virtSize) { 
			    	sizeOfRaw = virtSize;
			    }
			    long endPoint = pointerToRaw + sizeOfRaw;
				if (offset < endPoint) {
					offset = endPoint;
				}
			}
		}
		if(offset > file.length()) {
			offset = file.length();
		}
		return offset;
	}

	/**
	 * Determines if the PE file has an overlay.
	 * 
	 * @return true iff the file has an overlay
	 * @throws IOException
	 */
	public boolean hasOverlay() throws IOException {
		return file.length() > getOverlayOffset();
	}
	
	/**
	 * Calculates the size of the overlay in bytes.
	 * 
	 * @return size of overlay in bytes
	 * @throws IOException if unable to read the input file
	 */
	public long getOverlaySize() throws IOException {
		return file.length() - getOverlayOffset();
	}

	/**
	 * Writes a dump of the overlay to the specified output location.
	 * 
	 * @param outFile the file to write the dump to
	 * @return true iff successfully dumped
	 * @throws IOException if unable to read the input file or write the output file
	 */
	public boolean dumpTo(File outFile) throws IOException {
		if (hasOverlay()) {
			dump(getOverlayOffset(), outFile);
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
	private void dump(long offset, File outFile) throws IOException {
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
