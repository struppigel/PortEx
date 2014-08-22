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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.sections.SectionHeader;
import com.github.katjahahn.parser.sections.SectionHeaderKey;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.parser.sections.SectionTable;

/**
 * Recognizes and dumps overlay in a PE file.
 * 
 * @author Katja Hahn
 * 
 */
public class Overlay {

    private final File file;
    private Long offset;
    private PEData data;

    public static void main(String[] args) throws IOException {
        File file = new File(
                "/home/deque/portextestfiles/badfiles/VirusShare_d4a3a413257e49d81962e3d7ec0944eb");
        PEData data = PELoader.loadPE(file);
        System.out.println(data);
        Overlay overlay = new Overlay(file);
        long offset = overlay.getOffset();
        System.out.println("offset: " + offset);
        System.out.println("file length: " + file.length());
        SectionLoader loader = new SectionLoader(data);
        SectionTable table = data.getSectionTable();
        for (SectionHeader header : table.getSectionHeaders()) {
            long start = header.getAlignedPointerToRaw();
            long end = loader.getReadSize(header) + start;
            System.out.println(header.getNumber() + ". " + header.getName()
                    + " start: " + start + " end: " + end);
            long vStart = header.get(SectionHeaderKey.VIRTUAL_ADDRESS);
            long vEnd = header.getAlignedVirtualSize() + vStart;
            System.out.println("virtual start: " + vStart + " virtual end: "
                    + vEnd);
        }
    }

    /**
     * Creates an Overlay instance with the input file specified
     * 
     * @param file
     *            the file to be scanned for overlay
     */
    public Overlay(File file) {
        this.file = file;
    }

    /**
     * Creates an Overlay instance with the PE data specified
     * 
     * @param data
     *            the PE header data of the file
     */
    public Overlay(PEData data) {
        this.data = data;
        this.file = data.getFile();
    }

    public void read() throws IOException {
        if (data == null) {
            data = PELoader.loadPE(file);
        }
    }

    /**
     * Returns the file offset of the overlay.
     * 
     * @return file offset of the overlay
     * @throws IOException
     */
    public long getOffset() throws IOException {
        if (offset == null) {
            read();
            SectionTable table = data.getSectionTable();
            SectionLoader loader = new SectionLoader(data);
            offset = 0L;
            List<SectionHeader> headers = table.getSectionHeaders();
            // TODO low alingment check instead?
            if (headers.size() == 0) { // offset for sectionless PE's
                offset = file.length();
            }
            for (SectionHeader section : headers) {
                long alignedPointerToRaw = section.getAlignedPointerToRaw();
                // ignore invalid sections
                if (alignedPointerToRaw >= file.length()) {
                    continue;
                }
                long readSize = loader.getReadSize(section);
                long endPoint = readSize + alignedPointerToRaw;
                if (offset < endPoint) { // determine largest endPoint
                    offset = endPoint;
                }
            }
        }
        if (offset > file.length() || offset == 0) {
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
    public boolean exists() throws IOException {
        return file.length() > getOffset();
    }

    /**
     * Calculates the size of the overlay in bytes.
     * 
     * @return size of overlay in bytes
     * @throws IOException
     *             if unable to read the input file
     */
    public long getSize() throws IOException {
        return file.length() - getOffset();
    }

    /**
     * Writes a dump of the overlay to the specified output location.
     * 
     * @param outFile
     *            the file to write the dump to
     * @return true iff successfully dumped
     * @throws IOException
     *             if unable to read the input file or write the output file
     */
    public boolean dumpTo(File outFile) throws IOException {
        if (exists()) {
            dump(getOffset(), outFile);
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

    /**
     * Loads all bytes of the overlay into an array and returns them.
     * 
     * @return array containing the overlay bytes
     * @throws IOException
     */
    public byte[] getDump() throws IOException {
        byte[] dump = new byte[(int) getSize()];
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(offset);
            raf.readFully(dump);
        }
        return dump;
    }

}
