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
package com.github.katjahahn.sections;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import com.github.katjahahn.IOUtil;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;

/**
 * Holds header, size, offset and optional bytes of a PESection.
 * <p>
 * Section bytes are loaded lazily.
 * 
 * @author Katja Hahn
 *
 */
public class PESection {

    private Optional<byte[]> sectionbytes = Optional.absent();
    private SectionHeader header;
    private long offset;
    private long size;
    private File file;

    protected PESection() {
    }

    /**
     * Creates a PE section.
     * 
     * @param size
     *            number of bytes in the PE section, this is not necessarily the
     *            same as SizeOfRawData in the section headers.
     * @param offset
     *            the file offset to the section
     * @param header
     *            the header of the section from the section table
     * @param file
     *            the PE file
     */
    public PESection(long size, long offset, SectionHeader header, File file) {
        this.header = header;
        this.offset = offset;
        this.size = size;
        this.file = file;
    }

    // TODO PE section without the bytes?
    /**
     * Creates a PE section.
     * 
     * @param sectionbytes
     *            the bytes of the section
     * @param offset
     *            the file offset to the section
     * @param header
     *            the header of the section from the section table
     * @param file
     *            the PE file
     */
    public PESection(byte[] sectionbytes, long offset, SectionHeader header,
            File file) {
        this.sectionbytes = Optional.of(sectionbytes.clone());
        this.header = header;
        this.offset = offset;
        this.size = sectionbytes.length;
        this.file = file;
    }

    /**
     * Returns the number of bytes in the section.
     * <p>
     * this is not necessarily the same as SizeOfRawData in the section headers.
     * 
     * @return the number of bytes in the section
     */
    public long getSize() {
        return size;
    }

    /**
     * Returns the file offset of to the beginning of the section.
     * 
     * @return file offset
     */
    public long getOffset() {
        return offset;
    }

    /**
     * Returns the header of the section
     * 
     * @return section header
     */
    public SectionHeader getHeader() {
        return header;
    }

    /**
     * Dumps the section into a byte array. The file is read if the bytes aren't
     * already loaded.
     * 
     * @return bytes of the section
     * @throws IOException if file can not be read
     * @throws IllegalStateException
     *             if section is too large to fit into a byte array. This
     *             happens if the size is larger than int can hold.
     */
    public byte[] getDump() throws IOException {
        if (sectionbytes.isPresent()) {
            return sectionbytes.get().clone();
        }
        loadSectionBytes();
        return sectionbytes.get();
    }

    /**
     * Loads the section bytes from the file using offset and size.
     * 
     * @throws IOException if file can not be read
     * @throws IllegalStateException
     *             if section is too large to fit into a byte array. This
     *             happens if the size is larger than int can hold.
     */
    private void loadSectionBytes() throws IOException {
        Preconditions.checkState(size == (int) size,
                "section is too large to dump into byte array");
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(offset);
            byte[] bytes = new byte[(int) size];
            raf.read(bytes);
            sectionbytes = Optional.of(bytes);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "PE section offset: " + offset + IOUtil.NL
                + "PE section length: " + size;
    }

}
