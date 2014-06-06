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

import static com.github.katjahahn.sections.SectionHeaderKey.*;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.FileFormatException;
import com.github.katjahahn.PEData;
import com.github.katjahahn.optheader.DataDirEntry;
import com.github.katjahahn.optheader.DataDirectoryKey;
import com.github.katjahahn.optheader.OptionalHeader;
import com.github.katjahahn.optheader.WindowsEntryKey;
import com.github.katjahahn.sections.debug.DebugSection;
import com.github.katjahahn.sections.edata.ExportSection;
import com.github.katjahahn.sections.idata.ImportSection;
import com.github.katjahahn.sections.rsrc.ResourceSection;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.java.contract.Ensures;
import com.google.java.contract.Invariant;

/**
 * Responsible for computing section related values and loading sections with
 * the given section header information.
 * <p>
 * The section loader is able to load special sections like the
 * {@link ImportSection}, {@link ExportSection} and {@link ResourceSection}
 * 
 * @author Katja Hahn
 * 
 */
public class SectionLoader {

    private static final Logger logger = LogManager
            .getLogger(SectionLoader.class.getName());

    private final SectionTable table;
    private final File file;
    private final OptionalHeader optHeader;

    /**
     * @constructor Creates a SectionLoader instance with a file and the
     *              corresponding section table and optional Header of that
     *              file.
     * 
     * @param table
     * @param optHeader
     * @param file
     */
    public SectionLoader(SectionTable table, OptionalHeader optHeader, File file) {
        this.table = table;
        this.file = file;
        this.optHeader = optHeader;
    }

    /**
     * @constructor Creates a SectionLoader instance taking all information from
     *              the given {@link PEData} object
     * @param data
     */
    public SectionLoader(PEData data) {
        this.table = data.getSectionTable();
        this.optHeader = data.getOptionalHeader();
        this.file = data.getFile();
    }

    /**
     * Loads the first section with the given name. If the file doesn't have a
     * section by this name, it returns absent.
     * 
     * This does not instantiate subclasses of {@link PESection}. Use methods
     * like {@link #loadImportSection()} or {@link #loadResourceSection()}
     * instead.
     * 
     * The file on disk is read to fetch the information
     * 
     * @param name
     *            the section's name
     * @return PESection of the given name, absent if section isn't contained in
     *         file
     * @throws IOException
     *             if unable to read the file
     */
    public Optional<PESection> loadSection(String name) throws IOException {
        Optional<SectionHeader> section = table.getSectionHeaderByName(name);
        if (section.isPresent()) {
            int sectionNr = section.get().getNumber();
            return Optional.fromNullable(loadSection(sectionNr));
        }
        return Optional.absent();
    }

    /**
     * Loads the section with the given number and may patch the size of the
     * section if the {@code patchSize} parameter is set. If the file doesn't
     * have a section by this number, it returns null.
     * 
     * This does not instantiate subclasses of {@link PESection}. Use methods
     * like {@link #loadImportSection()} or {@link #loadResourceSection()}
     * instead.
     * 
     * The file on disk is read to fetch the information
     * 
     * @param sectionNr
     *            the section's name
     * @return PESection of the given number, null if there is no section with
     *         that number
     * @throws IOException
     *             if unable to read the file
     */
    public PESection loadSection(int sectionNr) throws IOException {
        BytesAndOffset tuple = loadSectionBytes(sectionNr);
        byte[] bytes = tuple.bytes;
        return new PESection(bytes);
    }

    /**
     * Returns the bytes of the section with the specified number.
     * 
     * @param sectionNr
     *            the number of the section
     * @return bytes that represent the section with the given section number
     * @throws IOException
     */
    @Ensures("result != null")
    public BytesAndOffset loadSectionBytes(int sectionNr) throws IOException {
        SectionHeader section = table.getSectionHeader(sectionNr);
        return loadSectionBytes(section);
    }

    /**
     * Loads the bytes of the section.
     * 
     * @param section
     * @return
     * @throws IOException
     */
    @Ensures("result != null")
    public BytesAndOffset loadSectionBytes(SectionHeader section)
            throws IOException {
        Preconditions.checkArgument(section != null, "given section was null");
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            long alignedPointerToRaw = section.getAlignedPointerToRaw();
            long readSize = getReadSize(section);
            raf.seek(alignedPointerToRaw);
            logger.debug("reading section bytes from " + alignedPointerToRaw
                    + " to " + readSize);
            byte[] sectionbytes = new byte[(int) readSize];
            raf.readFully(sectionbytes);
            return new BytesAndOffset(sectionbytes, alignedPointerToRaw);
        }
    }

    @Ensures("result % 512 == 0")
    private long fileAligned(long value) {
        long fileAlign = optHeader.get(WindowsEntryKey.FILE_ALIGNMENT);
        // Note: (two's complement of x AND value) rounds down value to a
        // multiple of x if x is a power of 2
        if (value % fileAlign != 0) {
            value = ((value) + fileAlign - 1) & ~(fileAlign - 1);
        }
        return value;
    }

    /**
     * Determines the the number of bytes that is read for the section.
     * 
     * @param section
     *            header of the section
     * @return section size
     */
    @Ensures("result >= 0")
    public long getReadSize(SectionHeader section) {
        long pointerToRaw = section.get(POINTER_TO_RAW_DATA);
        long virtSize = section.get(VIRTUAL_SIZE);
        long sizeOfRaw = section.get(SIZE_OF_RAW_DATA);
        long alignedPointerToRaw = section.getAlignedPointerToRaw();
        // see Peter Ferrie's answer in:
        // https://reverseengineering.stackexchange.com/questions/4324/reliable-algorithm-to-extract-overlay-of-a-pe
        long readSize = fileAligned(pointerToRaw + sizeOfRaw)
                - alignedPointerToRaw;
        readSize = Math.min(readSize, section.getAlignedSizeOfRaw());
        // see https://code.google.com/p/corkami/wiki/PE#section_table:
        // "if bigger than virtual size, then virtual size is taken. "
        // and:
        // "a section can have a null VirtualSize: in this case, only the SizeOfRawData is taken into consideration. "
        if (virtSize != 0) {
            readSize = Math.min(readSize, section.getAlignedVirtualSize());
        }
        if (readSize + alignedPointerToRaw > file.length()) {
            readSize = file.length() - alignedPointerToRaw;
        }
        return readSize;
    }

    /**
     * Loads all bytes and information of the debug section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link DebugSection} of the given file, null if file doesn't have
     *         this section
     * @throws IOException
     *             if unable to read the file
     */
    public DebugSection loadDebugSection() throws IOException {
        BytesAndOffset res = readDataDirBytesFor(DataDirectoryKey.DEBUG);
        if (res != null) {
            return DebugSection.apply(res.bytes, res.offset);
        }
        return null;
    }

    /**
     * Loads all bytes and information of the resource section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link ResourceSection} of the given file, null if file doesn't
     *         have this section
     * @throws IOException
     *             if unable to read the file
     */
    public ResourceSection loadResourceSection() throws IOException,
            FileFormatException {
        DataDirEntry resourceTable = optHeader.getDataDirEntries().get(
                DataDirectoryKey.RESOURCE_TABLE);
        if (resourceTable != null) {
            SectionHeader rsrcEntry = resourceTable.getSectionTableEntry(table);
            if (rsrcEntry != null) {
                Long virtualAddress = rsrcEntry.get(VIRTUAL_ADDRESS);
                if (virtualAddress != null) {
                    BytesAndOffset tuple = loadSectionBytes(rsrcEntry);
                    if (tuple == null) {
                        return null;
                    }
                    byte[] rsrcbytes = tuple.bytes;
                    long rsrcOffset = rsrcEntry.getAlignedPointerToRaw();
                    ResourceSection rsrc = ResourceSection.newInstance(file,
                            rsrcbytes, virtualAddress, rsrcOffset);
                    return rsrc;
                }
            }
        }
        return null;
    }

    /**
     * Returns the section entry of the section table the rva is pointing into.
     * 
     * @param table
     *            the section table of the file
     * @param rva
     *            the relative virtual address
     * @return the {@link SectionHeader} of the section the rva is pointing into
     */
    public SectionHeader getSectionHeaderByRVA(long rva) {
        List<SectionHeader> sections = table.getSectionHeaders();
        for (SectionHeader section : sections) {
            long vSize = section.get(VIRTUAL_SIZE);
            long vAddress = section.get(VIRTUAL_ADDRESS);
            if (rvaIsWithin(vAddress, vSize, rva)) {
                return section;
            }
        }
        return null;
    }

    private static boolean rvaIsWithin(long address, long size, long rva) {
        long endpoint = address + size;
        return rva >= address && rva < endpoint;
    }

    /**
     * Loads all bytes and information of the import section. The file on disk
     * is read to fetch the information.
     * 
     * @return the import section
     * @throws IOException
     *             if unable to read the file
     * @throws IllegalStateException
     *             if unable to load section
     */
    @Ensures("result != null")
    public ImportSection loadImportSection() throws IOException,
            FileFormatException {
        Optional<ImportSection> idata = maybeLoadImportSection();
        if (idata.isPresent()) {
            return idata.get();
        }
        throw new IllegalStateException("unable to load section");
    }

    /**
     * Loads all bytes and information of the import section. The file on disk
     * is read to fetch the information.
     * 
     * @return the import section, absent if section can not be loaded
     * @throws IOException
     *             if unable to read the file
     */
    @Ensures("result != null")
    public Optional<ImportSection> maybeLoadImportSection() throws IOException,
            FileFormatException {
        DataDirectoryKey dataDirKey = DataDirectoryKey.IMPORT_TABLE;
        DataDirEntry importTable = optHeader.getDataDirEntries()
                .get(dataDirKey);
        if (importTable != null) {
            long virtualAddress = importTable.virtualAddress;
            BytesAndOffset tuple = readSectionBytesFor(dataDirKey);
            if (tuple == null) {
                return Optional.absent();
            }
            byte[] idatabytes = tuple.bytes;
            long offset = tuple.offset;
            int importTableOffset = getOffsetDiffFor(dataDirKey);
            logger.debug("importsection offset diff: " + importTableOffset);
            logger.debug("idatalength: " + idatabytes.length);
            logger.debug("virtual address of ILT: " + virtualAddress);
            ImportSection idata = ImportSection.newInstance(idatabytes,
                    virtualAddress, optHeader, importTableOffset,
                    file.length(), offset);
            return Optional.of(idata);
        }
        return Optional.absent();
    }

    /**
     * Returns the difference between the offset the data directory entry and
     * the begin of the section the entry is in.
     * 
     * E.g. the difference between file offset of the import table and the
     * pointer_to_raw_data of the idata section the table is in.
     * 
     * @param dataDirKey
     * @return the difference of the calculated data dir entry file offset to
     *         the pointer_to_raw_data the data dir entry is in
     * @throws FileFormatException
     *             if offset can not be determined
     */
    private Integer getOffsetDiffFor(DataDirectoryKey dataDirKey)
            throws FileFormatException {
        SectionHeader header = getSectionHeaderFor(dataDirKey);
        if (header != null) {
            long pointerToRawData = header.getAlignedPointerToRaw();
            Long offset = getFileOffsetFor(dataDirKey);
            if (offset != null) {
                return (int) (offset - pointerToRawData);
            }
        }
        throw new FileFormatException("unable to load " + dataDirKey);
    }

    /**
     * Fetches the {@link SectionHeader} of the section the data directory entry
     * for the given key points into.
     * 
     * @param dataDirKey
     *            the data directory key
     * @return the section table entry the data directory entry of that key
     *         points into or null if there is no data dir entry for the key
     *         available
     */
    private SectionHeader getSectionHeaderFor(DataDirectoryKey dataDirKey) {
        Optional<DataDirEntry> dataDir = optHeader.getDataDirEntry(dataDirKey);
        if (dataDir.isPresent()) {
            return dataDir.get().getSectionTableEntry(table);
        }
        return null;
    }

    /**
     * Returns the file offset of the data directory entry the given key belongs
     * to.
     * 
     * @param dataDirKey
     *            the key of the data directory entry
     * @return file offset of the rva that is in the data directory entry with
     *         the given key, null if file offset can not be determined
     */
    public Long getFileOffsetFor(DataDirectoryKey dataDirKey) {
        DataDirEntry dataDir = optHeader.getDataDirEntries().get(dataDirKey);
        if (dataDir != null) {
            long rva = dataDir.virtualAddress;
            return getFileOffsetFor(rva);
        }
        return null;
    }

    public Long getFileOffsetFor(long rva) {
        SectionHeader section = getSectionHeaderByRVA(rva);
        if (section != null) {
            Long virtualAddress = section.get(VIRTUAL_ADDRESS);
            Long pointerToRawData = section.get(POINTER_TO_RAW_DATA);
            if (virtualAddress != null && pointerToRawData != null) {
                return rva - (virtualAddress - pointerToRawData);
            }
        } else if (rva <= file.length()) {
            // data is not located within a section
            return rva;
        }
        return null;
    }

    /**
     * Returns all bytes of the section where the given data dir entry is in.
     * 
     * @param dataDirKey
     * @return
     * @throws IOException
     */
    public BytesAndOffset readSectionBytesFor(DataDirectoryKey dataDirKey)
            throws IOException {
        Optional<DataDirEntry> dataDir = optHeader.getDataDirEntry(dataDirKey);
        if (dataDir.isPresent()) {
            SectionHeader header = getSectionHeaderFor(dataDirKey);
            try {
                return loadSectionBytes(header);
            } catch (IllegalArgumentException e) {
                logger.warn(e);
                return null;
            }
        } else {
            logger.warn("invalid data dir key");
        }
        return null;
    }

    /**
     * Loads all bytes and information of the export section. The file on disk
     * is read to fetch the information.
     * 
     * @return the export section
     * @throws IOException
     *             if unable to read the file
     * @throws IllegalStateException
     *             if unable to load section
     */
    @Ensures("result != null")
    public ExportSection loadExportSection() throws IOException {
        Optional<ExportSection> edata = maybeLoadExportSection();
        if (edata.isPresent()) {
            return edata.get();
        }
        throw new IllegalStateException("unable to read export section");
    }

    /**
     * Loads all bytes and information of the export section. The file on disk
     * is read to fetch the information.
     * 
     * @return the export section, null if file doesn't have an export section
     * @throws IOException
     *             if unable to read the file
     */
    @Ensures("result != null")
    public Optional<ExportSection> maybeLoadExportSection() throws IOException {
        DataDirEntry exportTable = optHeader.getDataDirEntries().get(
                DataDirectoryKey.EXPORT_TABLE);
        if (exportTable != null) {
            long virtualAddress = exportTable.virtualAddress;
            BytesAndOffset res = readDataDirBytesFor(DataDirectoryKey.EXPORT_TABLE);
            if (res == null) {
                return Optional.absent();
            }
            byte[] edatabytes = res.bytes;
            long offset = res.offset;
            ExportSection edata = ExportSection.newInstance(edatabytes,
                    virtualAddress, optHeader, this, offset);
            return Optional.of(edata);
        }
        return Optional.absent();
    }

    /**
     * Reads and returns the bytes that belong to the given data directory entry
     * as well as the offset the bytes where read from.
     * 
     * The data directory entry rva points into section. This section is
     * determined and the file offset for the rva calculated. This file offset
     * is different from the beginning of the determined section, as the section
     * may contain more than the data directory. The returned bytes start at
     * that file offset and end at the end of the section the data directory is
     * in.
     * 
     * @param dataDirKey
     *            the key of the data directory entry you want the bytes for
     * @return byte array that contains the bytes the data directory entry rva
     *         is pointing to
     * @throws IOException
     *             if unable to read the file
     * @throws FileFormatException
     *             if unable to load the file, e.g. not virtual address given
     */
    private BytesAndOffset readDataDirBytesFor(DataDirectoryKey dataDirKey)
            throws IOException, FileFormatException {
        DataDirEntry dataDir = optHeader.getDataDirEntries().get(dataDirKey);
        if (dataDir != null) {
            SectionHeader header = getSectionHeaderFor(dataDirKey);
            long pointerToRawData = header.getAlignedPointerToRaw();
            Long virtualAddress = header.get(VIRTUAL_ADDRESS);
            if (virtualAddress != null) {
                long rva = dataDir.virtualAddress;
                long offset = rva - (virtualAddress - pointerToRawData);
                long size = (getReadSize(header) + pointerToRawData) - rva;
                if (size < dataDir.size) {
                    size = dataDir.size;
                }
                if (size + offset > file.length()) {
                    size = file.length() - offset;
                }
                try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
                    raf.seek(offset);
                    virtualAddress = rva;
                    // TODO cast to int is insecure. actual int is unsigned
                    byte[] bytes = new byte[(int) size];
                    raf.readFully(bytes);
                    return new BytesAndOffset(bytes, offset);
                }
            } else {
                logger.warn("virtual address is null for data dir: "
                        + dataDirKey);
            }
        } else {
            logger.warn("invalid dataDirKey");
        }
        return null;
    }

    /**
     * 
     * Data structure to return or pass a bytes and offset pair.
     * 
     * @author Katja Hahn
     * 
     */
    @Invariant({ "bytes != null", "offset >= 0" })
    public static class BytesAndOffset {
        public final long offset;
        public final byte[] bytes;

        public BytesAndOffset(byte[] bytes, long offset) {
            Preconditions.checkArgument(bytes != null, "bytes are null");
            this.offset = offset;
            this.bytes = bytes;
        }
    }

}
