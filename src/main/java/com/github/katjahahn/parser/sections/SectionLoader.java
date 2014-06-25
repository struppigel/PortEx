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
package com.github.katjahahn.parser.sections;

import static com.github.katjahahn.parser.sections.SectionHeaderKey.*;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.FileFormatException;
import com.github.katjahahn.parser.MemoryMappedPE;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.optheader.DataDirEntry;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.github.katjahahn.parser.optheader.OptionalHeader;
import com.github.katjahahn.parser.sections.debug.DebugSection;
import com.github.katjahahn.parser.sections.edata.ExportSection;
import com.github.katjahahn.parser.sections.idata.ImportSection;
import com.github.katjahahn.parser.sections.pdata.ExceptionSection;
import com.github.katjahahn.parser.sections.rsrc.ResourceSection;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.java.contract.Ensures;
import com.google.java.contract.Invariant;
import com.google.java.contract.Requires;

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
    private final COFFFileHeader coffHeader;

    /**
     * Creates a SectionLoader instance with a file and the corresponding
     * section table and optional Header of that file.
     * 
     * @param table
     * @param optHeader
     * @param file
     */
    public SectionLoader(SectionTable table, OptionalHeader optHeader,
            COFFFileHeader coffHeader, File file) {
        this.table = table;
        this.file = file;
        this.optHeader = optHeader;
        this.coffHeader = coffHeader;
    }

    /**
     * Creates a SectionLoader instance taking all information from the given
     * {@link PEData} object.
     * 
     * @param data
     */
    public SectionLoader(PEData data) {
        this.table = data.getSectionTable();
        this.optHeader = data.getOptionalHeader();
        this.file = data.getFile();
        this.coffHeader = data.getCOFFFileHeader();
    }

    /**
     * Loads the first section with the given name. If the file doesn't have a
     * section by this name, it returns absent.
     * <p>
     * This does not instantiate special sections. Use methods like
     * {@link #loadImportSection()} or {@link #loadResourceSection()} instead.
     * <p>
     * The file on disk is read to fetch the information
     * 
     * @param name
     *            the section's name
     * @return {@link PESection} of the given name, absent if section isn't
     *         contained in file
     * @throws IOException
     *             if unable to read the file
     */
    @Ensures("result != null")
    public Optional<PESection> maybeLoadSection(String name) throws IOException {
        Optional<SectionHeader> section = table.getSectionHeaderByName(name);
        if (section.isPresent()) {
            int sectionNr = section.get().getNumber();
            return Optional.fromNullable(loadSection(sectionNr));
        }
        return Optional.absent();
    }

    /**
     * Loads the section with the sectionNr.
     * <p>
     * This does not instantiate special sections. Use methods like
     * {@link #loadImportSection()} or {@link #loadResourceSection()} instead.
     * 
     * @param sectionNr
     *            the section's number
     * @return {@link PESection} of the given number
     * @throws IllegalArgumentException
     *             if invalid sectionNr
     */
    @Ensures("result != null")
    public PESection loadSection(int sectionNr) {
        Preconditions.checkArgument(
                sectionNr > 0 && sectionNr <= table.getNumberOfSections(),
                "invalid section number");
        SectionHeader header = table.getSectionHeader(sectionNr);
        return loadSectionFrom(header);
    }

    /**
     * Loads the section that belongs to the header.
     * <p>
     * This does not instantiate special sections. Use methods like
     * {@link #loadImportSection()} or {@link #loadResourceSection()} instead.
     * 
     * @param header
     *            the section's header
     * @return {@link PESection} that belongs to the header
     */
    @Ensures("result != null")
    public PESection loadSectionFrom(SectionHeader header) {
        long size = getReadSize(header);
        long offset = header.getAlignedPointerToRaw();
        return new PESection(size, offset, header, file);
    }

    /**
     * Returns the bytes of the section with the specified number.
     * 
     * @param sectionNr
     *            the number of the section
     * @return bytes that represent the section with the given section number
     * @throws IOException
     * @throws IllegalStateException
     *             if section too large to fit into a byte array
     */
    @Ensures("result != null")
    public BytesAndOffset loadSectionBytes(int sectionNr) throws IOException {
        SectionHeader header = table.getSectionHeader(sectionNr);
        return loadSectionBytesFor(header);
    }

    /**
     * Loads the bytes of the section and returns bytes and file offset.
     * 
     * @param header
     *            of the section
     * @return bytes and file offset of the section
     * @throws IOException
     *             if file can not be read
     * @throws IllegalStateException
     *             if section too large to fit into a byte array
     */
    @Requires("header != null")
    @Ensures("result != null")
    public BytesAndOffset loadSectionBytesFor(SectionHeader header)
            throws IOException {
        Preconditions.checkArgument(header != null, "given section was null");
        logger.debug("reading section bytes for header " + header.getName());
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            long alignedPointerToRaw = header.getAlignedPointerToRaw();
            long readSize = getReadSize(header);
            Preconditions.checkState(readSize == (int) readSize,
                    "read size too large to load section into byte array");
            raf.seek(alignedPointerToRaw);
            logger.debug("reading section bytes from " + alignedPointerToRaw
                    + " to " + readSize);
            byte[] sectionbytes = new byte[(int) readSize];
            raf.readFully(sectionbytes);
            return new BytesAndOffset(sectionbytes, alignedPointerToRaw);
        }
    }

    /**
     * Rounds up the value to the file alignment of the optional header.
     * 
     * @param value
     * @return file aligned value
     */
    @Ensures({ "optHeader.isLowAlignmentMode() || result % 512 == 0",
            "result >= value" })
    private long fileAligned(long value) {
        long fileAlign = optHeader.getAdjustedFileAlignment();
        long rest = value % fileAlign;
        long result = value;
        if (rest != 0) {
            result = value - rest + fileAlign;
        }
        if (!(optHeader.isLowAlignmentMode() || result % 512 == 0)) {
            logger.error("file aligning went wrong");
            logger.error("value: " + value);
            logger.error("filealign: " + fileAlign);
            logger.error("result: " + result);
        }
        return result;
    }

    /**
     * Determines the the number of bytes that is read for the section.
     * 
     * @param header
     *            header of the section
     * @return section size
     */
    @Ensures("result >= 0")
    public long getReadSize(SectionHeader header) {
        Preconditions.checkArgument(header != null);
        long pointerToRaw = header.get(POINTER_TO_RAW_DATA);
        long virtSize = header.get(VIRTUAL_SIZE);
        long sizeOfRaw = header.get(SIZE_OF_RAW_DATA);
        long alignedPointerToRaw = header.getAlignedPointerToRaw();
        // see Peter Ferrie's answer in:
        // https://reverseengineering.stackexchange.com/questions/4324/reliable-algorithm-to-extract-overlay-of-a-pe
        long readSize = fileAligned(pointerToRaw + sizeOfRaw)
                - alignedPointerToRaw;
        readSize = Math.min(readSize, header.getAlignedSizeOfRaw());
        // see https://code.google.com/p/corkami/wiki/PE#section_table:
        // "if bigger than virtual size, then virtual size is taken. "
        // and:
        // "a section can have a null VirtualSize: in this case, only the SizeOfRawData is taken into consideration. "
        if (virtSize != 0) {
            readSize = Math.min(readSize, header.getAlignedVirtualSize());
        }
        if (readSize + alignedPointerToRaw > file.length()) {
            readSize = file.length() - alignedPointerToRaw;
        }
        if (readSize < 0) {
            // TODO VirusShare_6fdfdffeb4b1be2d0036bac49cb0d590 negative
            // readsize -> add in anomalies
            logger.warn("invalid readsize: " + readSize + " for file "
                    + file.getName() + " adjusting readsize to 0");
            readSize = 0;
        }
        return readSize;
    }

    /**
     * Loads all bytes and information of the debug section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link DebugSection} of the given file
     * @throws IOException
     *             if unable to read the file
     * @throws IllegalStateException
     *             if unable to load debug section
     */
    @Ensures("result != null")
    public DebugSection loadDebugSection() throws IOException {
        Optional<DebugSection> debug = maybeLoadDebugSection();
        if (debug.isPresent()) {
            return debug.get();
        }
        throw new IllegalStateException("unable to load debug section");
    }

    /**
     * Loads all bytes and information of the debug section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link DebugSection} of the given file, absent if file doesn't
     *         have this section
     * @throws {@link IOException} if unable to read the file
     */
    @Ensures("result != null")
    public Optional<DebugSection> maybeLoadDebugSection() throws IOException {
        Optional<BytesAndOffset> res = maybeReadDataDirBytes(DataDirectoryKey.DEBUG);
        if (res.isPresent()) {
            if (res.get().bytes.length == 0) {
                logger.warn("unable to read debug section, readsize is 0");
                return Optional.absent();
            }
            return Optional.of(DebugSection.apply(res.get().bytes,
                    res.get().offset));
        }
        return Optional.absent();
    }

    /**
     * Loads all bytes and information of the resource section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link ResourceSection} of the given file
     * @throws {@link IOException} if unable to read the file
     * @throws @{@link IllegalStateException} if section can not be loaded
     */
    @Ensures("result != null")
    public ResourceSection loadResourceSection() throws IOException,
            FileFormatException {
        Optional<ResourceSection> rsrc = maybeLoadResourceSection();
        if (rsrc.isPresent()) {
            return rsrc.get();
        }
        throw new IllegalStateException("unable to load resource section");
    }

    /**
     * Loads all bytes and information of the resource section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link ResourceSection} of the given file, absent if file doesn't
     *         have this section
     * @throws IOException
     *             if unable to read the file
     */
    @Ensures("result != null")
    public Optional<ResourceSection> maybeLoadResourceSection()
            throws IOException, FileFormatException {
        Optional<DataDirEntry> resourceTable = optHeader
                .maybeGetDataDirEntry(DataDirectoryKey.RESOURCE_TABLE);
        if (resourceTable.isPresent()) {
            Optional<SectionHeader> rsrcEntry = resourceTable.get()
                    .maybeGetSectionTableEntry(table);
            if (rsrcEntry.isPresent()) {
                Long virtualAddress = rsrcEntry.get().get(VIRTUAL_ADDRESS);
                if (virtualAddress != null) {
                    BytesAndOffset tuple = loadSectionBytesFor(rsrcEntry.get());
                    byte[] rsrcbytes = tuple.bytes;
                    if (rsrcbytes.length == 0) {
                        logger.warn("unable to read resource section, readsize is 0");
                        return Optional.absent();
                    }
                    long rsrcOffset = rsrcEntry.get().getAlignedPointerToRaw();
                    ResourceSection rsrc = ResourceSection.newInstance(file,
                            rsrcbytes, virtualAddress, rsrcOffset);
                    return Optional.of(rsrc);
                }
            }
        }
        return Optional.absent();
    }

    /**
     * Loads all bytes and information of the exception section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link ExceptionSection} of the given file
     * @throws {@link IOException} if unable to read the file
     * @throws @{@link IllegalStateException} if section can not be loaded
     */
    @Ensures("result != null")
    public ExceptionSection loadExceptionSection() throws IOException {
        Optional<ExceptionSection> pdata = maybeLoadExceptionSection();
        if (pdata.isPresent()) {
            return pdata.get();
        }
        throw new IllegalStateException("unable to load resource section");
    }

    /**
     * Loads all bytes and information of the resource section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link ResourceSection} of the given file, absent if file doesn't
     *         have this section
     * @throws IOException
     *             if unable to read the file
     */
    @Ensures("result != null")
    public Optional<ExceptionSection> maybeLoadExceptionSection()
            throws IOException {
        Optional<DataDirEntry> exceptionTable = optHeader
                .maybeGetDataDirEntry(DataDirectoryKey.EXCEPTION_TABLE);
        if (exceptionTable.isPresent()) {
            Optional<SectionHeader> header = exceptionTable.get()
                    .maybeGetSectionTableEntry(table);
            if (header.isPresent()) {
                Long virtualAddress = header.get().get(VIRTUAL_ADDRESS);
                if (virtualAddress != null) {
                    BytesAndOffset tuple = loadSectionBytesFor(header.get());
                    //TODO remove loadPE call, save data instance here instead
                    MemoryMappedPE bytes = MemoryMappedPE.newInstance(PELoader.loadPE(file), this);
                    if (bytes.length() == 0) {
                        logger.warn("unable to read exception section, readsize is 0");
                        return Optional.absent();
                    }
                    long offset = header.get().getAlignedPointerToRaw();
//                    MachineType machine = coffHeader.getMachineType();
//                    ExceptionSection section = ExceptionSection.newInstance(
//                            bytes, machine, virtualAddress, offset);
//                    return Optional.of(section); TODO
                }
            }
        }
        return Optional.absent();
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
    @Ensures("result != null")
    public Optional<SectionHeader> maybeGetSectionHeaderByRVA(long rva) {
        List<SectionHeader> sections = table.getSectionHeaders();
        for (SectionHeader section : sections) {
            long vSize = section.get(VIRTUAL_SIZE);
            long vAddress = section.get(VIRTUAL_ADDRESS);
            if (rvaIsWithin(vAddress, vSize, rva)) {
                return Optional.of(section);
            }
        }
        return Optional.absent();
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
     * @throws {@link IOException} if unable to read the file
     * @throws {@link IllegalStateException} if unable to load section
     */
    @Ensures("result != null")
    public ImportSection loadImportSection() throws IOException {
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
     * @throws {@link IOException} if unable to read the file
     */
    @Ensures("result != null")
    public Optional<ImportSection> maybeLoadImportSection() throws IOException {
        DataDirectoryKey dataDirKey = DataDirectoryKey.IMPORT_TABLE;
        Optional<DataDirEntry> importTable = optHeader
                .maybeGetDataDirEntry(dataDirKey);
        if (importTable.isPresent()) {
            long virtualAddress = importTable.get().virtualAddress;
            PEData data = PELoader.loadPE(file); // TODO remove this, store data
            MemoryMappedPE memoryMapped = MemoryMappedPE
                    .newInstance(data, this);
            if (memoryMapped.length() == 0) {
                logger.warn("unable to read import section, readsize is 0");
                return Optional.absent();
            }
            // TODO read offset only
            Optional<BytesAndOffset> optTup = maybeReadSectionBytesFor(dataDirKey);
            if (optTup.isPresent()) {
                long offset = optTup.get().offset;
                logger.debug("idatalength: " + memoryMapped.length());
                logger.debug("virtual address of ILT: " + virtualAddress);
                ImportSection idata = ImportSection.newInstance(memoryMapped,
                        virtualAddress, optHeader, file.length(), offset);
                if (idata.isEmpty()) {
                    logger.warn("empty import section");
                    return Optional.absent();
                }
                return Optional.of(idata);
            }
        }
        return Optional.absent();
    }

    /**
     * Fetches the {@link SectionHeader} of the section the data directory entry
     * for the given key points into.
     * 
     * @param dataDirKey
     *            the data directory key
     * @return the section table entry the data directory entry of that key
     *         points into or absent if there is no data dir entry for the key
     *         available
     */
    private Optional<SectionHeader> maybeGetSectionHeader(
            DataDirectoryKey dataDirKey) {
        Optional<DataDirEntry> dataDir = optHeader
                .maybeGetDataDirEntry(dataDirKey);
        if (dataDir.isPresent()) {
            return dataDir.get().maybeGetSectionTableEntry(table);
        }
        logger.warn("data dir entry " + dataDirKey + " doesn't exist");
        return Optional.absent();
    }

    /**
     * Returns the file offset of the data directory entry the given key belongs
     * to.
     * 
     * @param dataDirKey
     *            the key of the data directory entry
     * @return file offset of the rva that is in the data directory entry with
     *         the given key, absent if file offset can not be determined
     */
    @Ensures("result != null")
    public Optional<Long> maybeGetFileOffsetFor(DataDirectoryKey dataDirKey) {
        Optional<DataDirEntry> dataDir = optHeader
                .maybeGetDataDirEntry(dataDirKey);
        if (dataDir.isPresent()) {
            long rva = dataDir.get().virtualAddress;
            return maybeGetFileOffset(rva);
        }
        return Optional.absent();
    }

    /**
     * Returns the file offset for the RVA.
     * 
     * @param rva
     *            the relative virtual address that shall be converted
     * @return file offset optional, absent if it can not be determined.
     */
    @Ensures("result != null")
    public Optional<Long> maybeGetFileOffset(long rva) {
        Optional<SectionHeader> section = maybeGetSectionHeaderByRVA(rva);
        if (section.isPresent()) {
            long virtualAddress = section.get().get(VIRTUAL_ADDRESS);
            long pointerToRawData = section.get().get(POINTER_TO_RAW_DATA);
            return Optional.of(rva - (virtualAddress - pointerToRawData));
        } else if (rva <= file.length()) {
            // data is not located within a section
            return Optional.of(rva);
        }
        return Optional.absent();
    }

    /**
     * Returns all bytes and the file offset of the section where the given data
     * dir entry is in.
     * 
     * @param dataDirKey
     * @return bytes and offset of the section
     * @throws IOException
     */
    public Optional<BytesAndOffset> maybeReadSectionBytesFor(
            DataDirectoryKey dataDirKey) throws IOException {
        Optional<SectionHeader> header = maybeGetSectionHeader(dataDirKey);
        if (header.isPresent()) {
            try {
                return Optional.fromNullable(loadSectionBytesFor(header.get()));
            } catch (IllegalArgumentException e) {
                logger.warn(e.getMessage());
            }
        } else {
            logger.warn("unable to load header for datadirkey " + dataDirKey);
        }
        return Optional.absent();
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
     * @return the export section, absent if file doesn't have an export section
     * @throws IOException
     *             if unable to read the file
     */
    @Ensures("result != null")
    public Optional<ExportSection> maybeLoadExportSection() throws IOException {
        Optional<DataDirEntry> exportTable = optHeader
                .maybeGetDataDirEntry(DataDirectoryKey.EXPORT_TABLE);
        if (exportTable.isPresent()) {
            long virtualAddress = exportTable.get().virtualAddress;
            Optional<BytesAndOffset> res = maybeReadDataDirBytes(DataDirectoryKey.EXPORT_TABLE);
            if (!res.isPresent()) {
                return Optional.absent();
            }
            //TODO don't load data, save it
            MemoryMappedPE mmbytes = MemoryMappedPE.newInstance(PELoader.loadPE(file), this);
            if (mmbytes.length() == 0) {
                logger.warn("unable to read export section, readsize is 0");
                return Optional.absent();
            }
            //TODO correct offset, directory doesn't always start at section start
            long offset = res.get().offset; 
            ExportSection edata = ExportSection.newInstance(mmbytes,
                    virtualAddress, optHeader, this, offset);
            if (edata.isEmpty()) {
                logger.warn("empty export section");
            }
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
    @Ensures("result != null")
    private Optional<BytesAndOffset> maybeReadDataDirBytes(
            DataDirectoryKey dataDirKey) throws IOException,
            FileFormatException {
        Optional<DataDirEntry> dataDir = optHeader
                .maybeGetDataDirEntry(dataDirKey);
        Optional<SectionHeader> header = maybeGetSectionHeader(dataDirKey);
        if (header.isPresent() && dataDir.isPresent()) {
            long pointerToRawData = header.get().getAlignedPointerToRaw();
            Long virtualAddress = header.get().get(VIRTUAL_ADDRESS);
            if (virtualAddress != null) {
                long rva = dataDir.get().virtualAddress;
                long offset = rva - (virtualAddress - pointerToRawData);
                long size = (getReadSize(header.get()) + pointerToRawData)
                        - rva;
                if (size < dataDir.get().size) {
                    size = dataDir.get().size;
                }
                if (size + offset > file.length()) {
                    size = file.length() - offset;
                }
                Preconditions
                        .checkState(size == (int) size,
                                "readsize of section too large to load into a byte array");
                try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
                    raf.seek(offset);
                    virtualAddress = rva;
                    byte[] bytes = new byte[(int) size];
                    raf.readFully(bytes);
                    return Optional.of(new BytesAndOffset(bytes, offset));
                }
            } else {
                logger.warn("virtual address is null for data dir: "
                        + dataDirKey);
            }
        } else {
            logger.warn("invalid dataDirKey");
        }
        return Optional.absent();
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

    public boolean pointsToValidSection(DataDirectoryKey dataDirKey) {
        Optional<SectionHeader> header = maybeGetSectionHeader(dataDirKey);
        if(header.isPresent()) {
            return isValidSection(header.get());
        }
        return false;
    }
    
    public boolean isValidSection(SectionHeader header) {
        return getReadSize(header) > 0 && header.getAlignedPointerToRaw() < file.length();
    }

}
