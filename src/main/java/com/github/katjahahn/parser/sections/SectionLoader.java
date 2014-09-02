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
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.MemoryMappedPE;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.optheader.DataDirEntry;
import com.github.katjahahn.parser.optheader.DataDirectoryKey;
import com.github.katjahahn.parser.optheader.OptionalHeader;
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey;
import com.github.katjahahn.parser.sections.debug.DebugSection;
import com.github.katjahahn.parser.sections.edata.ExportSection;
import com.github.katjahahn.parser.sections.idata.DelayLoadSection;
import com.github.katjahahn.parser.sections.idata.ImportSection;
import com.github.katjahahn.parser.sections.pdata.ExceptionSection;
import com.github.katjahahn.parser.sections.reloc.RelocationSection;
import com.github.katjahahn.parser.sections.rsrc.ResourceSection;
import com.google.common.annotations.Beta;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;

/**
 * Responsible for computing section related values that are necessary for
 * loading a section---for example conversion between relative virtual addresses
 * and file offset---, loading data directories, and loading sections.
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
    private final PEData data;
    private Optional<MemoryMappedPE> memoryMapped = Optional.absent();

    /**
     * Creates a SectionLoader instance taking all information from the given
     * {@link PEData} object.
     * 
     * @param data
     */
    public SectionLoader(PEData data) {
        // extract data for easier access
        this.table = data.getSectionTable();
        this.optHeader = data.getOptionalHeader();
        this.file = data.getFile();
        this.data = data;
    }

    /**
     * Loads the first section with the given name (given the order of the
     * section headers). If the file doesn't have a section by this name, it
     * returns absent.
     * <p>
     * This does not instantiate special sections. Use methods like
     * {@link #loadImportSection()} or {@link #loadResourceSection()} instead.
     * <p>
     * The file on disk is read to fetch the information.
     * 
     * @param name
     *            the section's name
     * @return {@link PESection} of the given name, absent if section isn't
     *         contained in file
     * @throws IOException
     *             if unable to read the file
     */
    @Beta
    // TODO remove? This seems not necessary
    public Optional<PESection> maybeLoadSection(String name) throws IOException {
        Optional<SectionHeader> section = table.getSectionHeaderByName(name);
        if (section.isPresent()) {
            int sectionNr = section.get().getNumber();
            return Optional.fromNullable(loadSection(sectionNr));
        }
        return Optional.absent();
    }

    /**
     * Loads the section that has the sectionNr.
     * <p>
     * This does not instantiate special sections. Use methods like
     * {@link #loadImportSection()} or {@link #loadResourceSection()} instead.
     * 
     * @param sectionNr
     *            the section's number
     * @return {@link PESection} instance of the given number
     * @throws IllegalArgumentException
     *             if invalid sectionNr
     */
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
    public PESection loadSectionFrom(SectionHeader header) {
        long size = getReadSize(header);
        long offset = header.getAlignedPointerToRaw();
        return new PESection(size, offset, header, file);
    }

    /**
     * Rounds up the value to the file alignment of the optional header.
     * 
     * @param value
     * @return file aligned value
     */
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
        assert optHeader.isLowAlignmentMode() || result % 512 == 0;
        assert result >= value;
        return result;
    }

    /**
     * Determines the the number of bytes that is read for the section.
     * <p>
     * This is the actual section size.
     * 
     * @param header
     *            header of the section
     * @return section size
     * @throws IllegalArgumentException
     *             if header is null
     */
    public long getReadSize(SectionHeader header) {
        Preconditions.checkNotNull(header);
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
        readSize = fileSizeAdjusted(alignedPointerToRaw, readSize);
        // must not happen
        if (readSize < 0) {
            logger.error("Invalid readsize: " + readSize + " for file "
                    + file.getName() + " adjusting readsize to 0");
            readSize = 0;
        }
        assert readSize >= 0;
        return readSize;
    }

    /**
     * Adjusts the readsize of a section to the size of the file.
     * 
     * @param alignedPointerToRaw
     *            the file offset of the start of the section
     * @param readSize
     *            the determined readsize without file adjustments
     * @return adjusted readsize
     */
    private long fileSizeAdjusted(long alignedPointerToRaw, long readSize) {
        // end of section outside the file --> cut at file.length()
        if (readSize + alignedPointerToRaw > file.length()) {
            readSize = file.length() - alignedPointerToRaw;
        }
        // start of section outside the file --> nothing is read
        if (alignedPointerToRaw > file.length()) {
            logger.info("invalid section: starts outside the file, readsize set to 0");
            readSize = 0;
        }
        return readSize;
    }

    /**
     * Fetches the {@link SectionHeader} of the section the data directory entry
     * for the dataDirKey points into.
     * <p>
     * Returns absent if the data directory doesn't exist.
     * 
     * @param dataDirKey
     *            the data directory key
     * @return the section table entry the data directory entry of that key
     *         points into or absent if there is no data dir entry for the key
     *         available
     */
    public Optional<SectionHeader> maybeGetSectionHeader(
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
     * <p>
     * Returns absent if data directory doesn't exist.
     * 
     * @param dataDirKey
     *            the key of the data directory entry
     * @return file offset of the rva that is in the data directory entry with
     *         the given key, absent if file offset can not be determined
     */
    public Optional<Long> maybeGetFileOffsetFor(DataDirectoryKey dataDirKey) {
        Optional<DataDirEntry> dataDir = optHeader
                .maybeGetDataDirEntry(dataDirKey);
        if (dataDir.isPresent()) {
            long rva = dataDir.get().getVirtualAddress();
            return maybeGetFileOffset(rva);
        }
        return Optional.absent();
    }

    /**
     * Returns the file offset for the given RVA.
     * <p>
     * Returns absent if determined offset would point outside the file.
     * 
     * @param rva
     *            the relative virtual address that shall be converted to a
     *            plain file offset
     * @return file offset optional, absent if file offset can not be
     *         determined.
     */
    public Optional<Long> maybeGetFileOffset(long rva) {
        Optional<SectionHeader> section = maybeGetSectionHeaderByRVA(rva);
        // standard value if rva doesn't point into a section
        long fileOffset = rva;
        // rva is located within a section
        if (section.isPresent()) {
            long virtualAddress = section.get().get(VIRTUAL_ADDRESS);
            long pointerToRawData = section.get().get(POINTER_TO_RAW_DATA);
            fileOffset = rva - (virtualAddress - pointerToRawData);
        }
        // file offset is valid
        if (fileOffset <= file.length()) {
            return Optional.of(fileOffset);
        }
        logger.warn("invalid file offset: 0x" + Long.toHexString(fileOffset)
                + " for file: " + file.getName() + " with length 0x"
                + Long.toHexString(file.length()));
        // file offset is invalid
        return Optional.absent();
    }

    /**
     * Returns the section entry of the section table the rva is pointing into.
     * 
     * @param rva
     *            the relative virtual address
     * @return the {@link SectionHeader} of the section the rva is pointing into
     */
    public Optional<SectionHeader> maybeGetSectionHeaderByRVA(long rva) {
        List<SectionHeader> sections = table.getSectionHeaders();
        for (SectionHeader section : sections) {
            long vSize = section.getAlignedVirtualSize();
            long vAddress = section.getAlignedVirtualAddress();
            if (rvaIsWithin(vAddress, vSize, rva)) {
                return Optional.of(section);
            }
        }
        return Optional.absent();
    }

    /**
     * Returns the section entry of the section table the offset is pointing
     * into.
     * 
     * @param fileOffset
     *            the file offset
     * @return the {@link SectionHeader} of the section the offset is pointing
     *         into
     */
    public Optional<SectionHeader> maybeGetSectionHeaderByOffset(long fileOffset) {
        List<SectionHeader> sections = table.getSectionHeaders();
        for (SectionHeader header : sections) {
            long size = getReadSize(header);
            long address = header.getAlignedPointerToRaw();
            if (rvaIsWithin(address, size, fileOffset)) { // TODO misleading
                                                          // name of method
                return Optional.of(header);
            }
        }
        return Optional.absent();
    }

    /**
     * Returns true if rva is within address and size of a section
     * 
     * @param address
     *            start of a section
     * @param size
     *            size of a section
     * @param rva
     *            a relative virtual address that may point into the section
     * @return true iff rva is within section range
     */
    private static boolean rvaIsWithin(long address, long size, long rva) {
        long endpoint = address + size;
        return rva >= address && rva < endpoint;
    }

    /**
     * To get rid of code repetition in the maybeLoadXSection() methods, this
     * abtracts the behaviour of assembling the LoadInfo and calling the factory
     * methods of the special sections based on the data directory key.
     * <p>
     * This results in having to cast the return value to the appropriate type,
     * but correct types are well tested with unit tests.
     * 
     * @param key
     * @return the special section optional that belongs to the key.
     */
    private Optional<? extends SpecialSection> maybeLoadSpecialSection(
            DataDirectoryKey key) {
        Optional<LoadInfo> maybeLoadInfo = maybeGetLoadInfo(key);
        if (maybeLoadInfo.isPresent()) {
            LoadInfo loadInfo = maybeLoadInfo.get();
            SpecialSection section = null;
            switch (key) {
            case IMPORT_TABLE:
                section = ImportSection.newInstance(loadInfo);
                break;
            case EXCEPTION_TABLE:
                section = ExceptionSection.newInstance(loadInfo);
                break;
            case EXPORT_TABLE:
                section = ExportSection.newInstance(loadInfo);
                break;
            case DEBUG:
                section = DebugSection.newInstance(loadInfo);
                break;
            case RESOURCE_TABLE:
                section = ResourceSection.newInstance(loadInfo);
                break;
            case BASE_RELOCATION_TABLE:
                section = RelocationSection.newInstance(loadInfo);
                break;
            case DELAY_IMPORT_DESCRIPTOR:
                section = DelayLoadSection.newInstance(loadInfo);
                break;
            default:
                return Optional.absent();
            }
            if (section.isEmpty()) {
                logger.warn("empty data directory: " + key);
            }
            return Optional.of(section);
        }
        return Optional.absent();
    }

    /**
     * Shortens the loadXSection() methods by handling an empty Optional with an
     * IllegalStateException.
     * 
     * @param optional
     * @param message
     * @return
     */
    private SpecialSection getOrThrow(
            Optional<? extends SpecialSection> optional, String message) {
        if (optional.isPresent()) {
            return optional.get();
        }
        throw new IllegalStateException(message);
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
    public DelayLoadSection loadDelayLoadSection() throws IOException {
        Optional<DelayLoadSection> debug = maybeLoadDelayLoadSection();
        return (DelayLoadSection) getOrThrow(debug,
                "unable to load delay-load import section");
    }

    /**
     * Loads all bytes and information of the debug section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link DebugSection} of the given file, absent if file doesn't
     *         have this section
     * @throws IOException
     *             if unable to read the file
     */
    @SuppressWarnings("unchecked")
    public Optional<DelayLoadSection> maybeLoadDelayLoadSection()
            throws IOException {
        return (Optional<DelayLoadSection>) maybeLoadSpecialSection(DataDirectoryKey.DELAY_IMPORT_DESCRIPTOR);
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
    public RelocationSection loadRelocSection() throws IOException {
        Optional<RelocationSection> debug = maybeLoadRelocSection();
        return (RelocationSection) getOrThrow(debug,
                "unable to load reloc section");
    }

    /**
     * Loads all bytes and information of the debug section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link DebugSection} of the given file, absent if file doesn't
     *         have this section
     * @throws IOException
     *             if unable to read the file
     */
    @SuppressWarnings("unchecked")
    public Optional<RelocationSection> maybeLoadRelocSection()
            throws IOException {
        return (Optional<RelocationSection>) maybeLoadSpecialSection(DataDirectoryKey.BASE_RELOCATION_TABLE);
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
    public DebugSection loadDebugSection() throws IOException {
        Optional<DebugSection> debug = maybeLoadDebugSection();
        return (DebugSection) getOrThrow(debug, "unable to load debug section");
    }

    /**
     * Loads all bytes and information of the debug section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link DebugSection} of the given file, absent if file doesn't
     *         have this section
     * @throws IOException
     *             if unable to read the file
     */
    @SuppressWarnings("unchecked")
    public Optional<DebugSection> maybeLoadDebugSection() throws IOException {
        return (Optional<DebugSection>) maybeLoadSpecialSection(DataDirectoryKey.DEBUG);
    }

    /**
     * Loads all bytes and information of the resource section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link ResourceSection} of the given file
     * @throws IOException
     *             if unable to read the file
     * @throws IllegalStateException
     *             if section can not be loaded
     */
    public ResourceSection loadResourceSection() throws IOException {
        Optional<ResourceSection> rsrc = maybeLoadResourceSection();
        return (ResourceSection) getOrThrow(rsrc,
                "unable to load resource section");
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
    @SuppressWarnings("unchecked")
    public Optional<ResourceSection> maybeLoadResourceSection()
            throws IOException {
        return (Optional<ResourceSection>) maybeLoadSpecialSection(DataDirectoryKey.RESOURCE_TABLE);
    }

    /**
     * Loads all bytes and information of the exception section.
     * 
     * The file on disk is read to fetch the information.
     * 
     * @return {@link ExceptionSection} of the given file
     * @throws IOException
     *             if unable to read the file
     * @throws IllegalStateException
     *             if section can not be loaded
     */
    public ExceptionSection loadExceptionSection() throws IOException {
        Optional<ExceptionSection> pdata = maybeLoadExceptionSection();
        return (ExceptionSection) getOrThrow(pdata,
                "unable to load exception section");
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
    @SuppressWarnings("unchecked")
    public Optional<ExceptionSection> maybeLoadExceptionSection()
            throws IOException {
        return (Optional<ExceptionSection>) maybeLoadSpecialSection(DataDirectoryKey.EXCEPTION_TABLE);
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
    public ImportSection loadImportSection() throws IOException {
        Optional<ImportSection> idata = maybeLoadImportSection();
        return (ImportSection) getOrThrow(idata,
                "unable to load import section");
    }

    /**
     * Loads all bytes and information of the import section. The file on disk
     * is read to fetch the information.
     * 
     * @return the import section, absent if section can not be loaded
     * @throws IOException
     *             if unable to read the file
     */
    @SuppressWarnings("unchecked")
    public Optional<ImportSection> maybeLoadImportSection() throws IOException {
        return (Optional<ImportSection>) maybeLoadSpecialSection(DataDirectoryKey.IMPORT_TABLE);
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
    public ExportSection loadExportSection() throws IOException {
        Optional<ExportSection> edata = maybeLoadExportSection();
        return (ExportSection) getOrThrow(edata,
                "unable to load export section");
    }

    /**
     * Loads all bytes and information of the export section. The file on disk
     * is read to fetch the information.
     * 
     * @return the export section, absent if file doesn't have an export section
     * @throws IOException
     *             if unable to read the file
     */
    @SuppressWarnings("unchecked")
    public Optional<ExportSection> maybeLoadExportSection() throws IOException {
        return (Optional<ExportSection>) maybeLoadSpecialSection(DataDirectoryKey.EXPORT_TABLE);
    }

    /**
     * Creates new instance of MemoryMappedPE or just returns it, if it is
     * already there.
     * 
     * @return memory mapped PE
     */
    private MemoryMappedPE getMemoryMappedPE() {
        if (!memoryMapped.isPresent()) {
            memoryMapped = Optional.of(MemoryMappedPE.newInstance(data, this));
        }
        return memoryMapped.get();
    }

    /**
     * Assembles the loadInfo object for the dataDirKey.
     * 
     * @param dataDirKey
     *            data directory key
     * @return loading information
     */
    private Optional<LoadInfo> maybeGetLoadInfo(DataDirectoryKey dataDirKey) {
        Optional<DataDirEntry> dirEntry = optHeader
                .maybeGetDataDirEntry(dataDirKey);
        if (dirEntry.isPresent()) {
            long virtualAddress = dirEntry.get().getVirtualAddress();
            Optional<Long> maybeOffset = maybeGetFileOffsetFor(dataDirKey);
            if (maybeOffset.isPresent()) {
                long offset = maybeOffset.or(0L);
                return Optional.of(new LoadInfo(offset, virtualAddress,
                        getMemoryMappedPE(), data, this));
            } else {
                logger.info("unable to get file offset for " + dataDirKey);
            }
        }
        return Optional.absent();
    }

    /**
     * Data object. Contains the load information for a certain data special
     * section.
     */
    public static class LoadInfo {

        /**
         * The physical address to the start of the section
         */
        public final long fileOffset;
        /**
         * The virtual address to the start of the section
         */
        public final long va;
        /**
         * The header data
         */
        public final PEData data;
        /**
         * The memory mapped PE instance
         */
        public final MemoryMappedPE memoryMapped;
        /**
         * The section loader
         */
        public final SectionLoader loader;

        /**
         * Creates a LoadInfo instance with all the loading information.
         * 
         * @param fileOffset
         * @param va
         * @param memoryMapped
         * @param data
         * @param loader
         */
        public LoadInfo(long fileOffset, long va, MemoryMappedPE memoryMapped,
                PEData data, SectionLoader loader) {
            this.fileOffset = fileOffset;
            this.va = va;
            this.memoryMapped = memoryMapped;
            this.data = data;
            this.loader = loader;
        }

    }

    /**
     * Returns whether the virtual address of the data directory entry is valid.
     * 
     * @param dataDirKey
     * @return true iff virtual address is valid
     */
    @Beta
    public boolean hasValidPointer(DataDirectoryKey dataDirKey) {
        DataDirEntry dataDir = optHeader.getDataDirEntries().get(dataDirKey);
        long rva = dataDir.getVirtualAddress();
        return maybeGetFileOffset(rva).isPresent();
    }

    /**
     * Returns whether the section is valid.
     * <p>
     * A section is valid if the readsize is greater than 0 and the section
     * start is within the file.
     * 
     * @see #getReadSize(SectionHeader)
     * @param header
     *            the section's header
     * @return true iff section is valid
     */
    @Beta
    public boolean isValidSection(SectionHeader header) {
        // sidenote: the readsize should never be > 0 if the section starts
        // outside the file
        // but we make sure that everything is alright
        return getReadSize(header) > 0
                && header.getAlignedPointerToRaw() < file.length();
    }

    // TODO more general method? Like contains RVA?
    /**
     * Returns whether the section contains the entry point of the file.
     * 
     * @param header
     *            the header of the section that may contain the entry point.
     * @return true if entry point is within the section, false otherwise
     */
    @Beta
    public boolean containsEntryPoint(SectionHeader header) {
        long ep = data.getOptionalHeader().get(
                StandardFieldEntryKey.ADDR_OF_ENTRY_POINT);
        long vStart = header.getAlignedVirtualAddress();
        long vSize = header.getAlignedVirtualSize();
        if (vSize == 0) {
            vSize = header.getAlignedSizeOfRaw();
        }
        long vEnd = vSize + vStart;
        return ep >= vStart && ep < vEnd;
    }
}
