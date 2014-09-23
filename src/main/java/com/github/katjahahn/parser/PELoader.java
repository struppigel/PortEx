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
package com.github.katjahahn.parser;

import static com.github.katjahahn.parser.IOUtil.*;
import static com.google.common.base.Preconditions.*;

import java.awt.AWTException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.msdos.MSDOSHeader;
import com.github.katjahahn.parser.optheader.OptionalHeader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.github.katjahahn.tools.anomalies.AnomalySubType;

/**
 * Loads PEData of a file. Spares the user of the library to collect every
 * information necessary.
 * 
 * @author Katja Hahn
 * 
 */
public final class PELoader {

    private static final Logger logger = LogManager.getLogger(PELoader.class
            .getName());

    private final File file;

    private PELoader(File file) {
        this.file = file;
    }

    /**
     * Loads the basic header data for the given PE file.
     * 
     * @param peFile
     *            the file to load the data from
     * @return data header data of the PE file
     * @throws IOException
     *             if unable to load the file
     * @throws IllegalStateException
     *             if no valid PE file
     */
    public static PEData loadPE(File peFile) throws IOException {
        return new PELoader(peFile).loadData();
    }

    /**
     * Loads the PE file header data into a PEData instance.
     * 
     * @return header data
     * @throws IOException
     *             if file can not be read
     * @throws IllegalStateException
     *             if no valid PE file
     */
    private PEData loadData() throws IOException {
        PESignature pesig = new PESignature(file);
        pesig.read();
        checkState(pesig.hasSignature(),
                "no valid pe file, signature not found");
        // read all headers
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            MSDOSHeader msdos = loadMSDOSHeader(raf, pesig.getOffset());
            COFFFileHeader coff = loadCOFFFileHeader(pesig, raf);
            OptionalHeader opt = loadOptionalHeader(pesig, coff, raf);
            SectionTable table = loadSectionTable(pesig, coff, raf);
            table.read();
            // construct PEData instance
            PEData data = new PEData(msdos, pesig, coff, opt, table, file);
            /* reload headers in case of dual pe header */
            // MemoryMappedPE mmBytes = MemoryMappedPE.newInstance(data,
            // new SectionLoader(data));
            // reloadOptionalHeader(data);
            // table.reload(mmBytes);
            // System.out.println(new ReportCreator(data).secTableReport());
            return data;
        }
    }

    private long getFirstSectionVA(SectionTable table) {
        assert table.getNumberOfSections() > 0;
        // the VAs must be in correct order
        return table.getSectionHeader(1).getAlignedVirtualAddress();
    }

    /**
     * Loads the MSDOS header.
     * 
     * @param raf
     *            the random access file instance
     * @return msdos header
     * @throws IOException
     *             if unable to read header
     */
    private MSDOSHeader loadMSDOSHeader(RandomAccessFile raf, long peSigOffset)
            throws IOException {
        byte[] headerbytes = loadBytesSafely(0,
                MSDOSHeader.FORMATTED_HEADER_SIZE, raf);
        return MSDOSHeader.newInstance(headerbytes, peSigOffset);
    }

    /**
     * Loads the section table. Presumes a valid PE file.
     * 
     * @param pesig
     *            pe signature
     * @param coff
     *            coff file header
     * @param raf
     *            the random access file instance
     * @return section table
     * @throws IOException
     *             if unable to read header
     */
    private SectionTable loadSectionTable(PESignature pesig,
            COFFFileHeader coff, RandomAccessFile raf) throws IOException {
        // offset is the start of the optional header + SizeOfOptionalHeader
        long offset = pesig.getOffset() + PESignature.PE_SIG.length
                + COFFFileHeader.HEADER_SIZE + coff.getSizeOfOptionalHeader();
        logger.info("SectionTable offset: " + offset);
        // get entries, so you can determine the size
        int numberOfEntries = (int) coff.getNumberOfSections();
        int size = SectionTable.ENTRY_SIZE * numberOfEntries;
        if (size + offset > file.length()) {
            size = (int) (file.length() - offset);
        }
        if (size <= 0) {
            logger.warn("Unable to parse Section table, offset outside the file");
            return new SectionTable(new byte[0], 0, offset);
        }
        // read bytes
        byte[] tableBytes = loadBytes(offset, size, raf);
        // construct header
        return new SectionTable(tableBytes, numberOfEntries, offset);
    }

    /**
     * Loads the COFF File header. Presumes a valid PE file.
     * 
     * @param pesig
     *            pe signature
     * @param raf
     *            the random access file instance
     * @return coff file header
     * @throws IOException
     *             if unable to read header
     */
    private COFFFileHeader loadCOFFFileHeader(PESignature pesig,
            RandomAccessFile raf) throws IOException {
        // coff header starts right after the PE signature
        long offset = pesig.getOffset() + PESignature.PE_SIG.length;
        logger.info("COFF Header offset: " + offset);
        // read bytes, size is fixed anyway
        byte[] headerbytes = loadBytesSafely(offset,
                COFFFileHeader.HEADER_SIZE, raf);
        // construct header
        return COFFFileHeader.newInstance(headerbytes, offset);
    }

    /**
     * Loads the optional header. Presumes a valid PE file.
     * 
     * @param pesig
     *            pe signature
     * @param coff
     *            coff file header
     * @param raf
     *            the random access file instance
     * @return optional header
     * @throws IOException
     *             if unable to read header
     */
    private OptionalHeader loadOptionalHeader(PESignature pesig,
            COFFFileHeader coff, RandomAccessFile raf) throws IOException {
        // offset right after the eCOFF File Header
        long offset = pesig.getOffset() + PESignature.PE_SIG.length
                + COFFFileHeader.HEADER_SIZE;
        logger.info("Optional Header offset: " + offset);
        // set the maximum size for the bytes to read
        int size = OptionalHeader.MAX_SIZE;
        // ...with the exception of reaching EOF, this is rare, but see
        // tinype.exe
        if (size + offset > file.length()) {
            // cut size at EOF
            size = (int) (file.length() - offset);
        }
        if (size < 0) {
            size = 0;
        }
        // read bytes and construct header
        byte[] headerbytes = loadBytesSafely(offset, size, raf);
        return OptionalHeader.newInstance(headerbytes, offset);
    }

    /**
     * For testing purposes only.
     * 
     * @param args
     * @throws IOException
     */
    public static void main(String[] args) throws IOException, AWTException {
        logger.entry();
        // File file = new File(
        // "/home/deque/portextestfiles/unusualfiles/corkami/sc.exe");
        // TODO the following files take very long to parse, why?
        File file = new File(
                "/home/deque/portextestfiles/badfiles/VirusShare_e5ce7ba71528a1f221d6be883e5967f0");
        // VirusShare_e5ce7ba71528a1f221d6be883e5967f0 --> exhaustive name
        // pointer entries, export section not in section, pev doesn't show
        // imports
        // VirusShare_10c6fdb01b6b19f84055754b764c6e38 --> invalid delay-load
        // imports, exhaustive resource section
        // VirusShare_a90da79e98213703fc3342b281a95094 --> invalid export
        // entries, lots of
        // VirusShare_130f13919f9d6ed5b77046644fdbab42 --> virtual export
        // address table
//        ReportCreator reporter = ReportCreator.newInstance(file);
//        reporter.printReport();
        System.out.println(AnomalySubType.values().length);
        // System.out.println(data.getSectionTable().getOffset());
        // System.out.println(reporter.headerReports());
        // PEData data = loadPE(file);
        // SectionLoader loader = new SectionLoader(data);
        // loader.maybeLoadResourceSection();

        // System.out.println(reporter.importsReport());
        // System.out.println(reporter.exportsReport());
        // System.out.println(reporter.resourcesReport());
        // System.out.println(reporter.debugReport());
        // System.out.println(reporter.delayImportsReport());
        // System.out.println(reporter.relocReport());
        // System.out.println(reporter.anomalyReport());
        // System.out.println(reporter.hashReport());
        // System.out.println(reporter.overlayReport());
        // System.out.println(reporter.peidReport());
        // System.out.println(reporter.maldetReport());
        // System.out.println(reporter.jar2ExeReport());
        // System.out.println(reporter.additionalReports());
        // System.out.println("done");
    }
}
