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

import static com.github.katjahahn.parser.IOUtil.loadBytes;
import static com.github.katjahahn.parser.IOUtil.loadBytesSafely;
import static com.google.common.base.Preconditions.checkState;

import java.awt.AWTException;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;

import com.github.katjahahn.tools.visualizer.ImageUtil;
import com.github.katjahahn.tools.visualizer.Visualizer;
import com.github.katjahahn.tools.visualizer.VisualizerBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.coffheader.COFFFileHeader;
import com.github.katjahahn.parser.msdos.MSDOSHeader;
import com.github.katjahahn.parser.optheader.OptionalHeader;
import com.github.katjahahn.parser.optheader.WindowsEntryKey;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.github.katjahahn.parser.sections.edata.ExportSection;
import com.github.katjahahn.tools.PEAutoRepair;
import com.github.katjahahn.tools.ReportCreator;

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
        checkState(pesig.exists(),
                "no valid pe file, signature not found");
        // read all headers
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            MSDOSHeader msdos = loadMSDOSHeader(raf, pesig.getOffset());
            RichHeader rich = null;
            try {
                rich = loadRichHeader(raf, pesig.getOffset());
            } catch (FileFormatException e) {
                logger.info("no rich header found");
            }
            COFFFileHeader coff = loadCOFFFileHeader(pesig, raf);
            OptionalHeader opt = loadOptionalHeader(pesig, coff, raf);
            SectionTable table = loadSectionTable(pesig, coff, raf);
            table.read();
            // construct PEData instance
            PEData data = new PEData(msdos, pesig, coff, opt, table, file, rich);
            /* reload headers in case of dual pe header */
            // MemoryMappedPE mmBytes = MemoryMappedPE.newInstance(data,
            // new SectionLoader(data));
            // TODO reload coff, msdos, ..
            // coff = reloadCOFFFileHeader(pesig, mmBytes, data);
            // data = new PEData(msdos, pesig, coff, opt, table, file);
            // opt = reloadOptionalHeader(pesig, mmBytes, data);
            // data = new PEData(msdos, pesig, coff, opt, table, file);
            // table.reload(mmBytes);
            // System.out.println(new ReportCreator(data).secTableReport());
            // re-construct PEData instance
            return data;
        }
    }

    private int getOptHeaderSize(long offset) {
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
        return size;
    }

    // TODO is this necessary? look it up
    private COFFFileHeader reloadCOFFFileHeader(PESignature pesig,
            MemoryMappedPE mmBytes, PEData data) throws IOException {
        // coff header starts right after the PE signature
        long offset = pesig.getOffset() + PESignature.PE_SIG.length;
        /* read bytes, size is fixed anyway */
        long sizeOfHeaders = data.getOptionalHeader().get(
                WindowsEntryKey.SIZE_OF_HEADERS);
        logger.debug("SizeOfHeaders: " + sizeOfHeaders);
        // virtual end of header mapping marked by VA of first section
        long vEnd = data.getSectionTable().getSectionHeader(1)
                .getAlignedVirtualAddress() - 1;
        // virtual start of headers TODO test
        long vStart = vEnd - sizeOfHeaders;
        long sliceStart = vStart + PESignature.PE_SIG.length;
        logger.debug("reading coff at start: " + sliceStart);
        byte[] headerbytes = mmBytes.slice(sliceStart, sliceStart
                + COFFFileHeader.HEADER_SIZE);
        // construct header
        return COFFFileHeader.newInstance(headerbytes, offset);
    }

    // FIXME
    private OptionalHeader reloadOptionalHeader(PESignature pesig,
            MemoryMappedPE mmBytes, PEData data) throws IOException {
        logger.info("reloading optional header");
        // offset right after the eCOFF File Header
        long offset = pesig.getOffset() + PESignature.PE_SIG.length
                + COFFFileHeader.HEADER_SIZE;
        logger.info("Optional Header offset: " + offset);
        int size = getOptHeaderSize(offset);
        // read bytes and construct header
        long sizeOfHeaders = data.getOptionalHeader().get(
                WindowsEntryKey.SIZE_OF_HEADERS);
        // virtual end of header mapping marked by VA of first section
        long vEnd = data.getSectionTable().getSectionHeader(1)
                .getAlignedVirtualAddress() - 1;
        // virtual start of headers TODO test
        long vStart = vEnd - sizeOfHeaders;
        long sliceStart = vStart + COFFFileHeader.HEADER_SIZE
                + PESignature.PE_SIG.length;
        logger.debug("reading opt at start: " + sliceStart);
        byte[] headerbytes = mmBytes.slice(sliceStart, sliceStart + size);
        logger.debug("array size: " + headerbytes.length);
        logger.debug(ByteArrayUtil.byteToHex(headerbytes));
        return OptionalHeader.newInstance(headerbytes, offset);
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
     * Loads the Rich header.
     *
     * @param raf
     *            the random access file instance
     * @return rich header
     * @throws IOException
     *             if unable to read rich header
     */
    private RichHeader loadRichHeader(RandomAccessFile raf, long peSigOffset)
            throws IOException {
        byte[] headerbytes = loadBytesSafely(0,
                (int) peSigOffset, raf);
        return RichHeader.newInstance(headerbytes);
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
        int size = getOptHeaderSize(offset);
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

        File file = new File("C:\\Malware\\workspace\\redline");
        PEData data = PELoader.loadPE(file);

        ReportCreator reporter = ReportCreator.apply(file);
        System.out.println(reporter.clrReport());
       //  VisualizerBuilder builder = new VisualizerBuilder();
        // Visualizer vi = builder.build();
         //final BufferedImage entropyImage = vi.createEntropyImage(file);
         //final BufferedImage structureImage = vi.createImage(file);
        // final BufferedImage appendedImage = ImageUtil.appendImages(
        // entropyImage, structureImage);
        // show(appendedImage);
    }

    private static void show(final BufferedImage image) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JFrame frame = new JFrame();
                frame.setSize(600, 600);
                frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                frame.getContentPane().add(new JLabel(new ImageIcon(image)));
                frame.pack();
                frame.setVisible(true);
            }
        });
    }
}
