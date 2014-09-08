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
package com.github.katjahahn.parser.msdos;

import static com.github.katjahahn.parser.IOUtil.*;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.katjahahn.parser.Header;
import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.IOUtil.SpecificationFormat;
import com.github.katjahahn.parser.StandardField;
import com.google.common.base.Preconditions;

/**
 * Fetches values from the MSDOS header of the PE.
 * 
 * @author Katja Hahn
 * 
 */
public class MSDOSHeader extends Header<MSDOSHeaderKey> {

    private static final Logger logger = LogManager.getLogger(MSDOSHeader.class
            .getName());

    /**
     * The size of the formatted header is {@value} bytes
     * <p>
     * Note: The actual header may be larger, containing optional values.
     */
    public static final int FORMATTED_HEADER_SIZE = 64;
    /** The size one paragraph in bytes */
    private static final int PARAGRAPH_SIZE = 16; // in Byte

    /** the bytes of the MZ signature */
    private static final byte[] MZ_SIGNATURE = "MZ".getBytes();
    /** the specification name */
    private static final String SPEC_LOCATION = "msdosheaderspec";
    /** the header fields */
    private Map<MSDOSHeaderKey, StandardField> headerData;

    /** the bytes that make up the header */
    private final byte[] headerbytes;
    /** the file offset of the header */
    private final long offset = 0;
    /** the offset of the PE signature */
    private final long peSigOffset;

    /**
     * Creates an instance of the optional header.
     * 
     * @param headerbytes
     * @param offset
     */
    private MSDOSHeader(byte[] headerbytes, long peSigOffset) {
        assert headerbytes != null;
        this.headerbytes = headerbytes.clone();
        this.peSigOffset = peSigOffset;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getOffset() {
        return offset;
    }

    /**
     * Reads the header fields.
     */
    private void read() throws IOException {
        // check headerbytes
        Preconditions.checkState(headerbytes.length >= 28,
                "not enough headerbytes for MS DOS Header");
        // check MZ signature
        if (!hasSignature(headerbytes)) {
            throw new IOException("No MZ Signature found");
        }
        // define specification format
        SpecificationFormat format = new SpecificationFormat(0, 3, 1, 2);
        // read header fields
        try {
            headerData = IOUtil.readHeaderEntries(MSDOSHeaderKey.class, format,
                    SPEC_LOCATION, headerbytes, getOffset());
        } catch (IOException e) {
            logger.error("unable to read the msdos specification: "
                    + e.getMessage());
        }
    }

    /**
     * Calculates and returns the size of the header.
     * 
     * @return size of header
     */
    // TODO this is size of header + stub ?
    public long getHeaderSize() {
        long headerSize = get(MSDOSHeaderKey.HEADER_PARAGRAPHS)
                * PARAGRAPH_SIZE;
        if (headerSize > peSigOffset) {
            return peSigOffset;
        }
        assert headerSize >= 0;
        return headerSize;
    }

    private boolean hasSignature(byte[] headerbytes) {
        assert headerbytes != null;
        // check each signature byte
        for (int i = 0; i < MZ_SIGNATURE.length; i++) {
            if (MZ_SIGNATURE[i] != headerbytes[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns a list of the header entries.
     * 
     * @return a list of header entries
     */
    public List<StandardField> getHeaderEntries() {
        return new LinkedList<>(headerData.values());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long get(MSDOSHeaderKey key) {
        return getField(key).value;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public StandardField getField(MSDOSHeaderKey key) {
        return headerData.get(key);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getInfo() {
        if (headerData == null) {
            return "No MS DOS Header found!" + NL;
        } else {
            StringBuilder b = new StringBuilder("-------------" + NL
                    + "MS DOS Header" + NL + "-------------" + NL);
            for (StandardField entry : headerData.values()) {
                b.append(entry.description + ": " + entry.value + " (0x"
                        + Long.toHexString(entry.value) + ")" + NL);
            }
            return b.toString();
        }
    }

    /**
     * Creates and returns an instance of the MSDOSHeader with the given bytes
     * and the file offset of the PE signature.
     * 
     * @param headerbytes
     *            the bytes that make up the MSDOSHeader
     * @param peSigOffset
     *            file offset to the PE signature
     * @return MSDOSHeader instance
     * @throws IOException
     *             if header can not be read.
     */
    public static MSDOSHeader newInstance(byte[] headerbytes, long peSigOffset)
            throws IOException {
        MSDOSHeader header = new MSDOSHeader(headerbytes, peSigOffset);
        header.read();
        return header;
    }

}
