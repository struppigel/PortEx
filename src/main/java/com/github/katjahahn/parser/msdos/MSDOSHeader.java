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

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.github.katjahahn.parser.Header;
import com.github.katjahahn.parser.IOUtil;
import com.github.katjahahn.parser.IOUtil.SpecificationFormat;
import com.github.katjahahn.parser.StandardField;
import com.google.java.contract.Ensures;
import com.google.java.contract.Requires;

/**
 * Fetches values from the MSDOS header of the PE.
 * 
 * @author Katja Hahn
 * 
 */
public class MSDOSHeader extends Header<MSDOSHeaderKey> {

    /**
     * The size of the formatted header is {@value}
     * <p>
     * Note: The actual header may be larger, containing optional values.
     */
    public static final int FORMATTED_HEADER_SIZE = 64;
    private static final int PARAGRAPH_SIZE = 16; // in Byte

    private static final byte[] MZ_SIGNATURE = "MZ".getBytes();
    private static final String SPEC_LOCATION = "msdosheaderspec";
    private Map<MSDOSHeaderKey, StandardField> headerData;

    private final byte[] headerbytes;
    private final long offset = 0;
    private final long peSigOffset;

    /**
     * Creates an instance of the optional header.
     * 
     * @param headerbytes
     * @param offset
     */
    @Requires("headerbytes != null")
    private MSDOSHeader(byte[] headerbytes, long peSigOffset) {
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

    // TODO remove read
    private void read() throws IOException {
        if (!hasSignature(headerbytes)) {
            throw new IOException("No MZ Signature found");
        }
        SpecificationFormat format = new SpecificationFormat(0, 3, 1, 2);
        headerData = IOUtil.readHeaderEntries(MSDOSHeaderKey.class, format,
                SPEC_LOCATION, headerbytes, getOffset());
    }

    /**
     * Calculates and returns the size of the header.
     * 
     * @return size of header
     */
    //TODO this is size of header + stub ?
    @Ensures("result >= 0")
    public long getHeaderSize() {
        long headerSize = get(MSDOSHeaderKey.HEADER_PARAGRAPHS)
                * PARAGRAPH_SIZE;
        if (headerSize > peSigOffset) {
            return peSigOffset;
        }
        return headerSize;
    }

    @Requires("headerbytes != null")
    private boolean hasSignature(byte[] headerbytes) {
        // TODO collapsed MSDOS header? And wrong responsibility to check this
        // here!
        if (headerbytes.length < 28) {
            throw new IllegalArgumentException(
                    "not enough headerbytes for MS DOS Header");
        } else {
            for (int i = 0; i < MZ_SIGNATURE.length; i++) {
                if (MZ_SIGNATURE[i] != headerbytes[i]) {
                    return false;
                }
            }
            return true;
        }
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

    public static MSDOSHeader newInstance(byte[] headerbytes, long peSigOffset)
            throws IOException {
        MSDOSHeader header = new MSDOSHeader(headerbytes, peSigOffset);
        header.read();
        return header;
    }

}
