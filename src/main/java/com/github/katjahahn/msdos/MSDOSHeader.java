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
package com.github.katjahahn.msdos;

import static com.github.katjahahn.ByteArrayUtil.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.github.katjahahn.Header;
import com.github.katjahahn.IOUtil;
import com.github.katjahahn.StandardField;

/**
 * Fetches values from the MSDOS header of the PE.
 * 
 * @author Katja Hahn
 * 
 */
public class MSDOSHeader extends Header<MSDOSHeaderKey> {

    // Note: This is only the formatted header by now. The actual header may be
    // larger, containing optional values.
    public static final int FORMATTED_HEADER_SIZE = 28;
    private static final int PARAGRAPH_SIZE = 16; // in Byte

    private static final byte[] MZ_SIGNATURE = "MZ".getBytes();
    private static final String specification = "msdosheaderspec";
    private Map<MSDOSHeaderKey, StandardField> headerData;

    private final byte[] headerbytes;
    private final long offset;

    public MSDOSHeader(byte[] headerbytes, long offset) {
        this.headerbytes = headerbytes.clone();
        this.offset = offset;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getOffset() {
        return offset;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void read() throws IOException {
        if (!hasSignature(headerbytes)) {
            throw new IOException("No PE Signature found");
        }
        headerData = init();
        int offsetLoc = 0;
        int sizeLoc = 1;
        int descriptionLoc = 2;
        try {
            Map<String, String[]> map = IOUtil.readMap(specification);
            for (Entry<String, String[]> entry : map.entrySet()) {
                MSDOSHeaderKey key = MSDOSHeaderKey.valueOf(entry.getKey());
                String[] spec = entry.getValue();
                long value = getBytesLongValue(headerbytes,
                        Integer.parseInt(spec[offsetLoc]),
                        Integer.parseInt(spec[sizeLoc]));
                headerData.put(key, new StandardField(key,
                        spec[descriptionLoc], value));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    
    private Map<MSDOSHeaderKey, StandardField> init() {
        Map<MSDOSHeaderKey, StandardField> map = new HashMap<>();
        for(MSDOSHeaderKey key : MSDOSHeaderKey.values()) {
            map.put(key, new StandardField(key, "", 0L));
        }
        return map;
    }

    /**
     * Calculates and returns the size of the header.
     * 
     * @return size of header
     */
    public long getHeaderSize() {
        return get(MSDOSHeaderKey.HEADER_PARAGRAPHS) * PARAGRAPH_SIZE;
    }

    private boolean hasSignature(byte[] headerbytes) {
        if (headerbytes == null || headerbytes.length < 28) {
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

}
