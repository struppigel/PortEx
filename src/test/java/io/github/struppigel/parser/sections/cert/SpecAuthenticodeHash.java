/*******************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
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
package io.github.struppigel.parser.sections.cert;

import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.optheader.DataDirEntry;
import io.github.struppigel.parser.optheader.DataDirectoryKey;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.parser.sections.SectionHeader;
import io.github.struppigel.parser.sections.SectionHeaderKey;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * The image digest as described by the Authenticode specification
 * (Authenticode_PE.docx): headers without checksum and certificate table
 * entry, then the sections sorted by PointerToRawData, then the remaining
 * data except the certificate table. Used to cross-check the linear
 * implementation of {@link ImageHasher}.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class SpecAuthenticodeHash {

    private SpecAuthenticodeHash() {
    }

    static byte[] digest(PEData data, String algorithm) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        long checksum = data.getOptionalHeader().getField(WindowsEntryKey.CHECKSUM).getOffset();
        DataDirEntry entry = data.getOptionalHeader().maybeGetDataDirEntry(DataDirectoryKey.CERTIFICATE_TABLE).get();
        long certEntry = entry.getTableEntryOffset();
        long sizeOfHeaders = data.getOptionalHeader().get(WindowsEntryKey.SIZE_OF_HEADERS);
        long fileSize = data.getFile().length();
        try (RandomAccessFile raf = new RandomAccessFile(data.getFile(), "r")) {
            update(md, raf, 0, checksum);
            update(md, raf, checksum + 4, certEntry);
            update(md, raf, certEntry + 8, sizeOfHeaders);
            long hashed = sizeOfHeaders;
            List<SectionHeader> sections = new ArrayList<>(data.getSectionTable().getSectionHeaders());
            sections.sort(Comparator.comparingLong(s -> s.get(SectionHeaderKey.POINTER_TO_RAW_DATA)));
            for (SectionHeader s : sections) {
                long size = s.get(SectionHeaderKey.SIZE_OF_RAW_DATA);
                if (size == 0) {
                    continue;
                }
                long start = s.get(SectionHeaderKey.POINTER_TO_RAW_DATA);
                update(md, raf, start, start + size);
                hashed += size;
            }
            long extra = fileSize - entry.getDirectorySize() - hashed;
            if (extra > 0) {
                update(md, raf, hashed, hashed + extra);
            }
        }
        return md.digest();
    }

    private static void update(MessageDigest md, RandomAccessFile raf, long from, long to) throws IOException {
        byte[] buffer = new byte[(int) (to - from)];
        raf.seek(from);
        raf.readFully(buffer);
        md.update(buffer);
    }
}
