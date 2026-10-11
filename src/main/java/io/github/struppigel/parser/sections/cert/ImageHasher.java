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

import io.github.struppigel.parser.Interruption;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Computes the Authenticode image digest: the digest of the whole file
 * without the checksum field, the certificate table data directory entry and
 * the certificate table.
 * <p>
 * This gives the same result as the per-section algorithm of the Authenticode
 * specification for files with contiguous sections. It uses no ranges from
 * section headers, so malformed section headers can not cause out-of-bounds
 * reads, and all digests are computed in one streaming pass.
 *
 * @author Karsten Philipp Boris Hahn
 */
final class ImageHasher {

    private ImageHasher() {
    }

    /**
     * @param file          the PE file
     * @param excluded      ranges {start, length} that are not hashed, they are
     *                      clamped to the file
     * @param digestNames   the JDK names of the digests to compute
     * @return the digests by JDK name; unsupported names are left out
     * @throws IOException if the file can not be read
     */
    static Map<String, byte[]> hash(File file, List<long[]> excluded, Collection<String> digestNames)
            throws IOException {
        Map<String, MessageDigest> digests = new LinkedHashMap<>();
        for (String name : digestNames) {
            try {
                digests.put(name, MessageDigest.getInstance(name));
            } catch (NoSuchAlgorithmException e) {
                // left out, reported as unverifiable
            }
        }
        Map<String, byte[]> result = new LinkedHashMap<>();
        if (digests.isEmpty()) {
            return result;
        }
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            long length = raf.length();
            List<long[]> ranges = included(excluded, length);
            byte[] buffer = new byte[(int) Math.min(CertificateTable.HASH_BUFFER_SIZE, Math.max(length, 1))];
            for (long[] range : ranges) {
                long pos = range[0];
                raf.seek(pos);
                while (pos < range[1]) {
                    Interruption.checkInterrupt();
                    int n = (int) Math.min(buffer.length, range[1] - pos);
                    raf.readFully(buffer, 0, n);
                    for (MessageDigest md : digests.values()) {
                        md.update(buffer, 0, n);
                    }
                    pos += n;
                }
            }
        }
        for (Map.Entry<String, MessageDigest> e : digests.entrySet()) {
            result.put(e.getKey(), e.getValue().digest());
        }
        return result;
    }

    /**
     * @return the sorted ranges {start, end} of the file that are hashed
     */
    static List<long[]> included(List<long[]> excluded, long fileLength) {
        List<long[]> clamped = new ArrayList<>();
        for (long[] range : excluded) {
            long start = Math.max(0, Math.min(range[0], fileLength));
            long end = Math.max(start, Math.min(range[0] + Math.max(range[1], 0), fileLength));
            if (end > start) {
                clamped.add(new long[]{start, end});
            }
        }
        clamped.sort(Comparator.comparingLong(r -> r[0]));
        List<long[]> included = new ArrayList<>();
        long pos = 0;
        for (long[] range : clamped) {
            if (range[0] > pos) {
                included.add(new long[]{pos, range[0]});
            }
            pos = Math.max(pos, range[1]);
        }
        if (pos < fileLength) {
            included.add(new long[]{pos, fileLength});
        }
        return included;
    }
}
