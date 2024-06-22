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
package com.github.struppigel.tools;

import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoader;
import com.github.struppigel.parser.RichHeader;
import com.github.struppigel.parser.sections.SectionHeader;
import com.github.struppigel.parser.sections.SectionLoader;
import com.github.struppigel.parser.sections.SectionTable;
import com.google.common.base.Preconditions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * Creates hash values of PE files and sections.
 * 
 * @author Karsten Hahn
 * 
 */
public class Hasher {

    private static final Logger logger = LogManager.getLogger(Hasher.class
            .getName());

    private static final int BUFFER_SIZE = 16384;
    private PEData data;

    /**
     * Creates a hasher instance for the data.
     * 
     * @param data
     */
    public Hasher(PEData data) {
        this.data = data;
    }

    /**
     * Returns the hash value of the file with the messageDigest.
     * 
     * @return hash value of the file
     * @throws IOException
     */
    public byte[] fileHash(MessageDigest messageDigest) throws IOException {
        return fileHash(data.getFile(), messageDigest);
    }

    /**
     * Returns the rich header hash value if present. The hash is the MD5 of the cleartext rich header.
     *
     * @return md5 of the rich header if the rich header is present
     */
    public Optional<byte[]> maybeRichHash() {
        Optional<RichHeader> maybeRich = data.maybeGetRichHeader();
        try {
            if (maybeRich.isPresent()) {
                RichHeader rich = maybeRich.get();
                byte[] richData = rich.getDecodedRichHeaderBytes();
                byte[] richHash = MessageDigest.getInstance("MD5").digest(richData);
                return Optional.of(richHash);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.error("Invalid algorithm chosen for rich header hash");
        }
        return Optional.empty();
    }

    /**
     * Returns the rich header hash value if present. The hash is the MD5 of the cleartext rich header, excluding the count fields.
     *
     * @return md5 of the rich header if the rich header is present
     */
    public Optional<byte[]> maybeRichPVHash() {
        Optional<RichHeader> maybeRich = data.maybeGetRichHeader();
        try {
            if (maybeRich.isPresent()) {
                RichHeader rich = maybeRich.get();
                byte[] richData = rich.getDecodedRichHeaderBytesWithoutCount();
                byte[] richHash = MessageDigest.getInstance("MD5").digest(richData);
                return Optional.of(richHash);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.error("Invalid algorithm chosen for rich header hash");
        }
        return Optional.empty();
    }

    /**
     * Returns the hash value of the section with the section number and the
     * messageDigest.
     * <p>
     * The section's size must be greater than 0, otherwise the returned array
     * has zero length.
     * 
     * @param sectionNumber
     *            the section's number
     * @param messageDigest
     *            the message digest algorithm
     * @return hash value of the section with the section number
     * @throws IOException
     */
    public byte[] sectionHash(int sectionNumber, MessageDigest messageDigest)
            throws IOException {
        SectionTable table = data.getSectionTable();
        SectionHeader header = table.getSectionHeader(sectionNumber);
        long start = header.getAlignedPointerToRaw(data.getOptionalHeader().isLowAlignmentMode());
        long end = new SectionLoader(data).getReadSize(header) + start;
        if (end <= start) {
            logger.warn("The physical section size must be greater than zero!");
            return new byte[0];
        }
        return computeHash(data.getFile(), messageDigest, start, end);
    }

    public static Hasher newInstance(File file) throws IOException {
        PEData data = PELoader.loadPE(file);
        return new Hasher(data);
    }

    /**
     * Returns the hash value of the file for the specified messageDigest.
     * 
     * @param file
     *            to compute the hash value for
     * @param messageDigest
     *            the message digest algorithm
     * @return hash value of the file
     * @throws IOException
     */
    public static byte[] fileHash(File file, MessageDigest messageDigest)
            throws IOException {
        return computeHash(file, messageDigest, 0L, file.length());
    }

    /**
     * Computes the hash value for the file bytes from offset <code>from</code>
     * until offset <code>until</code>, using the hash instance as defined by
     * the hash type.
     * 
     * @param file
     *            the file to compute the hash from
     * @param digest
     *            the message digest instance
     * @param from
     *            file offset to start from
     * @param until
     *            file offset for the end
     * @return hash value as byte array
     * @throws IOException
     */
    public static byte[] computeHash(File file, MessageDigest digest,
            long from, long until) throws IOException {
        Preconditions.checkArgument(from >= 0, "negative offset");
        Preconditions.checkArgument(until > from, "end offset is smaller or equal to start offset");
        Preconditions.checkArgument(until <= file.length(), "end offset is greater than file length");
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int readbytes;
            long byteSum = from;
            raf.seek(from);
            while ((readbytes = raf.read(buffer)) != -1 && byteSum <= until) {
                byteSum += readbytes;
                if (byteSum > until) {
                    readbytes -= (byteSum - until);
                }
                digest.update(buffer, 0, readbytes);
            }
            return digest.digest();
        }
    }
}
