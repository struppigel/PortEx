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
package com.github.katjahahn.tools;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.github.katjahahn.parser.ByteArrayUtil;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;
import com.github.katjahahn.parser.sections.SectionHeader;
import com.github.katjahahn.parser.sections.SectionLoader;
import com.github.katjahahn.parser.sections.SectionTable;
import com.google.common.base.Preconditions;
import com.google.java.contract.Ensures;

/**
 * Creates hash values of PE files and sections.
 * 
 * @author Katja Hahn
 * 
 */
public class Hasher {

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
     * Returns the md5 hash value of the file.
     * 
     * @return md5 hash value of the file
     * @throws IOException
     */
    @Ensures("result != null")
    public byte[] md5() throws IOException {
        return md5(data.getFile());
    }

    /**
     * Returns the sha256 hash value of the file.
     * 
     * @return sha256 hash value of the file
     * @throws IOException
     */
    @Ensures("result != null")
    public byte[] sha256() throws IOException {
        return sha256(data.getFile());
    }

    /**
     * Returns the md5 hash value of the section with the section number
     * 
     * @param sectionNumber
     *            the section's number
     * @return md5 hash value of the section with the section number
     * @throws IOException
     */
    public byte[] md5OfSection(int sectionNumber) throws IOException {
        SectionTable table = data.getSectionTable();
        SectionHeader header = table.getSectionHeader(sectionNumber);
        long start = header.getAlignedPointerToRaw();
        long end = new SectionLoader(data).getReadSize(header) + start;
        return computeHash(data.getFile(), "MD5", start, end);
    }

    /**
     * Returns the sha256 hash value of the section with the section number
     * 
     * @param sectionNumber
     *            the section's number
     * @return sha256 hash value of the section with the section number
     * @throws IOException
     */
    public byte[] sha256OfSection(int sectionNumber) throws IOException {
        SectionTable table = data.getSectionTable();
        SectionHeader header = table.getSectionHeader(sectionNumber);
        long start = header.getAlignedPointerToRaw();
        long end = new SectionLoader(data).getReadSize(header) + start;
        return computeHash(data.getFile(), "SHA-256", start, end);
    }

    public static void main(String... args) throws IOException {
        File file = new File("/home/deque/portextestfiles/WinRar.exe");
        PEData data = PELoader.loadPE(file);
        Hasher hasher = new Hasher(data);
        byte[] hash = hasher.md5();
        System.out.println("MD5: " + ByteArrayUtil.byteToHex(hash, ""));
        hash = hasher.sha256();
        System.out.println("SHA-256: " + ByteArrayUtil.byteToHex(hash, ""));
        System.out.println();
        int sections = data.getSectionTable().getNumberOfSections();
        for (int i = 1; i <= sections; i++) {
            hash = hasher.sha256OfSection(i);
            System.out.println("SHA256 section " + i + ": "
                    + ByteArrayUtil.byteToHex(hash, ""));
        }
    }

    /**
     * Returns MD5 hash value of the file.
     * 
     * @param file
     *            to compute the hash value for
     * @return MD5 hash value of the file
     * @throws IOException
     */
    public static byte[] md5(File file) throws IOException {
        return computeHash(file, "MD5", 0L, file.length());
    }

    /**
     * Returns SHA256 hash value of the file.
     * 
     * @param file
     *            to compute the hash value for
     * @return SHA256 hash value of the file
     * @throws IOException
     */
    public static byte[] sha256(File file) throws IOException {
        return computeHash(file, "SHA-256", 0L, file.length());
    }

    /**
     * Computes the hash value for the file bytes from offset <code>from</code>
     * until offset <code>until</code>, using the hash instance as defined by
     * the hash type.
     * 
     * @param file
     *            the file to compute the hash from
     * @param hashType
     *            the message digest instance
     * @param from
     *            file offset to start from
     * @param until
     *            file offset for the end
     * @return hash value as byte array
     * @throws IOException
     */
    private static byte[] computeHash(File file, String hashType, long from,
            long until) throws IOException {
        Preconditions.checkArgument(until > from);
        Preconditions.checkArgument(until <= file.length());
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            MessageDigest digest = MessageDigest.getInstance(hashType);
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
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // must never happen (can happen with the wrong hash type and this is
        // catched by unit tests)
        return null;
    }
}
