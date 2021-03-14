/**
 * *****************************************************************************
 * Copyright 2021 Karsten Philipp Boris Hahn
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
 * ****************************************************************************
 */
package com.github.katjahahn.tools;

import static org.testng.Assert.*;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.github.katjahahn.TestreportsReader;
import com.github.katjahahn.parser.ByteArrayUtil;
import com.github.katjahahn.parser.PEData;
import com.github.katjahahn.parser.PELoader;

public class HasherTest {

    private PEData winrar;
    private MessageDigest md5;
    private MessageDigest sha256;

    @BeforeClass
    public void prepare() throws IOException, NoSuchAlgorithmException {
        PEData data = PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR
                + TestreportsReader.TEST_FILE_DIR + "/WinRar.exe"));
        this.winrar = data;
        md5 = MessageDigest.getInstance("MD5");
        sha256 = MessageDigest.getInstance("SHA-256");
    }

    @Test
    public void fileHashes() throws IOException, NoSuchAlgorithmException {
        Hasher hasher = new Hasher(winrar);
        byte[] hash = hasher.fileHash(md5);
        assertEquals(ByteArrayUtil.byteToHex(hash, ""),
                "54e97d9059e3ba4e4dee6f0433fec960");
        assertEquals(Hasher.fileHash(winrar.getFile(), md5), hash);
        hash = hasher.fileHash(sha256);
        assertEquals(ByteArrayUtil.byteToHex(hash, ""),
                "df7509783db57a7ed2b2c794cea04a08f1ca7c289999730c4b914237eeb3b072");
        assertEquals(Hasher.fileHash(winrar.getFile(), sha256), hash);
    }

    public void sectionMD5Hashes() throws IOException {
        String[] actualHashes = { "496ecf611b45abe56f64ab3ab495faf3",
                "23f563d2bed9b8916cb8f7b69b0902de",
                "ad1f7c6cd9b9a20390018781b70fb1a3",
                "03b360092b3b19a3cf43f2c213c54d5c" };
        Hasher hasher = new Hasher(winrar);
        byte[] hash;
        int sections = winrar.getSectionTable().getNumberOfSections();
        for (int i = 1; i <= sections; i++) {
            hash = hasher.sectionHash(i, md5);
            assertEquals(ByteArrayUtil.byteToHex(hash, ""), actualHashes[i]);
        }
    }
    
    public void sectionSHA256Hashes() throws IOException {
        String[] actualHashes = { "000048859a45a60fbca06ff292250bbc0e7249f85dad368288b573e2dcdd34be",
                "6023c1b0fd34a9e2bf0e1cadc7fe762db6f2986f0094dd92bfa68f5d4dac68c5",
                "078455084d1ff6b9b2b44a940987bf79253307191de75a3a2b3cf64ef863864b",
                "57f13d22be498f7f77bd87afedc8732a550a0c7957ac3e641ef32a3dc2b0ea7e" };
        Hasher hasher = new Hasher(winrar);
        byte[] hash;
        int sections = winrar.getSectionTable().getNumberOfSections();
        for (int i = 1; i <= sections; i++) {
            hash = hasher.sectionHash(i, sha256);
            assertEquals(ByteArrayUtil.byteToHex(hash, ""), actualHashes[i]);
        }
    }
}
