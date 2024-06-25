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
package com.github.struppigel.tools;

import com.github.struppigel.parser.ByteArrayUtil;
import com.github.struppigel.parser.PEData;
import com.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.testng.Assert.assertEquals;

public class HasherTest {

    private PEData pe;
    private MessageDigest md5;
    private MessageDigest sha256;

    @BeforeClass
    public void prepare() throws IOException, NoSuchAlgorithmException {
        this.pe = PELoaderTest.getPEData().get("Lab05-01");
        md5 = MessageDigest.getInstance("MD5");
        sha256 = MessageDigest.getInstance("SHA-256");
    }

    @Test
    public void fileHashes() throws IOException, NoSuchAlgorithmException {
        Hasher hasher = new Hasher(pe);
        byte[] hash = hasher.fileHash(md5);
        assertEquals(ByteArrayUtil.byteToHex(hash, ""),
                        "1a9fd80174aafecd9a52fd908cb82637");
        assertEquals(Hasher.fileHash(pe.getFile(), md5), hash);
        hash = hasher.fileHash(sha256);
        assertEquals(ByteArrayUtil.byteToHex(hash, ""),
                "EB1079BDD96BC9CC19C38B76342113A09666AAD47518FF1A7536EEBFF8AADB4A".toLowerCase());
        assertEquals(Hasher.fileHash(pe.getFile(), sha256), hash);
    }
    @Test
    public void sectionMD5Hashes() throws IOException {
        String[] actualHashes = {
               "04d66370327b841e3f2847eaa07578ec",
               "8b0748079adebffd152ac8f9534b56fb",
               "877a17afa5144027130318eae2fac53d",
               "cefd56e5d8f3c55036f62f7570640e11",
               "3d4a5136ca116a919b2688c93f988e59",
               "1f25452db8a1049987b390b802a1919c" };
        Hasher hasher = new Hasher(pe);
        byte[] hash;
        int sections = pe.getSectionTable().getNumberOfSections();
        for (int i = 1; i <= sections; i++) {
            hash = hasher.sectionHash(i, md5);
            assertEquals(ByteArrayUtil.byteToHex(hash, ""), actualHashes[i-1].toLowerCase());
        }
    }
    @Test
    public void sectionSHA256Hashes() throws IOException {
        String[] actualHashes = {
                "46926593C1038385F419706E109CDD23D67383ED55318F8B0E0D90CAB38A3F4C",
                "97E0A32C3C843981908360F105AEF652F8990EBCFA7362377B12B7BE29371081",
                "74C32CA9D904BECB4AC6EB6965AB4B7915ABB61C231D2124F73FABB16C817AD1",
                "9E4D583F3AE38998B750037A6826537D6B1FCFDC2596A3BBB6A040D76536A63D",
                "C007F66B09B62B82DABED2E2AAC9D3ABA17A5FEA730E7AB5D4C85A3EE93CD49C",
                "34f3fff6ed7211ba16f2a8abe2295da2873be92cabea731246665941e6afc64e"};
        Hasher hasher = new Hasher(pe);
        byte[] hash;
        int sections = pe.getSectionTable().getNumberOfSections();
        for (int i = 1; i <= sections; i++) {
            hash = hasher.sectionHash(i, sha256);
            assertEquals(ByteArrayUtil.byteToHex(hash, ""), actualHashes[i-1].toLowerCase());
        }
    }
}
