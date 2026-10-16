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
package io.github.struppigel.tools;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.ByteArrayUtil;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PELoaderTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

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
    public void fileHashOfAnEmptyFile() throws IOException {
        File empty = File.createTempFile("portex-hasher-empty", ".bin");
        try {
            assertEquals(ByteArrayUtil.byteToHex(Hasher.fileHash(empty, md5), ""),
                    "d41d8cd98f00b204e9800998ecf8427e");
        } finally {
            empty.delete();
        }
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

    @Test
    public void authentihashEqualsVerification() throws Exception {
        for (String path : new String[]{"testfiles/strings.exe", "testfiles/invalidCodeView"}) {
            PEData data = load(path);
            Map<String, String> computed = data.loadAuthenticodeVerification().get().getComputedImageDigests();
            assertFalse(computed.isEmpty(), path);
            for (Map.Entry<String, String> e : computed.entrySet()) {
                assertEquals(authentihash(data, e.getKey()), e.getValue(), path + " " + e.getKey());
            }
        }
        // the nested signature uses SHA-256, the outer one SHA-1
        assertEquals(load("testfiles/invalidCodeView").loadAuthenticodeVerification().get()
                .getComputedImageDigests().keySet(), new HashSet<>(Arrays.asList("SHA-1", "SHA-256")));
    }

    @Test
    public void authentihashMatchesWindows() throws Exception {
        // computed by Windows with CryptCATAdminCalcHashFromFileHandle2 (wintrust.dll)
        String[][] expected = {
                // unsigned
                {"Haus/TLSCallback_x86.exe", "SHA-1", "4546c11743b919ce740d40de71369493ae1dde46"},
                {"Haus/TLSCallback_x86.exe", "SHA-256", "e19d66374999571c4ebc83d955c8e7f9eee29bc0a81691f24ade29abb50c6b89"},
                // signed with SHA-1 only
                {"Haus/firefox_x64.exe", "SHA-256", "a93a93d09327cd14b17adc0e622abbb0654508839a459b900b07acbf115f3d1f"},
                {"testfiles/strings.exe", "SHA-1", "21d20aa697faf24d3a9d37f9540de5fdce6f25fa"},
                {"testfiles/strings.exe", "SHA-256", "0c2ed54fb700c468e7f8f90f3cb4221561913143195b0fae877277558ff7f38a"},
                // fewer than 5 data directories: Windows still excludes the bytes of the certificate table entry
                {"corkami/no_dd.exe", "SHA-256", "a52bb1ba33452dd347f21b610eaa825a6caf46fa7951f058301f697be1deaae8"},
                {"corkami/no_dd64.exe", "SHA-256", "0af8a88dea405256a2e2fef348275cd02ddbc4dae63091387be561a19bea4011"},
                {"corkami/lowaldiff.exe", "SHA-256", "d8104a8bb5e18ac127a82c09ac1bfa7a03703d8a0f05431bc44de3a7a3ac6e28"},
        };
        for (String[] e : expected) {
            assertEquals(authentihash(load(e[0]), e[1]), e[2], e[0] + " " + e[1]);
        }
    }

    @Test
    public void authentihashOfBrokenTables() throws Exception {
        for (String path : new String[]{"ose", "Haus/cff-chrome_elf.dll", "corkami/maxvals.exe"}) {
            PEData data = load(path);
            String hash = authentihash(data, "SHA-256");
            assertEquals(hash.length(), 64, path);
            assertEquals(authentihash(data, "SHA-256"), hash, path);
        }
    }

    private static PEData load(String path) throws IOException {
        return PELoader.loadPE(new File(TestreportsReader.RESOURCE_DIR + "/" + path));
    }

    private static String authentihash(PEData data, String algorithm) throws Exception {
        return ByteArrayUtil.byteToHex(new Hasher(data).authentihash(MessageDigest.getInstance(algorithm)), "");
    }
}
