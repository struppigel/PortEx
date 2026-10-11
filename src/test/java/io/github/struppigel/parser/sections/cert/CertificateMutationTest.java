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

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.optheader.DataDirEntry;
import io.github.struppigel.parser.optheader.DataDirectoryKey;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.tools.ReportCreator;
import io.github.struppigel.tools.anomalies.PEAnomalyScanner;
import io.github.struppigel.tools.layout.Detail;
import io.github.struppigel.tools.layout.StructureMapBuilder;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Random;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.github.struppigel.parser.sections.cert.CertificateIssueType.*;
import static io.github.struppigel.parser.sections.cert.TestSigner.putLe32;
import static org.testng.Assert.*;

/**
 * Mutates the certificate tables of signed files: broken sizes and offsets,
 * appended and hidden data, truncation, and random byte flips. Parsing and
 * verifying must never throw and must report the manipulation.
 *
 * @author Karsten Philipp Boris Hahn
 */
public class CertificateMutationTest {

    private static final File STRINGS = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/strings.exe");
    private static final File STANDARD = new File(TestreportsReader.RESOURCE_DIR + "/corkami/standard.exe");

    private Path dir;
    private byte[] strings;
    private long tableOffset;
    private long tableSize;
    private long entryOffset;
    private long sizeOfHeaders;

    @BeforeClass
    public void prepare() throws IOException {
        dir = Files.createTempDirectory("portex-certificate-mutations");
        strings = Files.readAllBytes(STRINGS.toPath());
        PEData data = PELoader.loadPE(STRINGS);
        DataDirEntry entry = data.getOptionalHeader().maybeGetDataDirEntry(DataDirectoryKey.CERTIFICATE_TABLE).get();
        tableOffset = entry.getVirtualAddress();
        tableSize = entry.getDirectorySize();
        entryOffset = entry.getTableEntryOffset();
        sizeOfHeaders = data.getOptionalHeader().get(WindowsEntryKey.SIZE_OF_HEADERS);
    }

    @AfterClass(alwaysRun = true)
    public void deleteDirectory() throws IOException {
        try (Stream<Path> files = Files.walk(dir)) {
            for (Path p : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                Files.deleteIfExists(p);
            }
        }
    }

    /** the result of parsing and verifying a mutated file */
    private static final class Result {
        private final CertificateTable table;
        private final AuthenticodeVerification verification;
        private final Set<CertificateIssueType> issues;

        private Result(CertificateTable table, AuthenticodeVerification verification) {
            this.table = table;
            this.verification = verification;
            this.issues = Stream.concat(table.getIssues().stream(), verification.getIssues().stream())
                    .map(CertificateIssue::getType).collect(Collectors.toSet());
        }

        private VerificationStatus imageDigest() {
            return verification.getPrimaryResult().get().getImageDigestStatus();
        }
    }

    private File write(byte[] bytes) throws IOException {
        File f = Files.createTempFile(dir, "mutated-", ".exe").toFile();
        Files.write(f.toPath(), bytes);
        return f;
    }

    private Result mutate(Consumer<byte[]> mutation) throws IOException {
        byte[] copy = Arrays.copyOf(strings, strings.length);
        mutation.accept(copy);
        return analyze(write(copy));
    }

    private static Result analyze(File file) throws IOException {
        PEData data = PELoader.loadPE(file);
        CertificateTable table = CertificateTable.load(data);
        return new Result(table, AuthenticodeVerifier.verify(data, table));
    }

    @Test
    public void invalidEntryLengths() throws IOException {
        for (long length : new long[]{0, 7, 0xffffffffL, tableSize + 1}) {
            Result r = mutate(b -> putLe32(b, (int) tableOffset, length));
            assertTrue(r.issues.contains(INVALID_LENGTH), length + ": " + r.issues);
            assertEquals(r.table.getEntries().size(), 1);
        }
    }

    @Test
    public void invalidDirectorySizes() throws IOException {
        Result zero = mutate(b -> putLe32(b, (int) entryOffset + 4, 0));
        assertTrue(zero.issues.contains(DIR_TOO_SMALL), zero.issues.toString());
        Result seven = mutate(b -> putLe32(b, (int) entryOffset + 4, 7));
        assertTrue(seven.issues.contains(DIR_TOO_SMALL), seven.issues.toString());
        for (long size : new long[]{0x7fffffffL, 0xffffffffL}) {
            Result r = mutate(b -> putLe32(b, (int) entryOffset + 4, size));
            assertTrue(r.issues.contains(DIR_SIZE_EXCEEDS_FILE), r.issues.toString());
            assertTrue(r.issues.contains(TABLE_TRUNCATED), r.issues.toString());
        }
        Result beyond = mutate(b -> putLe32(b, (int) entryOffset, 0xfffffff8L));
        assertTrue(beyond.issues.contains(TABLE_BEYOND_EOF), beyond.issues.toString());
        assertTrue(beyond.table.isEmpty());
    }

    @Test
    public void dataHiddenInTheEntry() throws IOException {
        // CVE-2013-3900: data appended to the signature; the image digest stays valid
        byte[] hidden = new byte[64];
        Arrays.fill(hidden, (byte) 0x41);
        byte[] bytes = concat(strings, hidden);
        putLe32(bytes, (int) tableOffset, tableSize + hidden.length);
        putLe32(bytes, (int) entryOffset + 4, tableSize + hidden.length);
        Result r = analyze(write(bytes));
        assertTrue(r.issues.contains(DATA_AFTER_PKCS7), r.issues.toString());
        assertEquals(r.imageDigest(), VerificationStatus.VALID);
        assertEquals(r.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void nonZeroPadding() throws IOException {
        Result r = mutate(b -> b[(int) (tableOffset + tableSize - 1)] = 1);
        assertTrue(r.issues.contains(NONZERO_PADDING), r.issues.toString());
        assertEquals(r.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void dataAfterTheTable() throws IOException {
        Result r = analyze(write(concat(strings, new byte[16])));
        assertTrue(r.issues.contains(TABLE_NOT_LAST), r.issues.toString());
        assertTrue(r.issues.contains(IMAGE_DIGEST_MISMATCH), r.issues.toString());
        assertEquals(r.verification.getStatus(), VerificationStatus.INVALID);
    }

    @Test
    public void duplicatedEntry() throws IOException {
        byte[] entry = Arrays.copyOfRange(strings, (int) tableOffset, (int) (tableOffset + tableSize));
        byte[] bytes = concat(strings, entry);
        putLe32(bytes, (int) entryOffset + 4, tableSize * 2);
        Result r = analyze(write(bytes));
        assertTrue(r.issues.contains(MULTIPLE_ENTRIES), r.issues.toString());
        assertEquals(r.table.getEntries().size(), 2);
        assertEquals(r.table.getSignatures().size(), 2);
        assertEquals(r.verification.getStatus(), VerificationStatus.VALID);
    }

    @Test
    public void extraDataInTheTable() throws IOException {
        byte[] bytes = concat(strings, new byte[64]);
        putLe32(bytes, (int) entryOffset + 4, tableSize + 64);
        Result r = analyze(write(bytes));
        assertTrue(r.issues.contains(TABLE_EXTRA_DATA), r.issues.toString());
        assertFalse(r.issues.contains(MULTIPLE_ENTRIES));
    }

    @Test
    public void truncatedTable() throws IOException {
        Result r = analyze(write(Arrays.copyOf(strings, (int) tableOffset + 100)));
        assertTrue(r.issues.contains(TABLE_TRUNCATED), r.issues.toString());
        assertTrue(r.issues.contains(MALFORMED_PKCS7), r.issues.toString());
        assertTrue(r.table.getEntries().get(0).isTruncated());
        assertFalse(r.table.getPrimarySignature().isPresent());
    }

    @Test
    public void modifiedCode() throws IOException {
        Result r = mutate(b -> b[(int) sizeOfHeaders + 0x10] ^= 0x55);
        assertEquals(r.imageDigest(), VerificationStatus.INVALID);
        assertTrue(r.issues.contains(IMAGE_DIGEST_MISMATCH));
    }

    @Test
    public void shiftedPointer() throws IOException {
        Result r = mutate(b -> putLe32(b, (int) entryOffset, tableOffset + 0x400));
        assertTrue(r.issues.contains(TABLE_MISPLACED), r.issues.toString());
        CertificateIssue misplaced = r.table.getIssues().stream().filter(i -> i.getType() == TABLE_MISPLACED)
                .findFirst().get();
        assertEquals(misplaced.getLocations().get(0).from(), tableOffset);
    }

    @Test
    public void randomByteFlipsNeverThrow() throws IOException {
        Random random = new Random(0x5EEDCE27L);
        byte[] standard = Files.readAllBytes(STANDARD.toPath());
        long start = System.nanoTime();
        fuzz(standard, 0x2200, 0x880, 1000, random, false);
        fuzz(strings, (int) tableOffset, (int) tableSize, 200, random, true);
        assertTrue(System.nanoTime() - start < 120_000_000_000L, "fuzzing took too long");
    }

    private void fuzz(byte[] original, int from, int size, int iterations, Random random, boolean verify)
            throws IOException {
        File file = Files.createTempFile(dir, "fuzz-", ".exe").toFile();
        for (int i = 0; i < iterations; i++) {
            byte[] copy = Arrays.copyOf(original, original.length);
            int flips = 1 + random.nextInt(8);
            for (int f = 0; f < flips; f++) {
                copy[from + random.nextInt(size)] = (byte) random.nextInt(256);
            }
            Files.write(file.toPath(), copy);
            long start = System.nanoTime();
            try {
                PEData data = PELoader.loadPE(file);
                CertificateTable table = CertificateTable.load(data);
                table.getInfo();
                if (verify || i % 10 == 0) {
                    AuthenticodeVerifier.verify(data, table);
                }
                if (i % 50 == 0) {
                    PEAnomalyScanner.newInstance(data).getAnomalies();
                    new StructureMapBuilder(data).withDetail(Detail.FINE).build();
                    new ReportCreator(data).authenticodeReport();
                }
            } catch (Throwable t) {
                throw new AssertionError("iteration " + i + " failed", t);
            }
            assertTrue(System.nanoTime() - start < 2_000_000_000L, "iteration " + i + " took too long");
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
