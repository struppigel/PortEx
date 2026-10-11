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
package io.github.struppigel.tools.visualizer.engine;

import io.github.struppigel.tools.ShannonEntropy;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import static org.testng.Assert.*;

public class ByteStatisticsTest {

    private static final double ENTROPY_DELTA = 1e-4;
    /** fractions are stored with 8 bits */
    private static final double FRACTION_DELTA = 1.0 / 255 + 1e-9;

    private final List<File> files = new ArrayList<>();

    @AfterClass
    public void deleteFiles() {
        for (File file : files) {
            file.delete();
        }
    }

    /** random bytes, zero runs, 0xFF runs, ASCII text and a ramp */
    static byte[] mixedContent(int length, long seed) {
        Random random = new Random(seed);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] text = ("The quick brown fox jumps over the lazy dog.\r\n\t"
                + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ").getBytes(StandardCharsets.US_ASCII);
        while (out.size() < length) {
            int kind = random.nextInt(5);
            int run = 1 + random.nextInt(900);
            byte[] chunk = new byte[run];
            switch (kind) {
                case 0:
                    random.nextBytes(chunk);
                    break;
                case 1:
                    break; // zeros
                case 2:
                    Arrays.fill(chunk, (byte) 0xFF);
                    break;
                case 3:
                    for (int i = 0; i < run; i++) chunk[i] = text[i % text.length];
                    break;
                default:
                    for (int i = 0; i < run; i++) chunk[i] = (byte) i;
            }
            out.write(chunk, 0, chunk.length);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }

    private File write(byte[] content) throws IOException {
        File file = File.createTempFile("portex-bytestats", ".bin");
        file.deleteOnExit();
        files.add(file);
        Files.write(file.toPath(), content);
        return file;
    }

    private ByteStatistics computed(File file) throws IOException {
        ByteStatistics stats = new ByteStatistics(file);
        stats.compute(ProgressListener.NONE);
        return stats;
    }

    /** the expected statistics of a range with the documented weighting */
    private static ByteStats bruteForce(byte[] content, long blockSize, long from, long to) {
        ByteStats expected = new ByteStats();
        expected.clear();
        double bytes = 0;
        double entropy = 0;
        double max = 0;
        double[] classBytes = new double[5];
        double[] valueSum = new double[5];
        for (long blockStart = (from / blockSize) * blockSize; blockStart < to; blockStart += blockSize) {
            int blockEnd = (int) Math.min(blockStart + blockSize, content.length);
            long overlap = Math.min(to, blockEnd) - Math.max(from, blockStart);
            // block statistics from the windows of the block
            double blockEntropySum = 0;
            int[] count = new int[5];
            long[] sum = new long[5];
            for (int w = (int) blockStart; w < blockEnd; w += 256) {
                byte[] window = Arrays.copyOfRange(content, w, Math.min(w + 256, blockEnd));
                double e = ShannonEntropy.entropy(window);
                blockEntropySum += e * window.length;
                max = Math.max(max, e);
                for (byte b : window) {
                    ByteClass c = ByteClass.of(b);
                    count[c.ordinal()]++;
                    sum[c.ordinal()] += b & 0xFF;
                }
            }
            int blockBytes = (int) (blockEnd - blockStart);
            bytes += overlap;
            entropy += blockEntropySum / blockBytes * overlap;
            for (int c = 0; c < 5; c++) {
                double cb = count[c] / (double) blockBytes * overlap;
                classBytes[c] += cb;
                if (count[c] > 0) valueSum[c] += cb * sum[c] / count[c];
            }
        }
        expected.byteCount = (long) bytes;
        expected.meanEntropy = entropy / bytes;
        expected.maxEntropy = max;
        for (int c = 0; c < 5; c++) {
            expected.fraction[c] = classBytes[c] / bytes;
            expected.meanValue[c] = classBytes[c] > 0 ? valueSum[c] / classBytes[c] : 0;
        }
        expected.meanValue[ByteClass.ZERO.ordinal()] = 0;
        expected.meanValue[ByteClass.MAX.ordinal()] = 255;
        return expected;
    }

    private static void assertStats(ByteStats actual, ByteStats expected, String message) {
        assertEquals(actual.getByteCount(), expected.getByteCount(), message);
        assertEquals(actual.getMeanEntropy(), expected.getMeanEntropy(), ENTROPY_DELTA, message);
        assertEquals(actual.getMaxEntropy(), expected.getMaxEntropy(), 1.0 / 255 + 1e-9, message);
        for (ByteClass c : ByteClass.values()) {
            assertEquals(actual.getFraction(c), expected.getFraction(c), FRACTION_DELTA, message + " " + c);
            if (expected.getFraction(c) > 0.05) {
                // means are stored as rounded byte values
                assertEquals(actual.getMeanValue(c), expected.getMeanValue(c), 1.0, message + " mean " + c);
            }
        }
    }

    @Test
    public void baseBlocksMatchShannonEntropy() throws IOException {
        byte[] content = mixedContent(64 * 1024 + 77, 1);
        ByteStatistics stats = computed(write(content));
        assertEquals(stats.getBlockSize(), 256);
        ByteStats out = new ByteStats();
        for (int start = 0; start < content.length; start += 256) {
            int end = Math.min(start + 256, content.length);
            stats.aggregate(start, end, out);
            double expected = ShannonEntropy.entropy(Arrays.copyOfRange(content, start, end));
            assertEquals(out.getMeanEntropy(), expected, ENTROPY_DELTA, "block at " + start);
            assertEquals(out.getMaxEntropy(), expected, 1.0 / 255 + 1e-9);
            int[] count = new int[5];
            for (int i = start; i < end; i++) count[ByteClass.of(content[i]).ordinal()]++;
            for (ByteClass c : ByteClass.values()) {
                assertEquals(out.getFraction(c), count[c.ordinal()] / (double) (end - start), FRACTION_DELTA);
            }
        }
    }

    @Test
    public void parentsAreTheMeanOfTheirChildren() throws IOException {
        byte[] content = mixedContent(256 * 64, 2);
        ByteStatistics stats = computed(write(content));
        ByteStats parent = new ByteStats();
        ByteStats left = new ByteStats();
        ByteStats right = new ByteStats();
        for (int size = 256; size < content.length; size *= 2) {
            for (int start = 0; start + 2 * size <= content.length; start += 2 * size) {
                stats.aggregate(start, start + 2 * size, parent);
                stats.aggregate(start, start + size, left);
                stats.aggregate(start + size, start + 2 * size, right);
                assertEquals(parent.getMeanEntropy(), (left.getMeanEntropy() + right.getMeanEntropy()) / 2, ENTROPY_DELTA);
                assertEquals(parent.getMaxEntropy(), Math.max(left.getMaxEntropy(), right.getMaxEntropy()), 1.0 / 255 + 1e-9);
                for (ByteClass c : ByteClass.values()) {
                    assertEquals(parent.getFraction(c), (left.getFraction(c) + right.getFraction(c)) / 2, FRACTION_DELTA);
                }
            }
        }
    }

    @Test
    public void arbitraryRangesMatchBruteForce() throws IOException {
        Random random = new Random(3);
        for (int maxBlocksLog2 : new int[]{20, 4}) {
            byte[] content = mixedContent(100_000, 4);
            File file = write(content);
            ByteStatistics stats = new ByteStatistics(file, maxBlocksLog2);
            stats.compute(ProgressListener.NONE);
            ByteStats out = new ByteStats();
            for (int i = 0; i < 500; i++) {
                long from = random.nextInt(content.length);
                long to = from + 1 + random.nextInt(content.length - (int) from);
                stats.aggregate(from, to, out);
                assertStats(out, bruteForce(content, stats.getBlockSize(), from, to),
                        "range " + from + "-" + to + " block " + stats.getBlockSize());
            }
            stats.aggregate(0, content.length, out);
            assertStats(out, bruteForce(content, stats.getBlockSize(), 0, content.length), "whole file");
            // ranges are clipped to the file
            stats.aggregate(-100, content.length + 100, out);
            assertEquals(out.getByteCount(), content.length);
            stats.aggregate(content.length, content.length + 100, out);
            assertTrue(out.isEmpty());
        }
    }

    @Test
    public void largeBlocksAreTheMeanOfTheirWindows() throws IOException {
        byte[] content = mixedContent(64 * 1024, 5);
        ByteStatistics stats = new ByteStatistics(write(content), 4);
        stats.compute(ProgressListener.NONE);
        assertEquals(stats.getBlockSize(), 4096);
        ByteStats out = new ByteStats();
        stats.aggregate(4096, 8192, out);
        double sum = 0;
        double max = 0;
        for (int w = 4096; w < 8192; w += 256) {
            double e = ShannonEntropy.entropy(Arrays.copyOfRange(content, w, w + 256));
            sum += e;
            max = Math.max(max, e);
        }
        assertEquals(out.getMeanEntropy(), sum / 16, ENTROPY_DELTA);
        assertEquals(out.getMaxEntropy(), max, 1.0 / 255 + 1e-9);
    }

    @Test
    public void edgeLengths() throws IOException {
        for (int length : new int[]{0, 1, 255, 256, 257, 511, 513}) {
            byte[] content = mixedContent(length, length);
            ByteStatistics stats = computed(write(content));
            assertTrue(stats.isComplete());
            assertEquals(stats.getComputedLength(), length);
            ByteStats out = new ByteStats();
            stats.aggregate(0, length, out);
            assertEquals(out.getByteCount(), length);
            if (length > 0) {
                assertStats(out, bruteForce(content, 256, 0, length), "length " + length);
                stats.aggregate(length - 1, length, out);
                assertEquals(out.getByteCount(), 1);
            } else {
                assertTrue(out.isEmpty());
            }
        }
    }

    @Test
    public void uniformContent() throws IOException {
        byte[] zeros = new byte[10_000];
        ByteStatistics stats = computed(write(zeros));
        ByteStats out = new ByteStats();
        stats.aggregate(0, zeros.length, out);
        assertEquals(out.getMeanEntropy(), 0.0, 1e-9);
        assertEquals(out.getFraction(ByteClass.ZERO), 1.0, 1e-9);
        assertEquals(out.getDominantClass(), ByteClass.ZERO);

        byte[] random = new byte[1 << 16];
        new Random(9).nextBytes(random);
        stats = computed(write(random));
        stats.aggregate(0, random.length, out);
        // 256 random bytes have an entropy of about 0.9
        assertTrue(out.getMeanEntropy() > 0.85 && out.getMeanEntropy() < 0.95, "entropy " + out.getMeanEntropy());
        assertEquals(out.getDominantClass(), ByteClass.HIGH);
    }

    @Test
    public void progressIsReportedInOrder() throws IOException {
        byte[] content = mixedContent(3 * 1024 * 1024 + 5, 6);
        final ByteStatistics stats = new ByteStatistics(write(content));
        final List<Long> progress = new ArrayList<>();
        final ByteStats partial = new ByteStats();
        stats.compute(new ProgressListener() {
            @Override
            public void progress(long done, long total) {
                assertEquals(total, stats.getLength());
                assertEquals(stats.getComputedLength(), done);
                progress.add(done);
                // the computed prefix can be aggregated while computing
                stats.aggregate(0, Long.MAX_VALUE, partial);
                assertEquals(partial.getByteCount(), done);
            }
        });
        assertTrue(progress.size() >= 3, progress.toString());
        for (int i = 1; i < progress.size(); i++) {
            assertTrue(progress.get(i) >= progress.get(i - 1));
        }
        assertEquals((long) progress.get(progress.size() - 1), content.length);
        // computing again does nothing
        stats.compute(ProgressListener.NONE);
        assertTrue(stats.isComplete());
    }

    @Test
    public void notComputedYieldsEmptyStats() throws IOException {
        ByteStatistics stats = new ByteStatistics(write(mixedContent(1000, 7)));
        ByteStats out = new ByteStats();
        stats.aggregate(0, 1000, out);
        assertTrue(out.isEmpty());
        assertEquals(stats.getComputedLength(), 0);
        assertFalse(stats.isComplete());
    }

    @Test
    public void blockSizeHasAtMostAMillionBlocks() {
        assertEquals(ByteStatistics.blockSizeFor(0, 20), 256);
        assertEquals(ByteStatistics.blockSizeFor(256L << 20, 20), 256);
        assertEquals(ByteStatistics.blockSizeFor((256L << 20) + 1, 20), 512);
        assertEquals(ByteStatistics.blockSizeFor(4L << 30, 20), 4096);
        assertEquals(ByteStatistics.blockSizeFor(1L << 40, 20), 1L << 20);
    }

    @Test
    public void localEntropyMatchesBruteForce() throws IOException {
        byte[] content = mixedContent(5000, 8);
        try (CachedByteSource source = new CachedByteSource(write(content))) {
            for (int bytesPerCell : new int[]{1, 3, 16, 100}) {
                long from = 37;
                int cells = 60;
                double[] mean = new double[cells];
                double[] max = new double[cells];
                LocalEntropy.compute(source, from, bytesPerCell, cells, mean, max);
                for (int cell = 0; cell < cells; cell++) {
                    long start = from + (long) cell * bytesPerCell;
                    long end = Math.min(content.length, start + bytesPerCell);
                    if (start >= content.length) {
                        assertTrue(Double.isNaN(mean[cell]));
                        continue;
                    }
                    double sum = 0;
                    double expectedMax = 0;
                    for (long p = start; p < end; p++) {
                        int low = (int) Math.max(0, p - 128);
                        int high = (int) Math.min(content.length, p + 128);
                        double e = ShannonEntropy.entropy(Arrays.copyOfRange(content, low, high));
                        sum += e;
                        expectedMax = Math.max(expectedMax, e);
                    }
                    assertEquals(mean[cell], sum / (end - start), 1e-9, "cell " + cell + " bpc " + bytesPerCell);
                    assertEquals(max[cell], expectedMax, 1e-9);
                }
            }
            // cells after the end of the file
            double[] mean = new double[4];
            LocalEntropy.compute(source, content.length - 2, 1, 4, mean, null);
            assertFalse(Double.isNaN(mean[1]));
            assertTrue(Double.isNaN(mean[2]));
        }
    }
}
