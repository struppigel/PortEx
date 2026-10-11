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

import io.github.struppigel.parser.AnalysisInterruptedException;
import io.github.struppigel.parser.Interruption;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Entropy and byte class statistics of a file that can be aggregated for any
 * range.
 * <p>
 * {@link #compute(ProgressListener)} reads the file once. It splits the file
 * into base blocks of {@link #getBlockSize()} bytes, at least 256, so that a
 * file has at most about 2^20 base blocks. For each block it stores the mean
 * and the maximum entropy of its 256 byte windows, the fraction of each
 * {@link ByteClass} and the mean value of each class. A pyramid of nodes, each
 * covering two nodes of the level below, holds the same statistics for larger
 * ranges. {@link #aggregate(long, long, ByteStats)} combines O(log n) nodes for
 * any range, weighting the blocks at the edges by their overlap with the range.
 * <p>
 * The mean entropy is the mean of the entropies of 256 byte windows. It
 * aggregates exactly, so a color means the same at every zoom level. The
 * maximum shows small packed or encrypted parts at coarse zoom levels. Use
 * {@link io.github.struppigel.tools.ShannonEntropy#entropy(File, long, long)}
 * for the exact entropy of a selected range.
 * <p>
 * Threads: compute runs on one thread. While it runs, other threads can call
 * {@link #aggregate(long, long, ByteStats)} and {@link #getComputedLength()};
 * aggregate only uses the computed prefix of the file. Memory is about 22
 * bytes per base block, i.e. at most about 24 MB, and is allocated by compute.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class ByteStatistics {

    /** the size of the windows the entropy is computed for */
    public static final int WINDOW_SIZE = 256;
    private static final int MAX_BLOCKS_LOG2 = 20;
    private static final int BUFFER_SIZE = 1 << 20;
    private static final int CLASSES = ByteClass.values().length;
    /** index of the first class with varying values, see ByteClass */
    private static final int FIRST_VARYING = ByteClass.PRINTABLE.ordinal();
    private static final double LN_256 = Math.log(256);
    /** c * ln(c) for counts up to the window size */
    static final double[] C_LN_C = new double[WINDOW_SIZE + 1];
    /** ln(n) for window sizes up to the window size */
    static final double[] LN = new double[WINDOW_SIZE + 1];

    static {
        for (int c = 1; c <= WINDOW_SIZE; c++) {
            C_LN_C[c] = c * Math.log(c);
            LN[c] = Math.log(c);
        }
    }

    private final File file;
    private final long length;
    private final long blockSize;
    private final int blockCount;
    /** allocated by compute, published by the volatile write of computedLength */
    private Level[] levels;
    private volatile long computedLength = 0;
    private boolean complete = false;

    /** quantized statistics of the nodes of one pyramid level */
    private static final class Level {
        final long nodeSize;
        final int count;
        final char[] meanEntropy;
        final byte[] maxEntropy;
        final byte[][] fraction = new byte[CLASSES][];
        final byte[][] meanValue = new byte[CLASSES - FIRST_VARYING][];

        Level(long nodeSize, int count) {
            this.nodeSize = nodeSize;
            this.count = count;
            this.meanEntropy = new char[count];
            this.maxEntropy = new byte[count];
            for (int c = 0; c < CLASSES; c++) {
                fraction[c] = new byte[count];
            }
            for (int v = 0; v < meanValue.length; v++) {
                meanValue[v] = new byte[count];
            }
        }
    }

    /** exact sums of an open node while computing */
    private static final class Sums {
        long bytes;
        double entropySum;
        double maxEntropy;
        final long[] classCount = new long[CLASSES];
        final long[] valueSum = new long[CLASSES];

        void add(Sums other) {
            bytes += other.bytes;
            entropySum += other.entropySum;
            maxEntropy = Math.max(maxEntropy, other.maxEntropy);
            for (int c = 0; c < CLASSES; c++) {
                classCount[c] += other.classCount[c];
                valueSum[c] += other.valueSum[c];
            }
        }

        void clear() {
            bytes = 0;
            entropySum = 0;
            maxEntropy = 0;
            for (int c = 0; c < CLASSES; c++) {
                classCount[c] = 0;
                valueSum[c] = 0;
            }
        }
    }

    /**
     * Prepares the statistics of a file. Call {@link #compute(ProgressListener)}
     * to fill them.
     *
     * @param file the file
     */
    public ByteStatistics(File file) {
        this(file, MAX_BLOCKS_LOG2);
    }

    /**
     * Prepares the statistics with a custom maximum number of base blocks, for
     * tests with large blocks on small files.
     */
    ByteStatistics(File file, int maxBlocksLog2) {
        this.file = file;
        this.length = file.length();
        this.blockSize = blockSizeFor(length, maxBlocksLog2);
        this.blockCount = (int) ((length + blockSize - 1) / blockSize);
        if (length == 0) {
            complete = true;
        }
    }

    /** allocates the pyramid, about 22 bytes per base block */
    private Level[] allocateLevels() {
        int levelCount = 0;
        for (int n = blockCount; n > 0; n = n == 1 ? 0 : (n + 1) / 2) {
            levelCount++;
        }
        Level[] result = new Level[levelCount];
        int n = blockCount;
        for (int k = 0; k < levelCount; k++) {
            result[k] = new Level(blockSize << k, n);
            n = (n + 1) / 2;
        }
        return result;
    }

    /**
     * Returns the base block size for a file length: a power of two of at least
     * 256 bytes, so that there are at most about 2^20 blocks.
     *
     * @param length the file length
     * @param maxBlocksLog2 log2 of the maximum number of blocks
     * @return the base block size
     */
    static long blockSizeFor(long length, int maxBlocksLog2) {
        long perBlock = (length + (1L << maxBlocksLog2) - 1) >>> maxBlocksLog2;
        long size = WINDOW_SIZE;
        while (size < perBlock) {
            size <<= 1;
        }
        return size;
    }

    /**
     * Reads the file and computes the statistics. Calling it again after it
     * completed does nothing. If it was interrupted, calling it again starts
     * over.
     *
     * @param listener receives progress after each read buffer, on this thread
     * @throws IOException if the file can not be read
     * @throws AnalysisInterruptedException if the thread is interrupted
     */
    public synchronized void compute(ProgressListener listener) throws IOException {
        if (complete) {
            listener.progress(length, length);
            return;
        }
        computedLength = 0;
        if (levels == null) {
            levels = allocateLevels();
        }
        Sums[] open = new Sums[levels.length];
        for (int k = 0; k < open.length; k++) {
            open[k] = new Sums();
        }
        byte[] buffer = new byte[(int) Math.min(BUFFER_SIZE, length)];
        int[] histogram = new int[256];
        int[] touched = new int[256];
        int touchedCount = 0;
        int inWindow = 0;
        int completedBlocks = 0;
        Sums block = open[0];
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            long position = 0;
            while (position < length) {
                Interruption.checkInterrupt();
                int toRead = (int) Math.min(buffer.length, length - position);
                raf.readFully(buffer, 0, toRead);
                for (int i = 0; i < toRead; i++) {
                    int b = buffer[i] & 0xFF;
                    if (histogram[b]++ == 0) {
                        touched[touchedCount++] = b;
                    }
                    if (++inWindow == WINDOW_SIZE) {
                        closeWindow(block, histogram, touched, touchedCount, inWindow);
                        touchedCount = 0;
                        inWindow = 0;
                        if (block.bytes == blockSize) {
                            completeNode(open, 0, completedBlocks++);
                        }
                    }
                }
                position += toRead;
                if (position < length) {
                    computedLength = completedBlocks * blockSize;
                    listener.progress(computedLength, length);
                }
            }
            if (inWindow > 0) {
                closeWindow(block, histogram, touched, touchedCount, inWindow);
            }
            if (block.bytes > 0) {
                completeNode(open, 0, completedBlocks++);
            }
        } catch (EOFException e) {
            throw new IOException("file " + file.getName() + " became shorter while reading", e);
        }
        complete = true;
        computedLength = length;
        listener.progress(length, length);
    }

    /** adds the statistics of the window in the histogram to the block and clears the histogram */
    private static void closeWindow(Sums block, int[] histogram, int[] touched, int touchedCount, int n) {
        double cLnC = 0;
        for (int t = 0; t < touchedCount; t++) {
            int b = touched[t];
            int c = histogram[b];
            histogram[b] = 0;
            cLnC += C_LN_C[c];
            int cls = ByteClass.ordinalOf(b);
            block.classCount[cls] += c;
            block.valueSum[cls] += (long) b * c;
        }
        double entropy = n <= 1 ? 0 : (LN[n] - cLnC / n) / LN_256;
        if (entropy < 0) {
            entropy = 0;
        }
        block.bytes += n;
        block.entropySum += entropy * n;
        block.maxEntropy = Math.max(block.maxEntropy, entropy);
    }

    /** stores the open node of a level and adds it to its parent, which is completed recursively */
    private void completeNode(Sums[] open, int level, int index) {
        Sums sums = open[level];
        store(levels[level], index, sums);
        if (level + 1 < levels.length) {
            open[level + 1].add(sums);
            sums.clear();
            boolean lastChild = (index & 1) == 1 || index == levels[level].count - 1;
            if (lastChild) {
                completeNode(open, level + 1, index >>> 1);
            }
        } else {
            sums.clear();
        }
    }

    private static void store(Level level, int index, Sums sums) {
        double bytes = sums.bytes;
        level.meanEntropy[index] = (char) Math.round(clamp(sums.entropySum / bytes) * 0xFFFF);
        level.maxEntropy[index] = (byte) Math.round(clamp(sums.maxEntropy) * 0xFF);
        for (int c = 0; c < CLASSES; c++) {
            level.fraction[c][index] = (byte) Math.round(sums.classCount[c] / bytes * 0xFF);
        }
        for (int c = FIRST_VARYING; c < CLASSES; c++) {
            long count = sums.classCount[c];
            level.meanValue[c - FIRST_VARYING][index] =
                    (byte) (count == 0 ? 0 : Math.round(sums.valueSum[c] / (double) count));
        }
    }

    private static double clamp(double value) {
        return value < 0 ? 0 : (value > 1 ? 1 : value);
    }

    /**
     * Aggregates the statistics of a range. Only the computed prefix of the
     * file is used, see {@link #getComputedLength()}. Blocks that overlap the
     * range partly are weighted by the overlap. Costs O(log n).
     *
     * @param from the start offset of the range
     * @param toExclusive the end offset of the range (exclusive)
     * @param out receives the statistics, empty if no computed byte is in the range
     */
    public void aggregate(long from, long toExclusive, ByteStats out) {
        out.clear();
        long done = computedLength;
        long start = Math.max(0, from);
        long end = Math.min(toExclusive, done);
        if (end <= start) {
            return;
        }
        long firstBlock = start / blockSize;
        long lastBlock = (end - 1) / blockSize;
        if (firstBlock == lastBlock) {
            addNode(out, 0, (int) firstBlock, end - start);
        } else {
            long fullFrom = firstBlock;
            if (start % blockSize != 0) {
                addNode(out, 0, (int) firstBlock, (firstBlock + 1) * blockSize - start);
                fullFrom++;
            }
            long fullTo = lastBlock + 1;
            long lastBlockEnd = Math.min((lastBlock + 1) * blockSize, length);
            if (end < lastBlockEnd) {
                addNode(out, 0, (int) lastBlock, end - lastBlock * blockSize);
                fullTo = lastBlock;
            }
            // canonical decomposition into pyramid nodes
            long low = fullFrom;
            long high = fullTo;
            int level = 0;
            while (low < high) {
                if ((low & 1) == 1) {
                    addNode(out, level, (int) low, nodeBytes(level, low));
                    low++;
                }
                if ((high & 1) == 1) {
                    high--;
                    addNode(out, level, (int) high, nodeBytes(level, high));
                }
                low >>>= 1;
                high >>>= 1;
                level++;
            }
        }
        finish(out);
    }

    private long nodeBytes(int level, long index) {
        long nodeSize = levels[level].nodeSize;
        return Math.min((index + 1) * nodeSize, length) - index * nodeSize;
    }

    /** adds a node weighted by the given number of bytes; fractions and values are summed up */
    private void addNode(ByteStats out, int levelIndex, int index, long weight) {
        Level level = levels[levelIndex];
        out.byteCount += weight;
        out.meanEntropy += level.meanEntropy[index] / (double) 0xFFFF * weight;
        out.maxEntropy = Math.max(out.maxEntropy, (level.maxEntropy[index] & 0xFF) / (double) 0xFF);
        for (int c = 0; c < CLASSES; c++) {
            double classBytes = (level.fraction[c][index] & 0xFF) / (double) 0xFF * weight;
            out.fraction[c] += classBytes;
            if (c >= FIRST_VARYING) {
                out.meanValue[c] += classBytes * (level.meanValue[c - FIRST_VARYING][index] & 0xFF);
            }
        }
    }

    /** turns the sums of addNode into means */
    private static void finish(ByteStats out) {
        double bytes = out.byteCount;
        out.meanEntropy /= bytes;
        for (int c = 0; c < CLASSES; c++) {
            if (c >= FIRST_VARYING) {
                out.meanValue[c] = out.fraction[c] > 0 ? out.meanValue[c] / out.fraction[c] : 0;
            }
            out.fraction[c] /= bytes;
        }
        out.meanValue[ByteClass.ZERO.ordinal()] = 0;
        out.meanValue[ByteClass.MAX.ordinal()] = 0xFF;
    }

    /**
     * @return the file of these statistics
     */
    public File getFile() {
        return file;
    }

    /**
     * @return the file length when these statistics were created
     */
    public long getLength() {
        return length;
    }

    /**
     * Returns the size of the base blocks. Ranges below this size are better
     * computed from the bytes, see {@link LocalEntropy}.
     *
     * @return the base block size, a power of two of at least 256
     */
    public long getBlockSize() {
        return blockSize;
    }

    /**
     * Returns the length of the file prefix whose statistics are available. It
     * grows while {@link #compute(ProgressListener)} runs and equals
     * {@link #getLength()} when it is done.
     *
     * @return the number of computed bytes from the start of the file
     */
    public long getComputedLength() {
        return computedLength;
    }

    /**
     * @return true if the statistics of the whole file are available
     */
    public boolean isComplete() {
        return computedLength == length;
    }
}
