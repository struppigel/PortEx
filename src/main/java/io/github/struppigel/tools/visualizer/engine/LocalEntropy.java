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

/**
 * Entropy of small cells computed from the bytes.
 * <p>
 * Below the base block size of {@link ByteStatistics} there are no
 * precomputed statistics. For each byte, this class computes the entropy of
 * the 256 byte window centered at that byte with a sliding histogram, so a
 * range of n bytes costs O(n). The entropy of a cell is the mean of the
 * window entropies of its bytes, which matches the mean window entropy of
 * {@link ByteStatistics}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class LocalEntropy {

    private static final int WINDOW = ByteStatistics.WINDOW_SIZE;
    private static final int HALF = WINDOW / 2;
    private static final double LN_256 = Math.log(256);

    private LocalEntropy() {
    }

    /**
     * Computes the mean and maximum window entropy of consecutive cells. Cells
     * without bytes, i.e. after the end of the source, get NaN.
     *
     * @param source the bytes
     * @param from the file offset of the first cell
     * @param bytesPerCell the number of bytes of each cell
     * @param cells the number of cells
     * @param mean receives the mean entropy of each cell, from 0 to 1
     * @param max receives the maximum entropy of each cell, may be null
     */
    public static void compute(ByteSource source, long from, int bytesPerCell, int cells, double[] mean,
                               double[] max) {
        if (bytesPerCell <= 0 || cells < 0 || from < 0) {
            throw new IllegalArgumentException("invalid cells");
        }
        long length = source.length();
        long end = Math.min(length, from + (long) bytesPerCell * cells);
        for (int i = 0; i < cells; i++) {
            mean[i] = Double.NaN;
            if (max != null) max[i] = Double.NaN;
        }
        if (end <= from) {
            return;
        }
        long readFrom = Math.max(0, from - HALF);
        long readTo = Math.min(length, end + HALF);
        byte[] bytes = new byte[(int) (readTo - readFrom)];
        int read = source.read(readFrom, bytes, 0, bytes.length);
        readTo = readFrom + read;
        end = Math.min(end, readTo);

        int[] histogram = new int[256];
        double cLnC = 0;
        // window of the first byte
        long low = Math.max(0, from - HALF);
        long high = Math.min(readTo, from + HALF);
        for (long p = low; p < high; p++) {
            int b = bytes[(int) (p - readFrom)] & 0xFF;
            int c = histogram[b]++;
            cLnC += ByteStatistics.C_LN_C[c + 1] - ByteStatistics.C_LN_C[c];
        }
        int cell = 0;
        int inCell = 0;
        double sum = 0;
        double cellMax = 0;
        for (long p = from; p < end; p++) {
            // move the window to [p - HALF, p + HALF)
            long newLow = Math.max(0, p - HALF);
            long newHigh = Math.min(readTo, p + HALF);
            for (; low < newLow; low++) {
                int b = bytes[(int) (low - readFrom)] & 0xFF;
                int c = histogram[b]--;
                cLnC += ByteStatistics.C_LN_C[c - 1] - ByteStatistics.C_LN_C[c];
            }
            for (; high < newHigh; high++) {
                int b = bytes[(int) (high - readFrom)] & 0xFF;
                int c = histogram[b]++;
                cLnC += ByteStatistics.C_LN_C[c + 1] - ByteStatistics.C_LN_C[c];
            }
            int n = (int) (high - low);
            double entropy = n <= 1 ? 0 : (ByteStatistics.LN[n] - cLnC / n) / LN_256;
            if (entropy < 0) {
                entropy = 0;
            }
            sum += entropy;
            cellMax = Math.max(cellMax, entropy);
            if (++inCell == bytesPerCell || p == end - 1) {
                mean[cell] = sum / inCell;
                if (max != null) max[cell] = cellMax;
                cell++;
                inCell = 0;
                sum = 0;
                cellMax = 0;
            }
        }
    }
}
