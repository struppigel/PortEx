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
 * Statistics of a file range, filled by
 * {@link ByteStatistics#aggregate(long, long, ByteStats)}.
 * <p>
 * Instances are reused to avoid allocations and are not thread-safe. Use one
 * instance per thread.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class ByteStats {

    private static final int CLASSES = ByteClass.values().length;

    long byteCount;
    double meanEntropy;
    double maxEntropy;
    final double[] fraction = new double[CLASSES];
    final double[] meanValue = new double[CLASSES];

    /** resets all values to an empty range */
    void clear() {
        byteCount = 0;
        meanEntropy = 0;
        maxEntropy = 0;
        for (int i = 0; i < CLASSES; i++) {
            fraction[i] = 0;
            meanValue[i] = 0;
        }
        meanValue[ByteClass.MAX.ordinal()] = 0xFF;
    }

    /**
     * @return the number of bytes the statistics cover, 0 for an empty range
     */
    public long getByteCount() {
        return byteCount;
    }

    /**
     * @return true if the statistics cover no bytes
     */
    public boolean isEmpty() {
        return byteCount == 0;
    }

    /**
     * Returns the mean entropy of the 256 byte windows of the range, from 0
     * to 1. The entropy is normalized like
     * {@link io.github.struppigel.tools.ShannonEntropy#entropy(byte[])}.
     *
     * @return the mean entropy
     */
    public double getMeanEntropy() {
        return meanEntropy;
    }

    /**
     * @return the highest entropy of a 256 byte window in the range, from 0 to 1
     */
    public double getMaxEntropy() {
        return maxEntropy;
    }

    /**
     * @param byteClass the byte class
     * @return the fraction of bytes of the class, from 0 to 1
     */
    public double getFraction(ByteClass byteClass) {
        return fraction[byteClass.ordinal()];
    }

    /**
     * @param byteClass the byte class
     * @return the mean value of the bytes of the class, 0 if the class does
     *         not occur
     */
    public double getMeanValue(ByteClass byteClass) {
        return meanValue[byteClass.ordinal()];
    }

    /**
     * Returns the class with the highest fraction. Ties go to the class that
     * comes first in {@link ByteClass}.
     *
     * @return the dominant class, ZERO for an empty range
     */
    public ByteClass getDominantClass() {
        int best = 0;
        for (int i = 1; i < CLASSES; i++) {
            if (fraction[i] > fraction[best]) {
                best = i;
            }
        }
        return ByteClass.values()[best];
    }

    /**
     * @param other the statistics to copy
     */
    public void copyFrom(ByteStats other) {
        byteCount = other.byteCount;
        meanEntropy = other.meanEntropy;
        maxEntropy = other.maxEntropy;
        System.arraycopy(other.fraction, 0, fraction, 0, CLASSES);
        System.arraycopy(other.meanValue, 0, meanValue, 0, CLASSES);
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("bytes=").append(byteCount).append(", entropy=").append(String.format("%.3f", meanEntropy))
                .append(", max=").append(String.format("%.3f", maxEntropy));
        for (ByteClass c : ByteClass.values()) {
            b.append(", ").append(c).append('=').append(String.format("%.3f", fraction[c.ordinal()]));
        }
        return b.toString();
    }
}
