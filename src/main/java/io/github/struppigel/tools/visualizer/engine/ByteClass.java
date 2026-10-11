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
 * Classes of byte values as shown by a byte plot.
 *
 * @author Karsten Philipp Boris Hahn
 */
public enum ByteClass {
    /** the byte 0x00 */
    ZERO,
    /** the byte 0xFF */
    MAX,
    /** printable ASCII, 33 to 126 */
    PRINTABLE,
    /** ASCII control characters and space, 1 to 32 and 127 */
    CONTROL,
    /** bytes above ASCII, 128 to 254 */
    HIGH;

    private static final ByteClass[] VALUES = values();
    private static final byte[] CLASS_OF = new byte[256];

    static {
        for (int b = 0; b < 256; b++) {
            CLASS_OF[b] = (byte) classify(b).ordinal();
        }
    }

    private static ByteClass classify(int b) {
        if (b == 0) return ZERO;
        if (b == 0xFF) return MAX;
        if (b >= 33 && b <= 126) return PRINTABLE;
        if (b <= 127) return CONTROL;
        return HIGH;
    }

    /**
     * @param value a byte value from 0 to 255, or a signed byte
     * @return the class of the byte value
     */
    public static ByteClass of(int value) {
        return VALUES[CLASS_OF[value & 0xFF]];
    }

    /** ordinal of the class of a byte value, for hot loops */
    static int ordinalOf(int value) {
        return CLASS_OF[value & 0xFF];
    }

    /**
     * Returns whether the byte values of this class differ. ZERO and MAX have
     * one value only, so their mean value is constant.
     *
     * @return true if the class has more than one byte value
     */
    public boolean hasVaryingValues() {
        return this != ZERO && this != MAX;
    }
}
