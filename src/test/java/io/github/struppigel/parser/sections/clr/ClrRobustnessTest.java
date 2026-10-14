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
package io.github.struppigel.parser.sections.clr;

import io.github.struppigel.TestreportsReader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.sections.SectionLoader;
import io.github.struppigel.tools.anomalies.PEAnomalyScanner;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.util.Random;
import java.util.function.Consumer;

import static io.github.struppigel.parser.sections.clr.ClrMutator.getLe;
import static io.github.struppigel.parser.sections.clr.ClrMutator.putLe;

/**
 * Malformed metadata must never throw or hang, parsing and anomaly scanning
 * have to survive every mutation of the #~ stream header and the CLI header.
 */
public class ClrRobustnessTest {

    private static final File HELLO = new File(TestreportsReader.RESOURCE_DIR + "/testfiles/HelloWorld.exe");
    private static final long TIME_OUT = 60_000;

    private ClrMutator mutator;

    @BeforeClass
    public void prepare() throws IOException {
        mutator = new ClrMutator(HELLO);
    }

    @AfterClass(alwaysRun = true)
    public void cleanup() throws IOException {
        mutator.delete();
    }

    private void assertSurvives(Consumer<byte[]> mutation) throws IOException {
        PEData data = mutator.mutate(mutation);
        new SectionLoader(data).maybeLoadCLRSection();
        PEAnomalyScanner.newInstance(data).getAnomalies();
    }

    @Test(timeOut = TIME_OUT)
    public void undefinedTableBitInValid() throws IOException {
        // 0x03 is FieldPtr, 0x2D lies above the last table of the specification
        for (int bit : new int[]{0x03, 0x05, 0x13, 0x1E, 0x2D, 0x30, 0x3F}) {
            assertSurvives(b -> putLe(b, mutator.tablesStreamValid(),
                    getLe(b, mutator.tablesStreamValid(), 8) | (1L << bit), 8));
        }
    }

    @Test(timeOut = TIME_OUT)
    public void validWithAllBitsSet() throws IOException {
        assertSurvives(b -> putLe(b, mutator.tablesStreamValid(), -1L, 8));
    }

    @Test(timeOut = TIME_OUT)
    public void hugeRowCounts() throws IOException {
        for (long rows : new long[]{0x7FFFFFFFL, 0xFFFFFFFFL, 0x01000000L, 0x00FFFFFFL, 0x10000L}) {
            assertSurvives(b -> putLe(b, mutator.tablesStreamFirstRowCount(), rows, 4));
        }
    }

    @Test(timeOut = TIME_OUT)
    public void heapSizesInconsistentWithHeaps() throws IOException {
        for (long sizes : new long[]{0x01, 0x02, 0x04, 0x07, 0x08, 0x40, 0xFF}) {
            assertSurvives(b -> putLe(b, mutator.tablesStream() + 6, sizes, 1));
        }
    }

    @Test(timeOut = TIME_OUT)
    public void streamsBeyondTheMetadata() throws IOException {
        for (String name : new String[]{"#~", "#Strings", "#Blob", "#GUID"}) {
            long header = mutator.streamHeader(name);
            assertSurvives(b -> putLe(b, header, 0xFFFFFFF0L, 4));
            assertSurvives(b -> putLe(b, header + 4, 0xFFFFFFF0L, 4));
            assertSurvives(b -> putLe(b, header + 4, 0, 4));
        }
    }

    @Test(timeOut = TIME_OUT)
    public void metadataDirectoryOutOfRange() throws IOException {
        for (CLIHeaderKey key : new CLIHeaderKey[]{CLIHeaderKey.META_DATA_RVA, CLIHeaderKey.META_DATA_SIZE}) {
            for (long value : new long[]{0, 1, 0x7FFFFFFFL, 0xFFFFFFFFL}) {
                assertSurvives(b -> putLe(b, mutator.cliHeaderField(key), value, 4));
            }
        }
    }

    @Test(timeOut = TIME_OUT)
    public void randomFlipsInTheTablesStreamHeader() throws IOException {
        Random random = new Random(0x5EED);
        long start = mutator.tablesStream();
        for (int i = 0; i < 300; i++) {
            int flips = 1 + random.nextInt(4);
            long[] offsets = new long[flips];
            int[] values = new int[flips];
            for (int f = 0; f < flips; f++) {
                offsets[f] = start + random.nextInt(24 + 4 * 8);
                values[f] = random.nextInt(256);
            }
            assertSurvives(b -> {
                for (int f = 0; f < offsets.length; f++) {
                    b[(int) offsets[f]] = (byte) values[f];
                }
            });
        }
    }
}
