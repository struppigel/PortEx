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

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static org.testng.Assert.*;

public class CachedByteSourceTest {

    private File file;
    private byte[] content;

    @BeforeClass
    public void createFile() throws IOException {
        content = new byte[10_000];
        new Random(11).nextBytes(content);
        file = File.createTempFile("portex-bytesource", ".bin");
        file.deleteOnExit();
        Files.write(file.toPath(), content);
    }

    @AfterClass
    public void deleteFile() {
        file.delete();
    }

    @Test
    public void readsAcrossPageBoundaries() throws IOException {
        try (CachedByteSource source = new CachedByteSource(file, 16, 2)) {
            assertEquals(source.length(), content.length);
            Random random = new Random(12);
            for (int i = 0; i < 2000; i++) {
                int offset = random.nextInt(content.length);
                int length = random.nextInt(100);
                byte[] buffer = new byte[length + 3];
                int read = source.read(offset, buffer, 3, length);
                int expected = Math.min(length, content.length - offset);
                assertEquals(read, expected);
                assertEquals(Arrays.copyOfRange(buffer, 3, 3 + read),
                        Arrays.copyOfRange(content, offset, offset + read));
                assertEquals(source.byteAt(offset), content[offset] & 0xFF);
            }
        }
    }

    @Test
    public void endOfFile() throws IOException {
        try (CachedByteSource source = new CachedByteSource(file)) {
            assertEquals(source.byteAt(content.length - 1), content[content.length - 1] & 0xFF);
            assertEquals(source.byteAt(content.length), -1);
            assertEquals(source.byteAt(-1), -1);
            byte[] buffer = new byte[10];
            assertEquals(source.read(content.length, buffer, 0, 10), 0);
            assertEquals(source.read(content.length + 100, buffer, 0, 10), 0);
            assertEquals(source.read(content.length - 4, buffer, 0, 10), 4);
        }
    }

    @Test(expectedExceptions = IndexOutOfBoundsException.class)
    public void invalidBufferRange() throws IOException {
        try (CachedByteSource source = new CachedByteSource(file)) {
            source.read(0, new byte[4], 2, 4);
        }
    }

    @Test
    public void concurrentReaders() throws Exception {
        try (final CachedByteSource source = new CachedByteSource(file, 64, 4)) {
            final AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread[] threads = new Thread[8];
            for (int t = 0; t < threads.length; t++) {
                final long seed = t;
                threads[t] = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            Random random = new Random(seed);
                            byte[] buffer = new byte[300];
                            for (int i = 0; i < 5000; i++) {
                                int offset = random.nextInt(content.length);
                                int read = source.read(offset, buffer, 0, buffer.length);
                                for (int k = 0; k < read; k++) {
                                    if (buffer[k] != content[offset + k]) {
                                        throw new AssertionError("wrong byte at " + (offset + k));
                                    }
                                }
                            }
                        } catch (Throwable e) {
                            failure.set(e);
                        }
                    }
                });
                threads[t].start();
            }
            for (Thread thread : threads) {
                thread.join();
            }
            assertNull(failure.get(), String.valueOf(failure.get()));
        }
    }

    @Test
    public void readsAfterCloseFail() throws IOException {
        CachedByteSource source = new CachedByteSource(file);
        source.byteAt(5);
        source.close();
        source.close(); // closing twice is fine
        assertTrue(source.isClosed());
        try {
            source.byteAt(5);
            fail("expected ByteSourceClosedException");
        } catch (ByteSourceClosedException expected) {
        }
        try {
            source.read(0, new byte[4], 0, 4);
            fail("expected ByteSourceClosedException");
        } catch (ByteSourceClosedException expected) {
        }
    }

    @Test
    public void survivesInterrupts() throws IOException {
        try (CachedByteSource source = new CachedByteSource(file, 16, 2)) {
            Thread.currentThread().interrupt();
            try {
                assertEquals(source.byteAt(1000), content[1000] & 0xFF);
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
            // the source still works after the interrupt
            assertEquals(source.byteAt(2000), content[2000] & 0xFF);
        }
    }
}
