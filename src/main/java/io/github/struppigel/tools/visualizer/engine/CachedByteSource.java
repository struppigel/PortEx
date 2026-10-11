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

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A {@link ByteSource} that keeps recently read pages of a file in memory.
 * <p>
 * Pages of 64 KB are kept in a least recently used cache of 64 pages (4 MB).
 * The source is thread-safe and can be shared, e.g. by tile renderers and a
 * hex view.
 * <p>
 * The file is read with {@link RandomAccessFile}. Unlike file channels, it is
 * not closed when a reading thread is interrupted, so cancelling one task does
 * not break the source for others. Close the source when the file is no longer
 * shown; later reads throw {@link ByteSourceClosedException}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class CachedByteSource implements ByteSource, AutoCloseable {

    /** default page size in bytes */
    public static final int DEFAULT_PAGE_SIZE = 64 * 1024;
    /** default number of cached pages */
    public static final int DEFAULT_MAX_PAGES = 64;

    private final File file;
    private final long length;
    private final int pageSize;
    private final RandomAccessFile raf;
    private final Map<Long, byte[]> pages;
    private boolean closed = false;

    /**
     * Opens a file with the default page size and cache size.
     *
     * @param file the file to read
     * @throws IOException if the file can not be opened
     */
    public CachedByteSource(File file) throws IOException {
        this(file, DEFAULT_PAGE_SIZE, DEFAULT_MAX_PAGES);
    }

    /**
     * Opens a file.
     *
     * @param file the file to read
     * @param pageSize the size of a cached page in bytes
     * @param maxPages the maximum number of cached pages
     * @throws IOException if the file can not be opened
     */
    public CachedByteSource(File file, int pageSize, final int maxPages) throws IOException {
        if (pageSize <= 0 || maxPages <= 0) {
            throw new IllegalArgumentException("page size and number of pages must be positive");
        }
        this.file = file;
        this.raf = new RandomAccessFile(file, "r");
        this.length = raf.length();
        this.pageSize = pageSize;
        this.pages = new LinkedHashMap<Long, byte[]>(maxPages * 2, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<Long, byte[]> eldest) {
                return size() > maxPages;
            }
        };
    }

    /**
     * @return the file this source reads
     */
    public File getFile() {
        return file;
    }

    @Override
    public long length() {
        return length;
    }

    @Override
    public int byteAt(long offset) {
        if (offset < 0 || offset >= length) {
            checkOpen();
            return -1;
        }
        byte[] page = page(offset / pageSize);
        return page[(int) (offset % pageSize)] & 0xFF;
    }

    @Override
    public int read(long offset, byte[] buffer, int bufferOffset, int count) {
        if (offset < 0) {
            throw new IllegalArgumentException("negative offset " + offset);
        }
        if (bufferOffset < 0 || count < 0 || bufferOffset + count > buffer.length) {
            throw new IndexOutOfBoundsException("invalid buffer range " + bufferOffset + "+" + count);
        }
        checkOpen();
        long end = Math.min(length, offset + count);
        int read = 0;
        long position = offset;
        while (position < end) {
            long pageNumber = position / pageSize;
            int inPage = (int) (position % pageSize);
            byte[] page = page(pageNumber);
            int n = (int) Math.min(page.length - inPage, end - position);
            System.arraycopy(page, inPage, buffer, bufferOffset + read, n);
            read += n;
            position += n;
        }
        return read;
    }

    private synchronized byte[] page(long pageNumber) {
        checkOpen();
        byte[] page = pages.get(pageNumber);
        if (page == null) {
            long start = pageNumber * pageSize;
            int size = (int) Math.min(pageSize, length - start);
            page = new byte[size];
            try {
                raf.seek(start);
                raf.readFully(page);
            } catch (IOException e) {
                throw new UncheckedIOException("could not read " + file.getName() + " at " + start, e);
            }
            pages.put(pageNumber, page);
        }
        return page;
    }

    private synchronized void checkOpen() {
        if (closed) {
            throw new ByteSourceClosedException("byte source of " + file.getName() + " is closed");
        }
    }

    /**
     * @return true if the source was closed
     */
    public synchronized boolean isClosed() {
        return closed;
    }

    /**
     * Closes the file and drops the cache. Closing twice has no effect.
     *
     * @throws IOException if the file can not be closed
     */
    @Override
    public synchronized void close() throws IOException {
        if (!closed) {
            closed = true;
            pages.clear();
            raf.close();
        }
    }
}
