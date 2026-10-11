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

import java.io.UncheckedIOException;

/**
 * Random access to the bytes of a file.
 * <p>
 * Implementations are thread-safe. Read errors are thrown as
 * {@link UncheckedIOException}, reads from a closed source throw
 * {@link ByteSourceClosedException}.
 *
 * @author Karsten Philipp Boris Hahn
 */
public interface ByteSource {

    /**
     * @return the number of bytes
     */
    long length();

    /**
     * Reads one byte.
     *
     * @param offset the file offset
     * @return the byte value from 0 to 255, -1 if the offset is negative or
     *         not before {@link #length()}
     * @throws UncheckedIOException if the file can not be read
     * @throws ByteSourceClosedException if the source is closed
     */
    int byteAt(long offset);

    /**
     * Reads bytes into a buffer. Reads stop at the end of the source.
     *
     * @param offset the file offset to read from
     * @param buffer the buffer to read into
     * @param bufferOffset the start position in the buffer
     * @param length the maximum number of bytes to read
     * @return the number of bytes read, 0 if the offset is at or after the
     *         end of the source
     * @throws UncheckedIOException if the file can not be read
     * @throws ByteSourceClosedException if the source is closed
     * @throws IndexOutOfBoundsException if the buffer range is invalid
     * @throws IllegalArgumentException if the offset is negative
     */
    int read(long offset, byte[] buffer, int bufferOffset, int length);
}
