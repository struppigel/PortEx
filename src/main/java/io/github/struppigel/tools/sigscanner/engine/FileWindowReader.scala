/**
 * *****************************************************************************
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
 * ****************************************************************************
 */
package io.github.struppigel.tools.sigscanner.engine

import io.github.struppigel.tools.sigscanner.pattern.ByteSource

import java.io.{Closeable, File, RandomAccessFile}

/**
 * Byte source for a file. The scanner loads windows of the file into the
 * buffer, bytes outside of the window are read through a small block cache.
 * <p>
 * Uses RandomAccessFile instead of a FileChannel, because channels are closed
 * if the thread is interrupted, and no memory mapping, because mapped files are
 * locked on Windows until the mapping is garbage collected.
 */
private[sigscanner] final class FileWindowReader(file: File) extends ByteSource with Closeable {

  private val raf = new RandomAccessFile(file, "r")

  override val size: Long = raf.length()

  private var buf = new Array[Byte](FileWindowReader.MinRead)
  private var start = 0L
  private var length = 0

  override def buffer: Array[Byte] = buf

  override def bufferStart: Long = start

  override def bufferLength: Int = length

  /**
   * Makes the range available in the buffer. Reads at least minRead bytes, so
   * that subsequent requests for nearby ranges need no I/O.
   */
  override def load(from: Long, len: Int, minRead: Int): Unit = {
    val end = math.min(size, from + len)
    if (from >= start && end <= start + length) return
    val readLen = math.min(size - from, math.max(len, minRead).toLong).toInt
    if (readLen <= 0) {
      start = from
      length = 0
      return
    }
    if (buf.length < readLen) buf = new Array[Byte](readLen)
    raf.seek(from)
    var read = 0
    while (read < readLen) {
      val r = raf.read(buf, read, readLen - read)
      if (r < 0) {
        start = from
        length = read
        return
      }
      read += r
    }
    start = from
    length = read
  }

  // block cache for random accesses outside of the window, e.g. follow targets
  private val blockSize = 4096
  private val blockCount = 8
  // most scans never read outside of the window, so the cache is created on first use
  private lazy val blocks = Array.fill(blockCount)(new Array[Byte](blockSize))
  private lazy val blockStarts = Array.fill(blockCount)(-1L)
  private lazy val blockLengths = new Array[Int](blockCount)
  private var nextBlock = 0

  override def byteAt(pos: Long): Int = {
    if (pos < 0 || pos >= size) return -1
    if (pos >= start && pos < start + length) return buf((pos - start).toInt) & 0xFF
    val blockStart = pos - pos % blockSize
    var i = 0
    while (i < blockCount) {
      if (blockStarts(i) == blockStart) return blocks(i)((pos - blockStart).toInt) & 0xFF
      i += 1
    }
    val slot = nextBlock
    nextBlock = (nextBlock + 1) % blockCount
    raf.seek(blockStart)
    val len = math.min(blockSize.toLong, size - blockStart).toInt
    var read = 0
    while (read < len) {
      val r = raf.read(blocks(slot), read, len - read)
      if (r < 0) return -1
      read += r
    }
    blockStarts(slot) = blockStart
    blockLengths(slot) = read
    blocks(slot)((pos - blockStart).toInt) & 0xFF
  }

  override def slice(from: Long, until: Long): Array[Byte] = {
    val s = math.max(0L, from)
    val e = math.min(size, until)
    if (e <= s) return Array.emptyByteArray
    val result = new Array[Byte]((e - s).toInt)
    raf.seek(s)
    raf.readFully(result)
    result
  }

  override def close(): Unit = raf.close()
}

private[sigscanner] object FileWindowReader {
  val MinRead: Int = 4096
}
