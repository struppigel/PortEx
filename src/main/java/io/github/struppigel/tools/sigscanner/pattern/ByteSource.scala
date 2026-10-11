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
package io.github.struppigel.tools.sigscanner.pattern

/**
 * Random access to the bytes a pattern is matched against, usually a file.
 * <p>
 * The current window (buffer, bufferStart, bufferLength) is read directly by
 * the matcher for speed, everything else goes through byteAt.
 */
private[sigscanner] abstract class ByteSource {

  /** number of bytes, positions from size on are outside of the source */
  def size: Long

  /** bytes of the current window */
  def buffer: Array[Byte]

  /** position of buffer(0) */
  def bufferStart: Long

  /** number of valid bytes in buffer */
  def bufferLength: Int

  /** byte at pos as value 0-255, or -1 if pos is outside of the source */
  def byteAt(pos: Long): Int

  /**
   * Makes the range available in the buffer, reading at least minRead bytes.
   * Sources that hold all bytes in the buffer do nothing.
   */
  def load(from: Long, len: Int, minRead: Int): Unit = ()

  /** copies the bytes from 'from' until 'until', clipped to the source */
  def slice(from: Long, until: Long): Array[Byte] = {
    val s = math.max(0L, from)
    val e = math.min(size, until)
    if (e <= s) return Array.emptyByteArray
    val result = new Array[Byte]((e - s).toInt)
    var i = 0
    while (i < result.length) {
      result(i) = byteAt(s + i).toByte
      i += 1
    }
    result
  }
}

/** a byte source for an in-memory array */
private[sigscanner] final class ArrayByteSource(bytes: Array[Byte]) extends ByteSource {
  override def size: Long = bytes.length
  override def buffer: Array[Byte] = bytes
  override def bufferStart: Long = 0
  override def bufferLength: Int = bytes.length
  override def byteAt(pos: Long): Int =
    if (pos >= 0 && pos < bytes.length) bytes(pos.toInt) & 0xFF else -1

  override def slice(from: Long, until: Long): Array[Byte] = {
    val s = math.max(0L, from).toInt
    val e = math.min(size, until).toInt
    if (e <= s) Array.emptyByteArray else java.util.Arrays.copyOfRange(bytes, s, e)
  }
}

/**
 * Maps file offsets to relative virtual addresses and back. Needed for the
 * follow tokens $$ and ## of patterns.
 */
private[sigscanner] trait AddressMapper {

  /** the RVA of the file offset or -1 if it is not mapped */
  def offsetToRva(offset: Long): Long

  /** the file offset of the RVA or -1 if it is not mapped */
  def rvaToOffset(rva: Long): Long

  /** the image base for absolute virtual addresses */
  def imageBase: Long
}

private[sigscanner] object AddressMapper {

  /** used for data without PE structure: addresses are file offsets */
  val Identity: AddressMapper = new AddressMapper {
    override def offsetToRva(offset: Long): Long = offset
    override def rvaToOffset(rva: Long): Long = rva
    override def imageBase: Long = 0
  }
}
