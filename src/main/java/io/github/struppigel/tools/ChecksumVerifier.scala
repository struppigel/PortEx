/**
 * *****************************************************************************
 * Copyright 2016 Karsten Philipp Boris Hahn
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

package io.github.struppigel.tools

import io.github.struppigel.parser.{Interruption, PEData}
import io.github.struppigel.parser.ScalaIOUtil.using
import io.github.struppigel.parser.optheader.WindowsEntryKey

import java.io.{File, RandomAccessFile}
import java.nio.{ByteBuffer, ByteOrder}

/**
 * The checksum field of the Optional Header compared with the checksum of the
 * file.
 *
 * @param headerChecksum the value of the checksum field
 * @param actualChecksum the checksum computed from the file
 */
final class ChecksumCheck(val headerChecksum: Long, val actualChecksum: Long) {

  def getHeaderChecksum: Long = headerChecksum

  def getActualChecksum: Long = actualChecksum

  /**
   * @return false if the field is 0. Linkers write 0 unless asked for a
   *         checksum, the loader only checks it for drivers, DLLs loaded at
   *         boot time and DLLs loaded into critical processes.
   */
  def isSet: Boolean = headerChecksum != 0

  /** @return true if the field holds the checksum of the file */
  def isValid: Boolean = headerChecksum == actualChecksum

  /** @return true if the field is set, but differs from the checksum of the file, e.g. because the file was modified */
  def isInvalid: Boolean = isSet && !isValid

  /** @return e.g. "Checksum is invalid (0x1234), the actual checksum is 0x5678" */
  def getDescription: String =
    if (isValid) s"Checksum is valid (${hex(headerChecksum)})"
    else if (!isSet) s"Checksum is not set, the actual checksum is ${hex(actualChecksum)}"
    else s"Checksum is invalid (${hex(headerChecksum)}), the actual checksum is ${hex(actualChecksum)}"

  private def hex(value: Long): String = "0x" + java.lang.Long.toHexString(value)

  override def toString: String = getDescription
}

object ChecksumVerifier {

  /** bytes read at once, a multiple of 8 */
  private val ChunkSize = 1 << 20

  def hasValidChecksum(peData: PEData): Boolean = {
    val checksum = peData.getOptionalHeader.get(WindowsEntryKey.CHECKSUM)
    val computedChecksum = computeChecksum(peData)
    checksum == computedChecksum
  }

  /**
   * Computes the checksum of the file and compares it with the checksum field.
   * Reads the whole file, PEData.loadChecksumCheck caches the result.
   */
  def check(peData: PEData): ChecksumCheck =
    new ChecksumCheck(peData.getOptionalHeader.get(WindowsEntryKey.CHECKSUM), computeChecksum(peData))

  /**
   * Computes the checksum of the optional header: the 32 bit little endian
   * words of the file are added with end around carry, the checksum field
   * counts as zero and a last incomplete word is padded with zeros. The sum is
   * folded to 16 bits and the file size is added.
   * <p>
   * The file is read in chunks, so big files need no memory of their size.
   */
  def computeChecksum(peData: PEData): Long =
    computeChecksum(peData.getFile, peData.getOptionalHeader.getField(WindowsEntryKey.CHECKSUM).getOffset, ChunkSize)

  private[tools] def computeChecksum(file: File, checksumOffset: Long, chunkSize: Int): Long = {
    require(chunkSize > 0 && chunkSize % 8 == 0, "chunk size must be a positive multiple of 8")
    // small files need no buffer of the full chunk size
    val chunk = new Array[Byte](math.max(8L, math.min(chunkSize.toLong, (file.length + 7) & ~7L)).toInt)
    val words = ByteBuffer.wrap(chunk).order(ByteOrder.LITTLE_ENDIAN)
    // the sum of all 32 bit words, files up to 8 GB do not overflow
    var total = 0L
    var length = 0L
    using(new RandomAccessFile(file, "r")) { raf =>
      var n = readFully(raf, chunk)
      while (n > 0) {
        Interruption.checkInterrupt()
        // the checksum field counts as zero
        var z = math.max(checksumOffset, length)
        while (z < math.min(checksumOffset + 4, length + n)) {
          chunk((z - length).toInt) = 0
          z += 1
        }
        // only the last chunk can be incomplete, its last word is padded with zeros
        val end = (n + 7) & ~7
        java.util.Arrays.fill(chunk, n, end, 0.toByte)
        var i = 0
        while (i < end) {
          // two words at once
          val v = words.getLong(i)
          total += (v & 0xffffffffL) + (v >>> 32)
          i += 8
        }
        length += n
        n = readFully(raf, chunk)
      }
    }
    var sum = endAroundCarrySum(total)
    // fold
    var high = sum >>> 16
    sum &= 0xFFFF
    sum += high
    high = sum >>> 16
    sum += high
    sum &= 0xFFFF
    sum += length
    sum
  }

  /**
   * The result of adding the words one by one and folding the carry back
   * whenever the sum exceeds 2^32, computed from the plain sum of all words.
   * That folding keeps the sum within [0, 2^32] and congruent to the total
   * modulo 2^32 - 1. The remainders 0 and 1 have two values in that range:
   * 0 and 1 are only reached by the totals 0 and 1 themselves, because a fold
   * results in at least 2 and sums never decrease otherwise, so other totals
   * end with 2^32 - 1 and 2^32.
   *
   * @param total the sum of all 32 bit words, at most 2^63 - 1
   */
  private[tools] def endAroundCarrySum(total: Long): Long = {
    val modulus = 0xffffffffL
    val remainder = total % modulus
    if (total <= 1) total
    else if (remainder == 0) modulus
    else if (remainder == 1) 1L << 32
    else remainder
  }

  /** reads until the buffer is full or the file ends, returns the number of bytes read */
  private def readFully(raf: RandomAccessFile, buffer: Array[Byte]): Int = {
    var n = 0
    var r = 0
    while (n < buffer.length && r >= 0) {
      r = raf.read(buffer, n, buffer.length - n)
      if (r > 0) n += r
    }
    n
  }
}
