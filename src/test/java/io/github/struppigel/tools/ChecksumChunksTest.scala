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
package io.github.struppigel.tools

import io.github.struppigel.parser.optheader.WindowsEntryKey
import io.github.struppigel.parser.{PELoader, PESignature}
import org.testng.Assert.assertEquals
import org.testng.SkipException
import org.testng.annotations.Test

import java.io.File
import java.nio.file.Files
import java.nio.{ByteBuffer, ByteOrder}
import scala.util.Random

/**
 * Compares the checksum that is computed in chunks with the algorithm of
 * former versions, which read the whole file into memory.
 */
class ChecksumChunksTest {

  /** the algorithm of former versions */
  private def wholeFile(bytes: Array[Byte], checksumOffset: Int): Long = {
    val buffer = ByteBuffer.wrap(bytes.clone()).order(ByteOrder.LITTLE_ENDIAN)
    buffer.putInt(checksumOffset, 0)
    val top = 1L << 32
    var sum = 0L
    while (buffer.remaining() >= 4) {
      sum += buffer.getInt() & 0xffffffffL
      if (sum > top) sum = (sum & 0xffffffffL) + (sum >>> 32)
    }
    val rest = new Array[Byte](4)
    var i = 0
    while (buffer.hasRemaining) {
      rest(i) = buffer.get()
      i += 1
    }
    sum += ByteBuffer.wrap(rest).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xffffffffL
    if (sum > top) sum = (sum & 0xffffffffL) + (sum >>> 32)
    var high = sum >>> 16
    sum &= 0xFFFF
    sum += high
    high = sum >>> 16
    sum += high
    sum &= 0xFFFF
    sum + bytes.length
  }

  @Test
  def chunksGiveTheChecksumOfTheWholeFile(): Unit = {
    val rnd = new Random(3)
    val file = File.createTempFile("portex-checksum", ".bin")
    file.deleteOnExit()
    try {
      for (size <- Seq(4, 5, 7, 1001, 4096, 70001)) {
        // 0xFF bytes make the sum overflow often
        val bytes = Array.fill(size)(if (rnd.nextBoolean()) 0xFF.toByte else rnd.nextInt(256).toByte)
        Files.write(file.toPath, bytes)
        // the checksum field may also be unaligned and span two chunks
        for (offset <- Seq(0, 3, 5, size - 4).distinct if offset + 4 <= size; chunk <- Seq(8, 16, 24, 1024, 1 << 20)) {
          assertEquals(ChecksumVerifier.computeChecksum(file, offset, chunk), wholeFile(bytes, offset),
            s"size $size, checksum at $offset, chunk size $chunk")
        }
      }
    } finally file.delete()
  }

  /** adds the words one by one and folds the carry whenever the sum exceeds 2^32, as former versions did */
  private def stepwise(words: Seq[Long]): Long = {
    var sum = 0L
    for (w <- words) {
      sum += w
      if (sum > (1L << 32)) sum = (sum & 0xffffffffL) + (sum >>> 32)
    }
    sum
  }

  @Test
  def endAroundCarryFromTheTotal(): Unit = {
    val max = 0xffffffffL
    // totals with the remainders 0 and 1, which have two results
    val edgeCases = Seq(Nil, Seq(0L), Seq(1L), Seq(max), Seq(max, max), Seq(max, 1L), Seq(1L, max), Seq(max, max, 1L),
      Seq(max, 2L), Seq(2L, max - 1))
    for (words <- edgeCases) assertEquals(ChecksumVerifier.endAroundCarrySum(words.sum), stepwise(words), words.toString)
    val rnd = new Random(5)
    val values = Seq(0L, 1L, 2L, max - 1, max)
    for (_ <- 0 until 2000) {
      val words = Seq.fill(rnd.nextInt(40))(if (rnd.nextBoolean()) values(rnd.nextInt(values.size)) else rnd.nextInt() & max)
      assertEquals(ChecksumVerifier.endAroundCarrySum(words.sum), stepwise(words), words.toString)
    }
  }

  @Test
  def corpusFilesHaveTheChecksumOfTheWholeFile(): Unit = {
    val corpus = new File("portextestfiles/testfiles")
    if (!corpus.isDirectory) throw new SkipException("test corpus not available")
    val files = corpus.listFiles().filter(f => f.isFile && f.length < (20 << 20) && new PESignature(f).exists())
    for (f <- files) {
      val pe = try Some(PELoader.loadPE(f)) catch { case _: Exception => None }
      for (data <- pe) {
        val offset = data.getOptionalHeader.getField(WindowsEntryKey.CHECKSUM).getOffset
        if (offset + 4 <= f.length) {
          assertEquals(ChecksumVerifier.computeChecksum(data), wholeFile(Files.readAllBytes(f.toPath), offset.toInt), f.getName)
        }
      }
    }
  }
}
