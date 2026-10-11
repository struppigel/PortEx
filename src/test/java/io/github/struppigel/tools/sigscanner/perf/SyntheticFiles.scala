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
package io.github.struppigel.tools.sigscanner.perf

import java.io.{BufferedOutputStream, File, FileOutputStream}
import java.nio.file.Files
import java.nio.{ByteBuffer, ByteOrder}
import scala.util.Random

/**
 * Creates test files in a temporary folder, so that no large binaries need to
 * be committed. All data is generated from fixed seeds.
 */
final class SyntheticFiles {

  val folder: File = Files.createTempDirectory("portex-perf").toFile

  /** writes random bytes with the given content planted at the given offsets */
  def random(name: String, size: Long, seed: Long, planted: Seq[(Long, Array[Byte])] = Nil): File = {
    val file = new File(folder, name)
    val rnd = new Random(seed)
    val out = new BufferedOutputStream(new FileOutputStream(file), 1 << 20)
    try {
      val chunk = new Array[Byte](1 << 20)
      var written = 0L
      while (written < size) {
        rnd.nextBytes(chunk)
        val len = math.min(chunk.length.toLong, size - written).toInt
        for ((offset, bytes) <- planted if offset < written + len && offset + bytes.length > written) {
          for (i <- bytes.indices) {
            val pos = offset + i - written
            if (pos >= 0 && pos < len) chunk(pos.toInt) = bytes(i)
          }
        }
        out.write(chunk, 0, len)
        written += len
      }
    } finally out.close()
    file
  }

  /**
   * A minimal PE32 file with one executable section and an appended overlay.
   *
   * @param entryPointCode bytes at the entry point
   * @param sectionSize size of the .text section, multiple of 0x200
   * @param overlay overlay bytes appended to the file
   */
  def pe(name: String, entryPointCode: Array[Byte], sectionSize: Int, overlay: Array[Byte], seed: Long = 1): File = {
    require(sectionSize % 0x200 == 0)
    val headerSize = 0x200
    val epOffsetInSection = 0x100
    val buf = ByteBuffer.allocate(headerSize + sectionSize).order(ByteOrder.LITTLE_ENDIAN)
    // MS-DOS header
    buf.put(0, 'M'.toByte).put(1, 'Z'.toByte).putInt(0x3C, 0x80)
    // PE signature and COFF file header
    buf.putInt(0x80, 0x00004550)
    buf.putShort(0x84, 0x14c.toShort) // i386
    buf.putShort(0x86, 1.toShort) // number of sections
    buf.putShort(0x94, 0xE0.toShort) // size of optional header
    buf.putShort(0x96, 0x0102.toShort) // executable image, 32 bit
    // optional header
    val opt = 0x98
    buf.putShort(opt, 0x10B.toShort) // PE32
    buf.putInt(opt + 4, sectionSize) // size of code
    buf.putInt(opt + 16, 0x1000 + epOffsetInSection) // address of entry point
    buf.putInt(opt + 20, 0x1000) // base of code
    buf.putInt(opt + 28, 0x400000) // image base
    buf.putInt(opt + 32, 0x1000) // section alignment
    buf.putInt(opt + 36, 0x200) // file alignment
    buf.putShort(opt + 40, 4.toShort) // OS version
    buf.putShort(opt + 48, 4.toShort) // subsystem version
    buf.putInt(opt + 56, 0x1000 + ((sectionSize + 0xFFF) / 0x1000) * 0x1000) // size of image
    buf.putInt(opt + 60, headerSize) // size of headers
    buf.putShort(opt + 68, 3.toShort) // console
    buf.putInt(opt + 72, 0x100000) // stack reserve
    buf.putInt(opt + 76, 0x1000) // stack commit
    buf.putInt(opt + 80, 0x100000) // heap reserve
    buf.putInt(opt + 84, 0x1000) // heap commit
    buf.putInt(opt + 92, 16) // number of data directories
    // section header
    val sh = opt + 0xE0
    ".text".getBytes("US-ASCII").zipWithIndex.foreach { case (b, i) => buf.put(sh + i, b) }
    buf.putInt(sh + 8, sectionSize) // virtual size
    buf.putInt(sh + 12, 0x1000) // virtual address
    buf.putInt(sh + 16, sectionSize) // size of raw data
    buf.putInt(sh + 20, headerSize) // pointer to raw data
    buf.putInt(sh + 36, 0x60000020) // code, execute, read
    // section content: random code with the entry point bytes
    val code = new Array[Byte](sectionSize)
    new Random(seed).nextBytes(code)
    System.arraycopy(entryPointCode, 0, code, epOffsetInSection, entryPointCode.length)
    buf.position(headerSize)
    buf.put(code)
    val file = new File(folder, name)
    val out = new FileOutputStream(file)
    try {
      out.write(buf.array())
      out.write(overlay)
    } finally out.close()
    file
  }

  def delete(): Unit = {
    Option(folder.listFiles()).foreach(_.foreach(_.delete()))
    folder.delete()
  }
}
