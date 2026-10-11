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
package io.github.struppigel.parser.sections.clr

import java.nio.charset.StandardCharsets
import scala.collection.JavaConverters._
import scala.collection.mutable.ArrayBuffer

/**
 * #US stream/heap: the user strings of a .NET assembly, e.g. string literals.
 * <p>
 * Each entry is a compressed length (ECMA-335 II.24.2.4), followed by the
 * UTF-16LE string and a terminal flag byte that is included in the length.
 *
 * @param strings the strings in heap order, without the empty first entry
 */
class UserStringsHeap private (val strings: IndexedSeq[String]) {

  def getStrings: java.util.List[String] = strings.asJava
}

object UserStringsHeap {

  /**
   * Parses the bytes of a #US stream. Parsing stops at the first malformed entry.
   */
  def apply(bytes: Array[Byte]): UserStringsHeap = {
    val strings = ArrayBuffer[String]()
    var pos = 0
    var valid = true
    while (valid && pos < bytes.length) {
      readCompressedLength(bytes, pos) match {
        case Some((length, headerSize)) =>
          val start = pos + headerSize
          if (start + length > bytes.length) valid = false
          else {
            if (length > 1) {
              // the last byte is a flag, not part of the string
              strings += new String(bytes, start, length - 1, StandardCharsets.UTF_16LE)
            }
            pos = start + length
          }
        case None => valid = false
      }
    }
    new UserStringsHeap(strings.toIndexedSeq)
  }

  /** @return the length and the number of bytes the length occupies */
  private def readCompressedLength(bytes: Array[Byte], pos: Int): Option[(Int, Int)] = {
    val b0 = bytes(pos) & 0xFF
    if ((b0 & 0x80) == 0) Some((b0, 1))
    else if ((b0 & 0xC0) == 0x80) {
      if (pos + 1 >= bytes.length) None
      else Some((((b0 & 0x3F) << 8) | (bytes(pos + 1) & 0xFF), 2))
    } else if ((b0 & 0xE0) == 0xC0) {
      if (pos + 3 >= bytes.length) None
      else Some((((b0 & 0x1F) << 24) | ((bytes(pos + 1) & 0xFF) << 16) |
        ((bytes(pos + 2) & 0xFF) << 8) | (bytes(pos + 3) & 0xFF), 4))
    } else None
  }
}
