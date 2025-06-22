/**
 * *****************************************************************************
 * Copyright 2014 Katja Hahn
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
package io.github.struppigel.parser.sections.edata

import ExportOrdinalTable.entrySize
import io.github.struppigel.parser.{FileFormatException}
import io.github.struppigel.parser.MemoryMappedPE

import scala.collection.mutable.ListBuffer

class ExportOrdinalTable (
  val ordinals: List[Int],
  val base: Int,
  val fileOffset: Long) {

  def size(): Long = entrySize * ordinals.length
  
  def apply(i: Int): Int = ordinals(i)

  override def toString(): String =
    s"""|Ordinal Table
        |..............
        |
        |${ordinals.mkString(", ")}""".stripMargin

}

object ExportOrdinalTable {
  
  val entrySize = 2 // in Byte

  def apply(mmBytes: MemoryMappedPE, base: Int, rva: Long, entries: Int,
    virtualAddress: Long, fileOffset: Long): ExportOrdinalTable = {
    if(entries <= 0) throw new FileFormatException("number of ordinal entries <= 0")
    if(rva <= 0) throw new FileFormatException("rva for ordinal table <= 0")
    if(rva >= mmBytes.length()) throw new FileFormatException("rva for ordinal table is too large: " + rva)
    if(fileOffset <= 0) throw new FileFormatException("file offset for ordinal table <= 0")
    val initialOffset = rva - virtualAddress
    val end = entrySize * entries + initialOffset
    val ordinals = new ListBuffer[Int]
    for (offset <- initialOffset until end by entrySize) {
      val ordinal = mmBytes.getBytesIntValue(offset + virtualAddress, entrySize)
      ordinals += (ordinal + base)
    }
    new ExportOrdinalTable(ordinals.toList, base, fileOffset)
  }

}
