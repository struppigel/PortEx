/*******************************************************************************
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
 ******************************************************************************/
package com.github.katjahahn.sections.edata

import com.github.katjahahn.ByteArrayUtil._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import com.github.katjahahn.PEModule._

class ExportOrdinalTable private (
    val ordinals: List[Int], 
    val base: Int) {
  
  def apply(i: Int): Int = ordinals(i)
  
  override def toString(): String = 
    s"""|Ordinal Table
        |..............
        |
        |${ordinals.mkString(", ")}""".stripMargin

}

object ExportOrdinalTable {

  def apply(edataBytes: Array[Byte], base: Int, rva: Long, entries: Int, 
      virtualAddress: Long): ExportOrdinalTable = {
    val entrySize = 2 //in Byte
    val initialOffset = (rva - virtualAddress).toInt
    val end = entrySize * entries + initialOffset
    val ordinals = new ListBuffer[Int]
    for(offset <- initialOffset until end by entrySize) {
      val ordinal = getBytesIntValue(edataBytes, offset, entrySize)
      ordinals += (ordinal + base)
    }
    new ExportOrdinalTable(ordinals.toList, base)
  }

}
