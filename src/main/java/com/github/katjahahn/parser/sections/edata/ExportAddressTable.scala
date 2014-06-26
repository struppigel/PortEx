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
package com.github.katjahahn.parser.sections.edata

import com.github.katjahahn.parser.ByteArrayUtil._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.MemoryMappedPE
/**
 * The export address table contains all relative virtual addresses in the order
 * they are found in the export section.
 * 
 * @author Katja Hahn
 * 
 * Creates the export table with the addresses found
 * @param addresses of the export section
 */
class ExportAddressTable private (val addresses: List[Long]) {

  /**
   * Returns the address at the given index
   *
   * @param index
   * @return the address in the given index
   */
  def apply(i: Int): Long = addresses(i)

  override def toString(): String =
    s"""|Export Address Table
        |....................
        |
        |${addresses.map("0x" + java.lang.Long.toHexString(_)).mkString(", ")}""".stripMargin

}

object ExportAddressTable {

  /**
   * Creates an instanceo of the export address table by loading the addresses
   * from the given export section bytes.
   *
   * @param edataBytes the bytes of the export section
   * @param rva the relative virtual address for the export address table
   *   (found in the data directory table)
   * @param entries number of entries in the export address table
   * @param virtualAddress the virtual address the rva is relative to
   * @return an instance for the export address table
   */
  def apply(mmBytes: MemoryMappedPE, rva: Long, entries: Int, virtualAddress: Long): ExportAddressTable = {
    val length = 4
    val initialOffset = rva - virtualAddress
    val addresses = new ListBuffer[Long]()
    val end = initialOffset + entries * length
    for (offset <- initialOffset until end by length) {
//      println("offset: " + offset)
//      println("offset + va: " + (offset + virtualAddress))
//      println("offset + va as Int: " + (offset + virtualAddress).toInt)
//      println("array length: " + length)
//      println("actual mmBytes length: " + mmBytes.length)
      //TODO int conversion problem here!
      addresses += mmBytes.getBytesLongValue(offset + virtualAddress, length)
    }
    new ExportAddressTable(addresses.toList)
  }

}
