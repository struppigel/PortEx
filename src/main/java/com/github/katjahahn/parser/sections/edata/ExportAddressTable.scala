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
class ExportAddressTable private (val addresses: List[Long], val fileOffset: Long) {

  /**
   * Returns the size of the EAT in bytes
   */
  def size(): Long = addresses.length * ExportAddressTable.addressLength
  
  /**
   * Returns the number of addresses in the EAT
   */
  def nrOfAddresses(): Long = addresses.length
  
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

  val addressLength = 4
  
  /**
   * Creates an instanceo of the export address table by loading the addresses
   * from the given export section bytes.
   *
   * @param mmBytes the bytes of the export section
   * @param rva the relative virtual address for the export address table
   *   (found in the data directory table)
   * @param entries number of entries in the export address table
   * @param virtualAddress the virtual address the rva is relative to
   * @param fileOffset the file offset where the EAT starts
   * @return an instance for the export address table
   */
  def apply(mmBytes: MemoryMappedPE, rva: Long, entries: Int, 
      virtualAddress: Long, fileOffset: Long): ExportAddressTable = {
    val initialOffset = rva - virtualAddress
    val addresses = new ListBuffer[Long]()
    val end = initialOffset + entries * addressLength
    for (offset <- initialOffset until end by addressLength) {
      addresses += mmBytes.getBytesLongValue(offset + virtualAddress, addressLength)
    }
    new ExportAddressTable(addresses.toList, fileOffset)
  }

}
