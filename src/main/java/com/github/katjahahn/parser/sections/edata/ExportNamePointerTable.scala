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
import com.github.katjahahn.parser.IOUtil.{ NL }
import java.io.File
import ExportNamePointerTable._
import com.github.katjahahn.parser.MemoryMappedPE
import org.apache.logging.log4j.LogManager

class ExportNamePointerTable private (val pointerNameList: List[(Address, String)],
  val fileOffset: Long) {

  def size(): Long = pointerNameList.length * ExportNamePointerTable.entryLength

  def getMap(): Map[Address, String] = pointerNameList.toMap

  def apply(i: Int): Long = pointerNameList(i)._1

  //TODO binary search
  def apply(name: String): Int = pointerNameList.indexWhere(_._2 == name)

  override def toString(): String =
    s"""|Name Pointer Table
        |...................
        |
        |RVA    ->  Name
        |****************
        |${pointerNameList.map(t => ("0x" + java.lang.Long.toHexString(t._1) -> t._2)).mkString(NL)}""".stripMargin

}

object ExportNamePointerTable {
  
  private val logger = LogManager.getLogger(ExportNamePointerTable.getClass().getName())

  type Address = Long
  val entryLength = 4

  def apply(mmBytes: MemoryMappedPE, rva: Long, entries: Int,
    virtualAddress: Long, fileOffset: Long): ExportNamePointerTable = {
    val initialOffset = (rva - virtualAddress).toInt
    val addresses = new ListBuffer[(Address, String)]
    val end = initialOffset + entries * entryLength
    for (offset <- initialOffset until end by entryLength) {
      val address = mmBytes.getBytesLongValue(offset + virtualAddress, entryLength)
      val name = getName(mmBytes, address)
      addresses += ((address, name))
    }

    new ExportNamePointerTable(addresses.toList, fileOffset)
  }

  private def getName(mmBytes: MemoryMappedPE, address: Long): String = {
    val end = mmBytes.indexOf('\0'.toByte, address)
    // check size
    val nameBytes = if ((end - address) != (end - address).toInt) {
      // TODO this is a full fledged anomaly! add detection for it.
      // example file: VirusShare_a90da79e98213703fc3342b281a95094
      logger.warn("No end of export name found, reading 10 chars instead")
      mmBytes.slice(address, address + 10)
    } else {
      mmBytes.slice(address, end)
    }
    new String(nameBytes)
  }

}
