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

import io.github.struppigel.parser.IOUtil.NL
import ExportNamePointerTable._
import io.github.struppigel.parser.MemoryMappedPE
import org.apache.logging.log4j.LogManager

import scala.collection.mutable.ListBuffer

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
  val maxNameLength = 0x200 // TODO anomaly

  def apply(mmBytes: MemoryMappedPE, rva: Long, entries: Int,
    virtualAddress: Long, fileOffset: Long, maxNameEntries: Int): ExportNamePointerTable = {
    val initialOffset = (rva - virtualAddress).toInt
    val addresses = new ListBuffer[(Address, String)]
    val end = initialOffset + entries * entryLength
    val limitedEnd = Math.min(maxNameEntries * 4 + initialOffset, end)
    for (offset <- initialOffset until limitedEnd by entryLength) {
      val address = mmBytes.getBytesLongValue(offset + virtualAddress, entryLength)
      val name = getName(mmBytes, address)
      addresses += ((address, name))
    }

    new ExportNamePointerTable(addresses.toList, fileOffset)
  }

  private def getName(mmBytes: MemoryMappedPE, address: Long): String = {
    val end = mmBytes.indexOf('\0'.toByte, address)
    val size = end - address
    // check size
    if (size > maxNameLength) {
      // TODO this is a full fledged anomaly! add detection for it.
      // example file: VirusShare_a90da79e98213703fc3342b281a95094
      logger.warn("No end of export name found or export name too big")
      ""
    } else {
      val nameBytes = mmBytes.slice(address, end)
      new String(nameBytes)
    }

  }

}
