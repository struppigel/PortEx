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
package com.github.katjahahn.sections.rsrc

import com.github.katjahahn.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.ByteArrayUtil._
import ResourceDirectoryEntry._

abstract class ResourceDirectoryEntry

case class SubDirEntry(id: IDOrName, table: ResourceDirectoryTable, entryNr: Int) extends ResourceDirectoryEntry {
  override def toString(): String = 
    s"""Sub Dir Entry $entryNr:
       |${id.toString()}
       |
       |${table.getInfo()}
       |""".stripMargin
}
case class DataEntry(id: IDOrName, data: ResourceDataEntry, entryNr: Int) extends ResourceDirectoryEntry {
  
  override def toString(): String = 
    s"""Data Dir Entry $entryNr:
       |${id.toString()}
       |
       |${data.toString()}
       |""".stripMargin
}

abstract class IDOrName

case class ID(id: Long) extends IDOrName {
  override def toString(): String = "ID: " + typeIDMap.getOrElse(id.toInt, id.toString)
}

case class Name(rva: Long, name: String) extends IDOrName

object ResourceDirectoryEntry {

  private val specLocation = "resourcedirentryspec";
  private val typeSpecLocation = "resourcetypeid"
  val typeIDMap = IOUtil.readArray(typeSpecLocation).asScala.map(a => (a(0).toInt, a(2))).toMap
  //TODO languageIDMap, nameIDMap

  def apply(isNameEntry: Boolean, entryBytes: Array[Byte],
    entryNr: Int, tableBytes: Array[Byte], offset: Long, level: Level): ResourceDirectoryEntry = {
    val entries = readEntries(entryBytes)
    val rva = entries("DATA_ENTRY_RVA_OR_SUBDIR_RVA")
    val id = getID(entries("NAME_RVA_OR_INTEGER_ID"), isNameEntry)
    if (isDataEntryRVA(rva)) {
      createDataEntry(rva, id, tableBytes, offset, entryNr)
    } else {
      createSubDirEntry(rva, id, tableBytes, offset, entryNr, level) 
    }
  }

  private def readEntries(entryBytes: Array[Byte]): Map[String, Long] = {
    val spec = IOUtil.readMap(specLocation).asScala.toMap
    val valueOffset = 2
    val valueSize = 3
    for ((sKey, sVal) <- spec) yield {
      val value = getBytesLongValue(entryBytes,
        Integer.parseInt(sVal(valueOffset)),
        Integer.parseInt(sVal(valueSize)))
      (sKey, value)
    }
  }

  private def getID(value: Long, isNameEntry: Boolean): IDOrName =
    if (isNameEntry) {
      val name = null //TODO
      Name(value, name)
    } else {
      ID(value)
    }

  private def removeHighestIntBit(value: Long): Long = {
    val mask = 0x7FFFFFFF
    (value & mask)
  }

  private def createDataEntry(rva: Long, id: IDOrName,
    tableBytes: Array[Byte], offset: Long, entryNr: Int): DataEntry = {
    val entryBytes = tableBytes.slice((rva - offset).toInt,
      (rva - offset + ResourceDataEntry.size).toInt)
    val data = ResourceDataEntry(entryBytes)
    DataEntry(id, data, entryNr)
  }

  private def createSubDirEntry(rva: Long, id: IDOrName,
    tableBytes: Array[Byte], offset: Long, entryNr: Int, level: Level): SubDirEntry = {
    val address = removeHighestIntBit(rva)
    val resourceBytes = tableBytes.slice((address - offset).toInt, tableBytes.length)
    val table = ResourceDirectoryTable(level.up, resourceBytes, address)
    SubDirEntry(id, table, entryNr)
  }

  private def isDataEntryRVA(value: Long): Boolean = {
    val mask = 1 << 31
    (value & mask) == 0
  }

}
