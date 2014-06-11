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
package com.github.katjahahn.sections.rsrc

import com.github.katjahahn.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.ByteArrayUtil._
import ResourceDirectoryEntry._
import java.io.File
import com.github.katjahahn.sections.SectionLoader
import com.github.katjahahn.PELoader
import com.github.katjahahn.sections.SectionHeaderKey
import java.io.RandomAccessFile
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.optheader.WindowsEntryKey

/**
 * The entry of a {@link ResourceDirectory}
 *
 * There are two types of resource directory entries. They either point to another
 * resource directory table or to data.
 * The entries have either an {@link ID} or a {@link Name}
 */
abstract class ResourceDirectoryEntry

/**
 * An entry that points to another {@link ResourceDirectory}
 *
 * @param id the ID or Name of the entry
 * @param table the table the entry points to
 * @param entryNr the number of the entry within the {@link ResourceDirectory}
 */
case class SubDirEntry(id: IDOrName, table: ResourceDirectory, entryNr: Int) extends ResourceDirectoryEntry {
  override def toString(): String =
    s"""Sub Dir Entry $entryNr
       |+++++++++++++++
       |
       |${id.toString()}
       |
       |${table.getInfo()}
       |""".stripMargin
}

/**
 * This entry points to a {@link ResourceDataEntry}.
 *
 * @param id the ID or Name of the entry
 * @param data the resource data entry
 * @param entryNr the number of the entry within the {@link ResourceDirectory}
 */
case class DataEntry(id: IDOrName, data: ResourceDataEntry, entryNr: Int) extends ResourceDirectoryEntry {

  override def toString(): String =
    s"""Data Dir Entry $entryNr
       |++++++++++++++++
       |
       |${id.toString()}
       |
       |${data.toString()}
       |""".stripMargin
}

/**
 * Represents and ID or a name for a directory table entry
 */
abstract class IDOrName

case class ID(id: Long, level: Level) extends IDOrName {
  override def toString(): String =
    "ID: " + { if (level.levelNr == 1) typeIDMap.getOrElse(id.toInt, id.toString) else id.toString }

}

case class Name(rva: Long, name: String) extends IDOrName {
  override def toString(): String = name
}

object ResourceDirectoryEntry {

  private val specLocation = "resourcedirentryspec";
  private val typeSpecLocation = "resourcetypeid"
  val typeIDMap = IOUtil.readArray(typeSpecLocation).asScala.map(a => (a(0).toInt, a(2))).toMap
  //TODO languageIDMap, nameIDMap

  /**
   * Creates a {@link ResourceDirectoryEntry}
   *
   * @param isNameEntry indicates whether the ID is a number id or points to a name
   * @param entryBytes the array of bytes this entry is made of
   * @param entryNr the number of the entry within the {@link ResourceDirectory}
   * @param tableBytes the array of bytes the whole table is made of
   *   where this is entry is a member of
   * @param offset of the {@link ResourceDirectory} this entry is a member of
   * @param level the level of the {@link ResourceDirectory} this entry is a member of
   * @return {@link ResourceDirectoryEntry}
   */
  def apply(file: File, isNameEntry: Boolean, entryBytes: Array[Byte],
    entryNr: Int, tableBytes: Array[Byte], offset: Long, level: Level,
    virtualAddress: Long, rsrcOffset: Long): ResourceDirectoryEntry = {
    val entries = readEntries(entryBytes)
    val rva = entries("DATA_ENTRY_RVA_OR_SUBDIR_RVA")
    val id = getID(entries("NAME_RVA_OR_INTEGER_ID"), isNameEntry, level,
      tableBytes, virtualAddress, offset, rsrcOffset)
    if (isDataEntryRVA(rva)) {
      createDataEntry(rva, id, tableBytes, offset, entryNr)
    } else {
      createSubDirEntry(file, rva, id, tableBytes, offset, entryNr, level, virtualAddress, rsrcOffset)
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

  private def getID(value: Long, isNameEntry: Boolean, level: Level,
    tablebytes: Array[Byte], virtualAddress: Long, offset: Long, rsrcOffset: Long): IDOrName =
    if (isNameEntry) {
      val name = getStringAtRVA(value, tablebytes, virtualAddress, offset, rsrcOffset) //TODO
      Name(value, name)
    } else {
      ID(value, level)
    }

  private def getStringAtRVA(rva: Long, tablebytes: Array[Byte],
    virtualAddress: Long, offset: Long, rsrcOffset: Long): String = {
    val nameRVA = removeHighestIntBit(rva)
    val address = nameRVA - offset
    readStringAtOffset(tablebytes, address)
  }

  private def readStringAtOffset(tablebytes: Array[Byte], address: Long): String = {
    val length = 2
    val strLength = getBytesIntValue(tablebytes, address.toInt, length)
    val strBytes = strLength * 2 //wg UTF-16 --> 2 Byte
    val stringAddress = (address + length).toInt
    val bytes = tablebytes.slice(stringAddress, stringAddress + strBytes)
    new String(bytes, "UTF-16LE")
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

  private def createSubDirEntry(file: File, rva: Long, id: IDOrName,
    tableBytes: Array[Byte], offset: Long, entryNr: Int, level: Level,
    virtualAddress: Long, rsrcOffset: Long): SubDirEntry = {
    val address = removeHighestIntBit(rva)
    val resourceBytes = tableBytes.slice((address - offset).toInt, tableBytes.length)
    val table = ResourceDirectory(file, level.up, resourceBytes, address, virtualAddress, rsrcOffset)
    SubDirEntry(id, table, entryNr)
  }

  private def isDataEntryRVA(value: Long): Boolean = {
    val mask = 1 << 31
    (value & mask) == 0
  }

}
