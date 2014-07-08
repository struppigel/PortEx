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
package com.github.katjahahn.parser.sections.rsrc

import scala.collection.JavaConverters._
import com.github.katjahahn.parser.ByteArrayUtil._
import ResourceDirectoryEntry._
import java.io.File
import java.io.RandomAccessFile
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.FileFormatException
import org.apache.logging.log4j.LogManager
import com.github.katjahahn.parser.MemoryMappedPE

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

  def idString: String = typeIDMap.getOrElse(id.toInt, id.toString)

  override def toString(): String =
    "ID: " + { if (level.levelNr == 1) idString else id.toString }

}

case class Name(rva: Long, name: String) extends IDOrName {
  override def toString(): String = name
}

object ResourceDirectoryEntry {

  private val logger = LogManager
    .getLogger(ResourceDirectoryEntry.getClass().getName());
  private val specLocation = "resourcedirentryspec";
  private val typeSpecLocation = "resourcetypeid"
  val typeIDMap = IOUtil.readArray(typeSpecLocation).asScala.map(a => (a(0).toInt, a(1))).toMap
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
    entryNr: Int, offset: Long, level: Level,
    virtualAddress: Long, rsrcOffset: Long, mmBytes: MemoryMappedPE): ResourceDirectoryEntry = {
    val entries = readEntries(entryBytes)
    val rva = entries("DATA_ENTRY_RVA_OR_SUBDIR_RVA")
    val id = getID(entries("NAME_RVA_OR_INTEGER_ID"), isNameEntry, level, mmBytes)
    if (isDataEntryRVA(rva)) {
      createDataEntry(rva, id, entryNr, rsrcOffset, mmBytes)
    } else {
      createSubDirEntry(file, rva, id, offset, entryNr, level,
        virtualAddress, rsrcOffset, mmBytes)
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

  private def getID(rva: Long, isNameEntry: Boolean, level: Level,
    mmBytes: MemoryMappedPE): IDOrName =
    if (isNameEntry) {
      val name = getStringAtRVA(rva, mmBytes) //TODO ?
      name match {
        case None => throw new FileFormatException("unable to read name entry")
        case Some(str) => Name(rva, str)
      }
    } else {
      ID(rva, level)
    }

  private def getStringAtRVA(rva: Long, mmBytes: MemoryMappedPE): Option[String] = {
    val nameRVA = removeHighestIntBit(rva)
    val address = nameRVA
    val length = 2
    if (address + length > mmBytes.length) {
      logger.warn("couldn't read string at offset " + address)
      //          return None
    }
    val strLength = mmBytes.getBytesIntValue(address, length)
    val strBytes = strLength * 2 //wg UTF-16 --> 2 Byte
    val stringAddress = (address + length).toInt
    if (stringAddress + strBytes > mmBytes.length) {
      logger.warn("couldn't read string at offset " + address)
      //      return None
    }
    val bytes = mmBytes.slice(stringAddress, stringAddress + strBytes)
    Some(new String(bytes, "UTF-16LE"))
  }

  private def removeHighestIntBit(value: Long): Long = {
    val mask = 0x7FFFFFFF
    (value & mask)
  }

  private def createDataEntry(rva: Long, id: IDOrName, entryNr: Int,
    rsrcOffset: Long, mmBytes: MemoryMappedPE): DataEntry = {
    val entryBytes = mmBytes.slice(rva, rva + ResourceDataEntry.size)
    //TODO is this file offset calculation correct?
    val entryOffset = rva + rsrcOffset
    val data = ResourceDataEntry(entryBytes, entryOffset)
    DataEntry(id, data, entryNr)
  }

  private def createSubDirEntry(file: File, rva: Long, id: IDOrName,
    offset: Long, entryNr: Int, level: Level,
    virtualAddress: Long, rsrcOffset: Long, mmBytes: MemoryMappedPE): SubDirEntry = {
    val address = removeHighestIntBit(rva)
    val table = ResourceDirectory(file, level.up, address, virtualAddress, rsrcOffset, mmBytes)
    SubDirEntry(id, table, entryNr)
  }

  private def isDataEntryRVA(value: Long): Boolean = {
    val mask = 1 << 31
    (value & mask) == 0
  }

}
