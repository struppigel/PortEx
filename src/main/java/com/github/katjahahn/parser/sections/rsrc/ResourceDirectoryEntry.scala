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
 * <p>
 * There are two types of resource directory entries. They either point to another
 * resource directory table or to data.
 * <p>
 * The entries have either an {@link ID} or a {@link Name}
 * 
 * @author Katja Hahn
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
 * Represents an ID or a name for a directory table entry
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

  /**
   * The specification file name of the resource directory entry
   */
  private val specLocation = "resourcedirentryspec";

  /**
   * The specification file name of the resource type
   */
  private val typeSpecLocation = "resourcetypeid"

  /**
   * Maps resource ids to the corresponding resource type
   */
  val typeIDMap = IOUtil.readArray(typeSpecLocation).asScala.map(a => (a(0).toInt, a(1))).toMap
  //TODO languageIDMap, nameIDMap

  /**
   * Creates a {@link ResourceDirectoryEntry}
   *
   * @param isNameEntry indicates whether the ID is a number id or points to a name
   * @param entryBytes the array of bytes this entry is made of
   * @param entryNr the number of the entry within the {@link ResourceDirectory}
   * @param level the level of the {@link ResourceDirectory} this entry is a member of
   * @param virtualAddress the rva to the resource table
   * @param rsrcOffset the relative offset from the resource table to the resource directory entry
   * @param mmBytes the memory mapped PE
   * @return {@link ResourceDirectoryEntry}
   */
  def apply(file: File, isNameEntry: Boolean, entryBytes: Array[Byte],
    entryNr: Int, level: Level, virtualAddress: Long, rsrcOffset: Long,
    mmBytes: MemoryMappedPE): ResourceDirectoryEntry = {
    val entries = readEntries(entryBytes)
    val rva = entries("DATA_ENTRY_RVA_OR_SUBDIR_RVA")
    val id = getIDOrName(entries("NAME_RVA_OR_INTEGER_ID"), isNameEntry, level, mmBytes)
    if (isDataEntryRVA(rva)) {
      createDataEntry(rva, id, entryNr, rsrcOffset, mmBytes)
    } else {
      createSubDirEntry(file, rva, id, entryNr, level,
        virtualAddress, rsrcOffset, mmBytes)
    }
  }

  /**
   * @param entryBytes an array representing the bytes of the resource directory entry
   * @return map of the entry fields
   */
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

  /**
   * @param rva the relative virtual address to the IDOrName entry
   * @param isNameEntry true if name entry is returned, false if ID entry is returned
   * @param level the level of the entry within the resource tree
   * @param mmBytes the memory mapped PE
   * @return ID entry or name entry
   */
  private def getIDOrName(rva: Long, isNameEntry: Boolean, level: Level,
    mmBytes: MemoryMappedPE): IDOrName =
    if (isNameEntry) {
      val name = getStringAtRVA(rva, mmBytes)
      Name(rva, name)
    } else ID(rva, level)

  /**
   * Returns the string at the specified rva.
   * <p>
   * The first two bytes at the given rva specify the length of following string.
   * @param rva the relative virtual address to the string
   * @param mmbytes the memory mapped PE
   * @return string at rva
   */
  private def getStringAtRVA(rva: Long, mmBytes: MemoryMappedPE): String = {
    val address = removeHighestIntBit(rva)
    val length = 2
    if (address + length > mmBytes.length) {
      logger.warn("couldn't read string at offset " + address)
    }
    val strLength = mmBytes.getBytesIntValue(address, length)
    val strBytes = strLength * 2 //wg UTF-16 --> 2 Byte
    val stringAddress = (address + length).toInt
    if (stringAddress + strBytes > mmBytes.length) {
      logger.warn("couldn't read string at offset " + address)
    }
    val bytes = mmBytes.slice(stringAddress, stringAddress + strBytes)
    new String(bytes, "UTF-16LE")
  }

  /**
   * Removes the highest bit in an int value and returns the result.
   *
   * @param value the value to remove the bit from
   * @return the value with the highest integer bit removed
   */
  private def removeHighestIntBit(value: Long): Long = {
    val mask = 0x7FFFFFFF
    (value & mask)
  }

  /**
   * Creates a data entry instance from the directory at the specified
   * rsrcOffset and with the entryNr.
   *
   * @param virtualAddress the virtual address to the resource table
   * @param id the ID or Name entry
   * @param entryNr the number of the entry
   * @param rsrcOffset the relative offset from the beginning of the
   *        resource table to the entry
   * @param mmBytes the memory mapped PE
   * @return a data entry
   */
  private def createDataEntry(virtualAddress: Long, id: IDOrName, entryNr: Int,
    rsrcOffset: Long, mmBytes: MemoryMappedPE): DataEntry = {
    val entryBytes = mmBytes.slice(virtualAddress, virtualAddress + ResourceDataEntry.size)
    //TODO is this file offset calculation correct?
    val entryOffset = virtualAddress + rsrcOffset
    val data = ResourceDataEntry(entryBytes, entryOffset)
    DataEntry(id, data, entryNr)
  }

  private def createSubDirEntry(file: File, rva: Long, id: IDOrName, entryNr: Int, level: Level,
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
