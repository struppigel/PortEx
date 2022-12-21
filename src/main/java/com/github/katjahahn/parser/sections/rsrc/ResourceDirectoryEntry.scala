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

import com.github.katjahahn.parser.ByteArrayUtil._
import com.github.katjahahn.parser.{IOUtil, MemoryMappedPE, PhysicalLocation}
import com.github.katjahahn.parser.sections.rsrc.ResourceDirectoryEntry._
import org.apache.logging.log4j.LogManager

import java.io.File
import scala.collection.JavaConverters._
import scala.math.min

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
abstract class ResourceDirectoryEntry {

  def locations(): List[PhysicalLocation]

}

/**
 * An entry that points to another {@link ResourceDirectory}
 *
 * @param id the ID or Name of the entry
 * @param table the table the entry points to
 * @param entryNr the number of the entry within the {@link ResourceDirectory}
 */
case class SubDirEntry(id: IDOrName, table: ResourceDirectory, entryNr: Int, rsrcOffset: Long) extends ResourceDirectoryEntry {

  private lazy val idLoc = id match {
    case Name(rva, name) => List(new PhysicalLocation(rva + rsrcOffset, name.length * 2))
    case _               => Nil
  }

  /**
   * {@inheritDoc}
   */
  override def locations(): List[PhysicalLocation] = idLoc ::: table.locations

  /**
   * {@inheritDoc}
   */
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
case class DataEntry(id: IDOrName, data: ResourceDataEntry, entryNr: Int, rsrcOffset: Long) extends ResourceDirectoryEntry {

  private lazy val idLoc = id match {
    case Name(rva, name) => List(new PhysicalLocation(rva + rsrcOffset, name.length * 2))
    case _               => Nil
  }

  override def locations(): List[PhysicalLocation] = idLoc ::: data.locations

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
    "ID: " + { if (level == Level.typeLevel()) idString else id.toString }
  
  def canEqual(other: Any) = {
    other.isInstanceOf[ID]
  }

  /**
   * {@inheritDoc}
   */
  override def equals(other: Any) = {
    other match {
      case that: ID => that.canEqual(ID.this) && id == that.id && level.equals(that.level)
      case _ => false
    }
  }
  
  override def hashCode() = {
    val prime = 41
    prime * (prime + id.hashCode) + level.hashCode
  } 

}

case class Name(rva: Long, name: String) extends IDOrName {
  override def toString(): String = name
}

object ResourceDirectoryEntry {

  val maxNameLength = 30

  private val logger = LogManager.getLogger(ResourceDirectoryEntry.getClass().getName())

  /**
   * The specification file name of the resource directory entry
   */
  private val specLocation = "resourcedirentryspec"

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
   * @param file the PE file
   * @param isNameEntry indicates whether the ID is a number id or points to a name
   * @param entryBytes the array of bytes this entry is made of
   * @param entryNr the number of the entry within the {@link ResourceDirectory}
   * @param level the level of the {@link ResourceDirectory} this entry is a member of
   * @param virtualAddress the rva to the resource table
   * @param rsrcOffset the relative offset from the resource table to the resource directory entry
   * @param mmBytes the memory mapped PE
   * @param loopChecker the resource loop checker
   * @return {@link ResourceDirectoryEntry}
   */
  def apply(file: File, isNameEntry: Boolean, entryBytes: Array[Byte],
            entryNr: Int, level: Level, virtualAddress: Long, rsrcOffset: Long,
            mmBytes: MemoryMappedPE, loopChecker: ResourceLoopChecker): ResourceDirectoryEntry = {
    // read all fields of this resource directory entry
    val entries = readEntries(entryBytes)
    // fetch rva to subdirectory or data entry
    val rva = entries("DATA_ENTRY_RVA_OR_SUBDIR_RVA")
    // fetch id or name field
    val optionalEntry = getIDOrName(entries("NAME_RVA_OR_INTEGER_ID"), isNameEntry, level, mmBytes, virtualAddress)
    // rva determines if this is a subdirectory or a data entry
    if (optionalEntry.isDefined) {
      if (isDataEntryRVA(rva)) {
        // create and return data entry
        createDataEntry(rva, optionalEntry.get, entryNr, virtualAddress, rsrcOffset, mmBytes)
      } else {
        // create and return subdirectory
        createSubDirEntry(file, rva, optionalEntry.get, entryNr, level,
          virtualAddress, rsrcOffset, mmBytes, loopChecker)
      }
    } else throw new IllegalArgumentException("invalid resource directory entry at va " + (rsrcOffset+virtualAddress))
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
   * @return Option of ID entry or name entry or None if invalid
   */
  private def getIDOrName(rva: Long, isNameEntry: Boolean, level: Level,
                          mmBytes: MemoryMappedPE, va: Long): Option[IDOrName] =
    try {
      if (isNameEntry) {
        // if name entry fetch the name string at given rva
        val name = getStringAtRVA(rva, va, mmBytes, maxNameLength)
        Some(Name(rva, name))
        // create id instance otherwise
      } else Some(ID(rva, level))
    } catch {
      case e: IllegalArgumentException => None
    }

  /**
   * Returns the string at the specified rva.
   * <p>
   * The first two bytes at the given rva specify the length of following string.
   * @param rva the relative virtual address to the string
   * @param mmbytes the memory mapped PE
   * @param maxStrLength maximum number of characters to read
   * @return string at rva
   */
  private def getStringAtRVA(rva: Long, va: Long, mmBytes: MemoryMappedPE, maxStrLength: Int): String = {
    // highest bit does not belong to rva, add virtualAddress of resource section
    val address = removeHighestIntBit(rva) + va
    // 2 bytes reserved for length
    val length = 2
    // check if able to read
    if (address + length > mmBytes.length) {
      logger.warn("couldn't read string at offset " + address)
      throw new IllegalArgumentException()
    }
    // read the length of the string (number of characters)
    val strLength = min(mmBytes.getBytesIntValue(address, length), maxStrLength)
    // UTF-16 needs two bytes per character
    val strBytes = strLength * 2
    // the actual address of the string
    val stringAddress = address + length
    // check if within boundaries
    if (stringAddress + strBytes > mmBytes.length) {
      logger.warn("couldn't read string at offset " + address)
    }
    // read bytes
    val bytes = mmBytes.slice(stringAddress, stringAddress + strBytes)
    // create UTF-16 little endian string
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
   * @param rva the data entry rva
   * @param id the ID or Name entry
   * @param entryNr the number of the entry
   * @param rsrcOffset the relative offset from the beginning of the
   *        resource table to the entry
   * @param mmBytes the memory mapped PE
   * @return a data entry
   */
  private def createDataEntry(rva: Long, id: IDOrName, entryNr: Int,
                              virtualAddress: Long, rsrcOffset: Long,
                              mmBytes: MemoryMappedPE): DataEntry = {
    // calculate virtual start of the data entry
    val virtStart = rva + virtualAddress
    // calculate virtual end of the data entry
    val virtEnd = virtStart + ResourceDataEntry.entrySize
    // read bytes of the data entry
    val entryBytes = mmBytes.slice(virtStart, virtEnd)
    // calculate the file offset of the data entry
    val entryOffset = rva + rsrcOffset
    // create and return resource data entry
    val data = ResourceDataEntry(entryBytes, entryOffset, mmBytes, virtualAddress)
    DataEntry(id, data, entryNr, rsrcOffset)
  }

  /**
   * Creates a subdirectory entry.
   *
   * @param rva the subdirectory rva
   * @param id the ID or Name entry
   * @param entryNr the number of the entry
   * @param level the current level of the entry in the resource tree
   * @param virtualAddress the address to the resource table
   * @param rsrcOffset the relative offset from the beginning of the
   *        resource table to the entry
   * @param mmBytes the memory mapped PE
   * @return a subdirectory entry
   */
  private def createSubDirEntry(file: File, rva: Long, id: IDOrName, entryNr: Int, level: Level,
                                virtualAddress: Long, rsrcOffset: Long, mmBytes: MemoryMappedPE,
                                loopChecker: ResourceLoopChecker): SubDirEntry = {
    // highest bit does not belong to actual rva
    val address = removeHighestIntBit(rva)
    // parse and create underlying resource directory of the subdirectory entry
    val table = ResourceDirectory(file, level.up, address, virtualAddress, rsrcOffset, mmBytes, loopChecker)
    // create sub directory entry
    SubDirEntry(id, table, entryNr, rsrcOffset)
  }

  private def isDataEntryRVA(value: Long): Boolean = {
    // highest integer bit determines if entry is a data entry or subdir entry
    val mask = 1 << 31
    (value & mask) == 0
  }

}
