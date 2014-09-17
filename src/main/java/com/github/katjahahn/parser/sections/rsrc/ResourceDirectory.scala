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

import java.io.File
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import org.apache.logging.log4j.LogManager
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.MemoryMappedPE
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.sections.rsrc.ResourceDirectoryKey._
import ResourceDirectory._
import com.github.katjahahn.parser.PhysicalLocation

/**
 * Header and the entries which point to either data or other resource directory
 * tables.
 * <p>
 * Each ResourceDirectory therefore is also a tree consisting of more
 * tables or resource data entries as leaves.
 *
 * @author Katja Hahn
 *
 * Creates an instance of the resource directory table with level,
 * header and entries.
 *
 * @param level the level of the table in the tree (where the table is a node)
 * @param header the table header
 * @param entries the table entries
 */
class ResourceDirectory private (private val level: Level,
  private val header: Header,
  private val entries: List[ResourceDirectoryEntry],
  private val fileOffset: Long) extends Equals {

  private val headerLoc = new PhysicalLocation(fileOffset, resourceDirSize)

  def locations(): List[PhysicalLocation] = headerLoc :: entries.flatMap(e => e.locations)

  /**
   * @return resource directory information string
   */
  def getInfo(): String =
    s"""|Resource Dir Table Header
        |-------------------------
        |${level.toString()}
        |${header.values.map(_.toString()).mkString("\n")}
        |
        |${entries.map(_.toString()).mkString("\n")}
        |""".stripMargin

  /**
   * Returns all resource directory entries of the table
   *
   * @return a list of all resource directory entries
   */
  def getEntries(): java.util.List[ResourceDirectoryEntry] = entries.asJava

  /**
   * @return all directory table entries that are data entries
   */
  def getDataEntries(): java.util.List[DataEntry] =
    entries.collect { case d: DataEntry => d }.asJava

  /**
   * @return all directory table entries that are subdirectory entries
   */
  def getSubDirEntries(): java.util.List[SubDirEntry] =
    entries.collect { case s: SubDirEntry => s }.asJava

  /**
   * Returns a map of the header key and value pairs.
   *
   * @return header map
   */
  def getHeader(): java.util.Map[ResourceDirectoryKey, StandardField] = header.asJava

  /**
   * Returns the Long value for the given key
   *
   * @param key the resource directory key
   * @return The value for the given resource directory table key
   */
  def getHeaderValue(key: ResourceDirectoryKey): Long = header(key).value

  /**
   * Collects and returns all resources that this resource table tree has.
   *
   * @param mmBytes the memory mapped PE
   * @return a list of all resources
   */
  def getResources(): java.util.List[Resource] =
    _getResources().asJava

  /**
   * Collects and returns all resources that this resource table tree has.
   * <p>
   * Scala only. Use {@link #getResources}.
   *
   * @param mmBytes the memory mapped PE
   * @return a list of all resources
   */
  def _getResources(): List[Resource] =
    entries.flatMap(getResources)

  /**
   * Collects all the resources of one table entry.
   *
   * @param entry the table directory entry
   * @param mmBytes the memory mapped PE
   * @return a list of all resources that can be found with this entry
   */
  private def getResources(entry: ResourceDirectoryEntry): List[Resource] = {
    entry match {
      case e: DataEntry =>
        val resourceBytes = e.data.getResourceLocation()
        val levelIDs = Map(level -> e.id)
        List(new Resource(resourceBytes, levelIDs))
      case s: SubDirEntry =>
        val res = s.table._getResources()
        res.foreach(r => r.levelIDs ++= Map(level -> s.id))
        res
    }
  }

  def canEqual(other: Any) = {
    other.isInstanceOf[com.github.katjahahn.parser.sections.rsrc.ResourceDirectory]
  }

  /**
   * Equals another resource directory iff it is at the same file offset.
   */
  override def equals(other: Any) = {
    other match {
      case that: com.github.katjahahn.parser.sections.rsrc.ResourceDirectory => that.canEqual(ResourceDirectory.this) && fileOffset == that.fileOffset
      case _ => false
    }
  }

  /**
   * {@inheritDoc}
   */
  override def hashCode() = {
    val prime = 41
    prime + fileOffset.hashCode
  }
}

object ResourceDirectory {

  /**
   * Represents a resource directory header
   */
  type Header = Map[ResourceDirectoryKey, StandardField]

  private val logger = LogManager.getLogger(ResourceDirectory.getClass().getName());

  /**
   * The size of a resource directory entry
   */
  private val entrySize = 8;

  /**
   * The size of the resource directory header
   */
  private val resourceDirSize = 16;

  /**
   * The name of resource directory specification file
   */
  private val specLocation = "rsrcdirspec"
    
  /**
   * Maximum of resource entries for each directory
   */
  val entryMaximum = 1000

  /**
   * Creates a resource directory.
   *
   * @param file the PE file
   * @param rva the relative virtual address to the resource directory
   * @param level the level in the resource tree of the resource directory to create
   * @param virtualAddress the rva to the resource table
   * @param rsrcOffset the file offset to the resource table
   * @param mmBytes the memory mapped PE
   * @return resource directory
   */
  def apply(file: File, level: Level, rva: Long,
    virtualAddress: Long, rsrcOffset: Long, mmBytes: MemoryMappedPE,
    loopChecker: ResourceLoopChecker): ResourceDirectory = {
    val headerBytes = mmBytes.slice(virtualAddress + rva, resourceDirSize + rva + virtualAddress)
    val header = readHeader(headerBytes, rva)
    val fileOffset = rsrcOffset + rva
    if (!loopChecker.isNewResourceDirFileOffset(fileOffset)) {
      throw new ResourceLoopException("resource loop detected")
    }
    //check for max level and max resourceDirs, don't load entries if reached
    val entries = {
      if (level.levelNr < ResourceSection.maxLevel && loopChecker.size < ResourceSection.maxResourceDirs)
        readEntries(file, header, rva, level, virtualAddress, rsrcOffset,
          mmBytes, loopChecker)
      else List[ResourceDirectoryEntry]()
    }
    new ResourceDirectory(level, header, entries, fileOffset)
  }

  /**
   * Returns the resource directory header.
   *
   * @param tableBytes the bytes representing the table header
   * @param the file offset to the directory header
   * @return resource directory header
   */
  private def readHeader(tableBytes: Array[Byte], tableOffset: Long): Header = {
    val specformat = new SpecificationFormat(0, 1, 2, 3)
    //TODO read header from memory mapped PE?
    IOUtil.readHeaderEntries(classOf[ResourceDirectoryKey], specformat,
      specLocation, tableBytes, tableOffset).asScala.toMap
  }

  /**
   * Reads and returns all resource directory entries.
   *
   * @param file the PE file
   * @param header the resource directory header
   * @param tableOffset the rva to the resource directory
   * @param level the level of the current directory within the resource tree
   * @param virtualAddress the rva to the resource table
   * @param rsrcOffset the file offset to the resource table
   * @param mmBytes the memory mapped PE
   * @return a list of resource directory entries
   */
  private def readEntries(file: File, header: Header, tableOffset: Long,
    level: Level, virtualAddress: Long, rsrcOffset: Long,
    mmBytes: MemoryMappedPE, loopChecker: ResourceLoopChecker): List[ResourceDirectoryEntry] = {
    val nameEntries = header(NR_OF_NAME_ENTRIES).value.toInt
    val idEntries = header(NR_OF_ID_ENTRIES).value.toInt
    val entriesSum = nameEntries + idEntries
    val limitedEntriesSum = if(entriesSum < entryMaximum) entriesSum else entryMaximum
    var entries = ListBuffer.empty[ResourceDirectoryEntry]
    try {
      for (i <- 0 until limitedEntriesSum) {
        val offset = resourceDirSize + i * entrySize + virtualAddress + tableOffset
        val endpoint = offset + entrySize
        val entryNr = i + 1
        val entryBytes = mmBytes.slice(offset, endpoint)
        val isNameEntry = i < nameEntries
        try {
          entries += ResourceDirectoryEntry(file, isNameEntry, entryBytes, entryNr,
            level, virtualAddress, rsrcOffset, mmBytes, loopChecker)
        } catch {
          case e: ResourceLoopException => logger.warn("resource loop detected at va " + offset)
        }
      }
    } catch {
      case e: IllegalArgumentException =>
        logger.warn(e.getMessage());
    }
    entries.toList
  }
}
