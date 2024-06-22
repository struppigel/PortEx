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
package com.github.struppigel.parser.sections.rsrc

import com.github.struppigel.parser.IOUtil.SpecificationFormat
import ResourceDirectory._
import ResourceDirectoryKey._
import com.github.struppigel.parser.{IOUtil, MemoryMappedPE, PhysicalLocation, StandardField}
import org.apache.logging.log4j.LogManager

import java.io.File
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

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
 * @param fileOffset the offset of the resource directory
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
  def getHeaderValue(key: ResourceDirectoryKey): Long = header(key).getValue

  /**
   * Collects and returns a distinct list of resources that this 
   * resource table tree has.
   *
   * @param mmBytes the memory mapped PE
   * @return a list of all resources
   */
  def getUniqueResources(): java.util.List[Resource] =
    _getResources().distinct.asJava

  
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
    other.isInstanceOf[ResourceDirectory]
  }

  /**
   * Equals another resource directory iff it is at the same file offset.
   */
  override def equals(other: Any) = {
    other match {
      case that: ResourceDirectory => that.canEqual(ResourceDirectory.this) && fileOffset == that.fileOffset
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

  private val logger = LogManager.getLogger(ResourceDirectory.getClass().getName())

  /**
   * The size of a resource directory entry
   */
  private val entrySize = 8

  /**
   * The size of the resource directory header
   */
  private val resourceDirSize = 16

  /**
   * The name of resource directory specification file
   */
  private val specLocation = "rsrcdirspec"

  /**
   * Maximum of resource entries for each directory
   */
  val entryMaximum = 500

  /**
   * Creates a resource directory.
   *
   * @param file the PE file
   * @param level the level in the resource tree of the resource directory to create
   * @param rsrcDirRVA the relative virtual address to the resource directory,
   *        relative to the resource table va
   * @param rsrcVA the rva to the resource table
   * @param rsrcOffset the file offset to the resource table
   * @param mmBytes the memory mapped PE
   * @param loopChecker the resource loop checker
   * @return resource directory
   */
  def apply(file: File, level: Level, rsrcDirRVA: Long,
            rsrcVA: Long, rsrcOffset: Long, mmBytes: MemoryMappedPE,
            loopChecker: ResourceLoopChecker): ResourceDirectory = {
    // fetch the bytes of the resource directory header
    val headerBytes = mmBytes.slice(rsrcVA + rsrcDirRVA, resourceDirSize + rsrcDirRVA + rsrcVA)
    // read the header data from the bytes
    val header = readHeader(headerBytes, rsrcDirRVA)
    // calculate the file offset to the resource directory header
    val fileOffset = rsrcOffset + rsrcDirRVA
    // check for resource loop
    if (!loopChecker.isNewResourceDirFileOffset(fileOffset)) {
      throw new ResourceLoopException("resource loop detected")
    }
    //check for max level and max resourceDirs, don't load entries if reached
    val entries = {
      if (level.levelNr < ResourceSection.maxLevel && loopChecker.size < ResourceSection.maxResourceDirs)
        readEntries(file, header, rsrcDirRVA, level, rsrcVA, rsrcOffset,
          mmBytes, loopChecker)
      // no loading
      else List[ResourceDirectoryEntry]()
    }
    // create resource directory with header, entries and file offset
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
    IOUtil.readHeaderEntries(classOf[ResourceDirectoryKey], specformat,
      specLocation, tableBytes, tableOffset).asScala.toMap
  }

  /**
   * Reads and returns all resource directory entries.
   *
   * @param file the PE file
   * @param header the resource directory header
   * @param rsrcDirRVA the relative virtual address to the resource directory,
   *        relative to the resource table va
   * @param level the level of the current directory within the resource tree
   * @param virtualAddress the rva to the resource table
   * @param rsrcOffset the file offset to the resource table
   * @param mmBytes the memory mapped PE
   * @param loopChecker the resource loop checker
   * @return a list of resource directory entries
   */
  private def readEntries(file: File, header: Header, rsrcDirRVA: Long,
                          level: Level, virtualAddress: Long, rsrcOffset: Long,
                          mmBytes: MemoryMappedPE, loopChecker: ResourceLoopChecker): List[ResourceDirectoryEntry] = {
    // fetch number of name entries
    val nameEntries = header(NR_OF_NAME_ENTRIES).getValue.toInt
    logger.debug("number of name entries: " + nameEntries)
    // fetch number of id entries
    val idEntries = header(NR_OF_ID_ENTRIES).getValue.toInt
    logger.debug("number of id entries: " + idEntries)
    // number of all entries
    val entriesSum = nameEntries + idEntries
    logger.debug("entriesSum: " + entriesSum)
    // we limit the number to maximum if reached
    val limitedEntriesSum = if (entriesSum < entryMaximum) entriesSum else entryMaximum
    logger.debug("limited entriesSum: " + limitedEntriesSum)
    val entries = ListBuffer.empty[ResourceDirectoryEntry]
    val offsets: ListBuffer[Long] = scala.collection.mutable.ListBuffer.empty
    try {
      for (i <- 0 until limitedEntriesSum) {
        // calculate the offset for the entry
        val offset = resourceDirSize + i * entrySize + virtualAddress + rsrcDirRVA
        // the offset to the end of the entry
        val endpoint = offset + entrySize
        // actual number of the entry is index + 1
        val entryNr = i + 1
        // now read entry bytes
        val entryBytes = mmBytes.slice(offset, endpoint)
        // number of name entries defines if this is one
        val isNameEntry = i < nameEntries
        try {
          // create and add entry to the list
          val possibleEntry = ResourceDirectoryEntry(file, isNameEntry, entryBytes, entryNr,
            level, virtualAddress, rsrcOffset, mmBytes, loopChecker)
          // if(isValidEntry(possibleEntry, file.length())) { //TODO find a different solution!
            entries += possibleEntry
          //} else {logger.warn("invalid resource entry")} //TODO add these to anomalies!
        } catch {
          // resource loop detected during entry creation
          case e: ResourceLoopException => logger.warn("resource loop detected at va " + offset);
        }
      }
    } catch {
      case e: IllegalArgumentException =>
        logger.warn(e.getMessage())
    }
    entries.toList
  }

  private def isValidEntry(entry: ResourceDirectoryEntry, maximum: Long): Boolean =
    entry.locations().forall { loc => loc.from > 0 && (loc.size + loc.from) < maximum }
}
