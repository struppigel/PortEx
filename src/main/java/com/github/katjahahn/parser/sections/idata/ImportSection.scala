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
package com.github.katjahahn.parser.sections.idata

import com.github.katjahahn.parser.IOUtil.NL
import com.github.katjahahn.parser._
import com.github.katjahahn.parser.optheader.OptionalHeader.MagicNumber._
import com.github.katjahahn.parser.optheader.{OptionalHeader, WindowsEntryKey}
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.sections.{SectionLoader, SpecialSection}
import com.github.katjahahn.parser.sections.idata.DirectoryEntryKey._
import org.apache.logging.log4j.LogManager

import java.io.File
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

/**
 * Represents the import section, fetches information about the data directory
 * entries and their lookup table entries.
 *
 * @author Katja Hahn
 */
//TODO implement lookup for ordinal entries: https://code.google.com/p/pefile/source/detail?r=134
class ImportSection private (
  private val directoryTable: List[DirectoryEntry],
  private val offset: Long) extends SpecialSection {

  /**
   * {@inheritDoc}
   */
  override def getOffset: Long = offset

  /**
   * {@inheritDoc}
   */
  override def isEmpty: Boolean = directoryTable.isEmpty || directoryTable.forall(_.getEntries().isEmpty)

  /**
   * Returns the directory table entries of the import section.
   * Each entry contains the lookup table entries that belong to it.
   *
   * @return a list of the directory table entries of the import section
   */
  def getDirectory: java.util.List[DirectoryEntry] = directoryTable.asJava

  /**
   * Generates a description string of all entries
   */
  private def entriesDescription: String =
    (for (e <- directoryTable)
      yield e.getInfo() + NL + NL).mkString

  /**
   * @return a list of all import entries found
   */
  def getImports: java.util.List[ImportDLL] =
    directoryTable.map(e => e.toImportDLL()).asJava

  /**
   *
   * @return a list with all locations the import information has been written to.
   */
  //TODO include IAT and ILT, add string locations
  def getPhysicalLocations: java.util.List[PhysicalLocation] = {
    val ranges = Location.mergeContinuous(directoryTable.foldRight(
        List[PhysicalLocation]())((entry, list) => entry.getPhysicalLocations ::: list))
    ranges.asJava
  }

  /**
   * Returns a decription of all entries in the import section.
   *
   * @return a description of all entries in the import section
   */
  override def getInfo: String =
    s"""|--------------
	|Import section
	|--------------
    |
    |$entriesDescription""".stripMargin

}

object ImportSection {

  /**
   * Maximum offset the import section has values in (used to determine the accurate size)
   */
  private var relOffsetMax = 0L

  def apply(li: LoadInfo): ImportSection =
    apply(li.memoryMapped, li.va, li.data.getOptionalHeader, li.data.getFile.length(), li.fileOffset)

  def apply(mmbytes: MemoryMappedPE, virtualAddress: Long,
    optHeader: OptionalHeader, fileSize: Long, fileOffset: Long): ImportSection = {
    logger.debug("reading directory entries for root table ...")
    // read directory table (as a list of entries)
    var directoryTable = readDirEntries(mmbytes, virtualAddress, fileOffset)
    logger.debug(directoryTable.size + " directory entries read")
    logger.debug("reading lookup table entries ...")
    try {
      // read all lookup table entries
      readLookupTableEntries(directoryTable, virtualAddress, optHeader, mmbytes, 
          fileSize, fileOffset)
    } catch {
      case e: FailureEntryException => logger.warn(
          "Invalid LookupTableEntry found, parsing aborted, " + e.getMessage)
    }
    //filter empty directoryTableEntries, they are of no use and probably because
    //of collapsed imports or other malformations, example: tinype
    directoryTable = directoryTable.filterNot(_.getLookupTableEntries().isEmpty())
    new ImportSection(directoryTable, fileOffset)
  }

  /**
   * Parses all lookup table entries for all entries in the directory table
   * and adds the lookup table entries to the directory table entry they belong to
   * 
   * @param directoryTable the directory table to get the lookup table entries from
   * @param virtualAddress the address to the import section
   * @param optHeader the optional header
   * @param mmbytes the memory mapped PE
   * @param fileSize the length of the file in bytes
   * @param fileOffset file offset to the directory table
   */
  private def readLookupTableEntries(directoryTable: List[DirectoryEntry],
    virtualAddress: Long, optHeader: OptionalHeader, mmbytes: MemoryMappedPE,
    fileSize: Long, fileOffset: Long): Unit = {
    //set a maximum of entries to avoid problems with, e.g., manyimportsW7.exe
    var entryCounter = 0
    val importMax = 10000 
    for (dirEntry <- directoryTable if entryCounter < importMax) {
      var entry: LookupTableEntry = null
      var iRVA = dirEntry(I_LOOKUP_TABLE_RVA)
      if (iRVA == 0 || (iRVA - virtualAddress) > fileSize) {
        iRVA = dirEntry(I_ADDR_TABLE_RVA)
        logger.debug("using IAT rva")
      } else {
        logger.debug("using ILT rva")
      }
      var offset = iRVA - virtualAddress
      var relOffset = iRVA
      val iVA = iRVA + optHeader.get(WindowsEntryKey.IMAGE_BASE)
      logger.debug("offset: " + offset + " rva: " + iRVA + " byteslength: " + 
          mmbytes.length() + " virtualAddress " + virtualAddress)
      val EntrySize = optHeader.getMagicNumber match {
        case PE32 => 4
        case PE32_PLUS => 8
        case ROM => throw new IllegalArgumentException("ROM file format not covered by PortEx")
        case UNKNOWN => throw new IllegalArgumentException("Unknown magic number")
      }
      do {
        //TODO get fileoffset for entry from mmbytes instead of this to avoid
        //fractionated section issues ?
        val entryFileOffset = fileOffset + offset 
//        val entryFileOffset = mmbytes.getPhysforVir(iRVA) //doesn't work
        entry = LookupTableEntry(mmbytes, offset.toInt, EntrySize, 
            virtualAddress, relOffset, iVA, dirEntry, entryFileOffset)
        if (!entry.isInstanceOf[NullEntry]) {
          dirEntry.addLookupTableEntry(entry)
          entryCounter += 1
        }
        offset += EntrySize
        relOffset += EntrySize
        if (relOffsetMax < relOffset) relOffsetMax = relOffset
      } while (!entry.isInstanceOf[NullEntry] && entryCounter < importMax)
    }
  }

  /**
   * Parses all entries of the import section and writes them into the
   * {@link directoryTable}
   */
  private def readDirEntries(mmbytes: MemoryMappedPE,
    virtualAddress: Long, fileOffset: Long): List[DirectoryEntry] = {
    val directoryTable = ListBuffer[DirectoryEntry]()
    var isLastEntry = false
    var i = 0
    val dirEntryMax = 10000
    do {
      logger.debug(s"reading ${i + 1}. entry")
      readDirEntry(i, mmbytes, virtualAddress, fileOffset) match {
        case Some(entry) =>
          logger.debug("------------start-----------")
          logger.debug("dir entry read: " + entry)
          logger.debug("------------end-------------")
          directoryTable += entry
        case None => isLastEntry = true
      }
      i += 1
    } while (!isLastEntry && i < dirEntryMax)
    directoryTable.toList
  }

  private def getASCIIName(nameRVA: Int, virtualAddress: Long,
    mmbytes: MemoryMappedPE): String = {
    val offset = nameRVA
    val nullindex = mmbytes.indexWhere(_ == 0, offset)
    new String(mmbytes.slice(offset, nullindex))
  }

  /**
   * Parses the directory table entry at the given nr.
   *
   * @param nr the number of the entry
   * @return Some entry if the entry at the given nr is not the null entry,
   * None otherwise
   */
  private def readDirEntry(nr: Int, mmbytes: MemoryMappedPE,
    virtualAddress: Long, fileOffset: Long): Option[DirectoryEntry] = {
    val from = nr * ENTRY_SIZE + virtualAddress
    logger.debug("reading from: " + from)
    val until = from + ENTRY_SIZE
    if (relOffsetMax < until) relOffsetMax = until
    logger.debug("reading until: " + until)
    val entrybytes = mmbytes.slice(from, until)
    if (entrybytes.length < ENTRY_SIZE) return None

    /**
     * @return true iff the given entry is not the last empty entry or null entry
     */
    def isEmpty(entry: DirectoryEntry): Boolean =
      //this was my first try based on the spec, but didn't always work
      //entry.entries.values.forall(v => v == 0) 
      entry(I_LOOKUP_TABLE_RVA) == 0 && entry(I_ADDR_TABLE_RVA) == 0

    val entry = DirectoryEntry(entrybytes, fileOffset + (nr * ENTRY_SIZE))
    entry.name = getASCIIName(entry(NAME_RVA).toInt, virtualAddress, mmbytes)
    logger.debug("entry name: " + entry.name)
    if (entry(FORWARDER_CHAIN) != 0) {
      entry.forwarderString = getASCIIName(entry(FORWARDER_CHAIN).toInt, virtualAddress, mmbytes)
      logger.debug("forwarder string: " + entry.forwarderString)
    }
    if (isEmpty(entry)) None else
      Some(entry)
  }

  /**
   * The instance of this class is usually created by the section loader.
   *
   * @param loadInfo
   * @return ImportSection instance
   */
  def newInstance(loadInfo: LoadInfo): ImportSection = apply(loadInfo)

  /**
   * Loads the import section and returns it.
   *
   * This is just a shortcut to loading the section using the {@link SectionLoader}
   *
   * @return instance of the import section
   */
  def load(data: PEData): ImportSection =
    new SectionLoader(data).loadImportSection()

  def main(args: Array[String]): Unit = {
    val file = new File("/home/deque/portextestfiles/unusualfiles/tinype/downloader.exe")
    val data = PELoader.loadPE(file)
    val loader = new SectionLoader(data)
    val idata = loader.loadImportSection()
    if (idata != null) {
      println(idata.getInfo)
    } else {
      println("import section null")
    }
  }

  /**
   * Size of one entry is {@value}.
   * It is used to calculate the offset of an entry.
   */
  private final val ENTRY_SIZE = 20

  private final val logger = LogManager.getLogger(ImportSection.getClass.getName)
}
