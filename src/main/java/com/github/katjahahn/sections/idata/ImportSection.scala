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
package com.github.katjahahn.sections.idata

import com.github.katjahahn.sections.PESection
import com.github.katjahahn.IOUtil.{ NL }
import ImportSection._
import DirectoryTableEntryKey._
import com.github.katjahahn.StandardField
import scala.collection.JavaConverters._
import com.github.katjahahn.optheader.OptionalHeader
import com.github.katjahahn.optheader.OptionalHeader.MagicNumber._
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import com.github.katjahahn.sections.SectionLoader
import com.github.katjahahn.PELoader
import java.io.File
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.sections.SpecialSection
import com.github.katjahahn.tools.anomalies.PEAnomalyScanner
import com.github.katjahahn.PEData

/**
 * Represents the import section, fetches information about the data directory
 * entries and their lookup table entries.
 * TODO forwarder addresses
 * TODO implement lookup for ordinal entries: https://code.google.com/p/pefile/source/detail?r=134
 * @author Katja Hahn
 */
class ImportSection private (
  private val directoryTable: List[DirectoryTableEntry],
  val offset: Long,
  val size: Long) extends SpecialSection {
  
  override def getOffset(): Long = offset
  
  def getSize(): Long = size

  /**
   * Returns the directory table entries of the import section.
   * Each entry contains the lookup table entries that belong to it.
   *
   * @return a list of the directory table entries of the import section
   */
  def getDirectoryTable(): java.util.List[DirectoryTableEntry] = directoryTable.asJava

  /**
   * Generates a description string of all entries
   */
  private def entriesDescription(): String =
    (for (e <- directoryTable)
      yield e.getInfo() + NL + NL).mkString

  def getImports(): java.util.List[ImportDLL] =
    directoryTable.map(e => e.toImportDLL).asJava

  /**
   * Returns a decription of all entries in the import section.
   *
   * @return a description of all entries in the import section
   */
  override def getInfo(): String =
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

  def apply(idatabytes: Array[Byte], virtualAddress: Long,
    optHeader: OptionalHeader, importTableOffsetDiff: Int, fileSize: Long, fileOffset: Long): ImportSection = {
    logger.debug("reading direntries for root table")
    var directoryTable = readDirEntries(idatabytes, virtualAddress, importTableOffsetDiff)
    try {
      readLookupTableEntries(directoryTable, virtualAddress, optHeader, idatabytes, importTableOffsetDiff, fileSize)
    } catch {
      case e: FailureEntryException =>
        //filter empty directoryTableEntries, they are of no use and probably because
        //of collapsed imports or other malformations, example: tinype
        directoryTable = directoryTable.filterNot(_.getLookupTableEntries.isEmpty())
    }
    new ImportSection(directoryTable, fileOffset, idatabytes.length)
  }

  /**
   * Parses all lookup table entries for all entries in the directory table
   * and adds the lookup table entries to the directory table entry they belong to
   */
  private def readLookupTableEntries(directoryTable: List[DirectoryTableEntry],
    virtualAddress: Long, optHeader: OptionalHeader, idatabytes: Array[Byte], importTableOffset: Int, fileSize: Long): Unit = {
    for (dirEntry <- directoryTable) {
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
      logger.debug("offset: " + offset + " rva: " + iRVA + " byteslength: " + idatabytes.length + " virtualAddress " + virtualAddress)
      val EntrySize = optHeader.getMagicNumber match {
        case PE32 => 4
        case PE32_PLUS => 8
        case ROM => throw new IllegalArgumentException("ROM file format not covered by PortEx")
      }
      do {
        entry = LookupTableEntry(idatabytes, offset.toInt, EntrySize, virtualAddress, importTableOffset, relOffset, dirEntry)
        if (!entry.isInstanceOf[NullEntry]) dirEntry.addLookupTableEntry(entry)
        offset += EntrySize
        relOffset += EntrySize
        if(relOffsetMax < relOffset) relOffsetMax = relOffset;
      } while (!entry.isInstanceOf[NullEntry])
    }
  }

  /**
   * Parses all entries of the import section and writes them into the
   * {@link #directoryTable}
   */
  private def readDirEntries(idatabytes: Array[Byte], virtualAddress: Long, importTableOffset: Int): List[DirectoryTableEntry] = {
    val directoryTable = ListBuffer[DirectoryTableEntry]()
    var isLastEntry = false
    var i = 0
    do {
      logger.debug(s"reading ${i + 1}. entry")
      readDirEntry(i, idatabytes, virtualAddress, importTableOffset) match {
        case Some(entry) =>
          logger.debug("------------start-----------")
          logger.debug("dir entry read: " + entry)
          logger.debug("------------end-------------")
          directoryTable += entry
        case None => isLastEntry = true
      }
      i += 1
    } while (!isLastEntry)
    directoryTable.toList
  }

  /**
   * Returns the string for the given directory table entry
   *
   * @param entry the directory table entry whose name shall be returned
   * @return string
   */
  private def getASCIIName(nameRVA: Int, virtualAddress: Long,
    idatabytes: Array[Byte], importTableOffset: Int): String = {
    val offset = nameRVA - virtualAddress + importTableOffset
    //TODO cast to int is insecure. actual int is unsigned, java int is signed
    val nullindex = idatabytes.indexWhere(_ == 0, offset.toInt)
    new String(idatabytes.slice(offset.toInt, nullindex))
  }

  /**
   * Parses the directory table entry at the given nr.
   *
   * @param nr the number of the entry
   * @return Some entry if the entry at the given nr is not the null entry,
   * None otherwise
   */
  private def readDirEntry(nr: Int, idatabytes: Array[Byte], virtualAddress: Long, importTableOffset: Int): Option[DirectoryTableEntry] = {
    val from = nr * ENTRY_SIZE + importTableOffset
    logger.debug("reading from: " + from)
    val until = from + ENTRY_SIZE
    if (relOffsetMax < until) relOffsetMax = until
    logger.debug("reading until: " + until)
    val entrybytes = idatabytes.slice(from, until)
    if (entrybytes.length < ENTRY_SIZE) return None

    /**
     * @return true iff the given entry is not the last empty entry or null entry
     */
    def isEmpty(entry: DirectoryTableEntry): Boolean =
      //this was my first try based on the spec, but didn't always work
      //entry.entries.values.forall(v => v == 0) 
      entry(I_LOOKUP_TABLE_RVA) == 0 && entry(I_ADDR_TABLE_RVA) == 0

    val entry = DirectoryTableEntry(entrybytes)
    logger.debug("entry info ---> \n" + entry.getInfo + "\n ----> end of entry info\n")
    entry.name = getASCIIName(entry(NAME_RVA).toInt, virtualAddress, idatabytes, importTableOffset)
    logger.debug("entry name: " + entry.name)
    if (entry(FORWARDER_CHAIN) != 0) {
      entry.forwarderString = getASCIIName(entry(FORWARDER_CHAIN).toInt, virtualAddress, idatabytes, importTableOffset)
      logger.debug("forwarder string: " + entry.forwarderString)
    }
    if (isEmpty(entry)) None else
      Some(entry)
  }

  /**
   * The instance of this class is usually created by the section loader.
   *
   * @param idatabytes the bytes that belong to the import section
   * @param virtualAddress the address all rva values in the import section are relative to
   * @param optHeader the optional header of the file
   * @param importTableOffset
   * @param fileSize
   * @return ImportSection instance
   */
  def newInstance(idatabytes: Array[Byte], virtualAddress: Long,
    optHeader: OptionalHeader, offsetDiff: Int, fileSize: Long, fileOffset: Long): ImportSection =
    apply(idatabytes, virtualAddress, optHeader, offsetDiff, fileSize, fileOffset)
    
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
    //    val file = new File("src/main/resources/x64viruses/VirusShare_baed21297974b6adf3298585baa78691")
    val file = new File("src/main/resources/unusualfiles/tinype/downloader.exe")
    val data = PELoader.loadPE(file)
    println(data)
    val loader = new SectionLoader(data)
    val idata = loader.loadImportSection()
    if (idata != null) {
      println(idata.getInfo)
    } else {
      println("import section null")
    }
    println(PEAnomalyScanner.newInstance(data).scanReport)
  }

  /**
   * Size of one entry is {@value}.
   * It is used to calculate the offset of an entry.
   */
  private final val ENTRY_SIZE = 20

  private final val logger = LogManager.getLogger(ImportSection.getClass().getName())
}
