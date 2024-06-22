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
package com.github.struppigel.parser.sections.edata

import com.github.struppigel.parser.IOUtil.NL
import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import ExportDirectoryKey._
import com.github.struppigel.parser.optheader.DataDirectoryKey
import com.github.struppigel.parser.sections.{SectionLoader, SpecialSection}
import com.github.struppigel.parser.{FileFormatException, Location, MemoryMappedPE, PhysicalLocation}
import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import org.apache.logging.log4j.LogManager

import java.io.File
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

/**
 * Represents the export section of a PE file and provides access to lists of
 * it's inner structures (export address table, ordinal table, name pointer table,
 * data directory table) as well as access to a list of export entries fetched
 * from these structures.
 * <p>
 * The export section instance should be created with the {@link SectionLoader}
 *
 * @author Katja Hahn
 *
 * Creates an export section instance
 * @param edataTable the data directory table
 * @param exportAddressTable contains addresses to exported functions
 * @param namePointerTable contains addresses to names of exported functions
 * @param ordinalTable contains ordinal number of exported functions
 * @param exportEntries a list of all exports
 * @param offset to the beginning of the export section
 * @param secLoader the section loader instance
 * @param invalidExportCount the number of invalid export entries
 */
class ExportSection private (
  private val edataTable: ExportDirectory,
  private val exportAddressTable: ExportAddressTable,
  private val namePointerTable: ExportNamePointerTable,
  private val ordinalTable: ExportOrdinalTable,
  val exportEntries: List[ExportEntry],
  val offset: Long,
  val secLoader: SectionLoader,
  val invalidExportCount: Integer) extends SpecialSection {

  override def getOffset(): Long = offset

  override def isEmpty(): Boolean = exportEntries.isEmpty

  /**
   * @return physical location of all ASCII strings with export names
   */
  private def nameLocations(): List[PhysicalLocation] = {
    namePointerTable.pointerNameList.map(p =>
      new PhysicalLocation(secLoader.getFileOffset(p._1), ExportNamePointerTable.entryLength))
  }

  /**
   * @return all physical export locations including tables and ASCII strings with export names
   */
  def getPhysicalLocations(): java.util.List[PhysicalLocation] = if (isEmpty) List[PhysicalLocation]().asJava else
    Location.mergeContinuous(
      List(new PhysicalLocation(edataTable.fileOffset, edataTable.size),
        new PhysicalLocation(exportAddressTable.fileOffset, exportAddressTable.getSize),
        new PhysicalLocation(namePointerTable.fileOffset, namePointerTable.size),
        new PhysicalLocation(ordinalTable.fileOffset, ordinalTable.size))
        ::: nameLocations).asJava

  /**
   * Returns the export directory table which contains general information and
   * information about the other tables in the export section
   *
   * @return the export directory table
   */
  def getExportDirectory(): ExportDirectory = edataTable

  /**
   * Returns the export addresses that are in the export address table.
   *
   * @return a list of export addresses
   */
  def getExportAddresses(): java.util.List[Long] = exportAddressTable.addresses.asJava

  /**
   * Returns a map of address-name pairs contained in the name pointer table
   *
   * @return a map that contains addresses as key and names as value
   */
  def getPointerNameMap(): java.util.Map[Long, String] = namePointerTable.getMap.asJava

  /**
   * Returns a list of all pointers of the name pointer table, ordered.
   *
   * @return all pointers/addresses of the name pointer table
   */
  def getNamePointers(): java.util.List[Long] = namePointerTable.pointerNameList.map(_._1).asJava

  /**
   * Returns an ordered list of all ordinals in the ordinal table
   *
   * @return a list of all ordinals in the order they are found in the ordinal table
   */
  def getOrdinals(): java.util.List[Int] = ordinalTable.ordinals.asJava

  /**
   * Returns the ordinal for a given name.
   *
   * This maps a given name of the name pointer table to the ordinal in the
   * ordinal table.
   *
   * @param name the name of an exported function
   * @return the ordinal for the given function name
   */
  def getOrdinalForName(name: String): Int = ordinalTable.ordinals(namePointerTable(name))

  /**
   * Returns the relative virtual address for a given function name.
   *
   * This maps a name of the name pointer table the corresponding address of
   * the export address table.
   *
   * @param name the name of the exported function
   * @return the rva out of the address table for a function name
   */
  def getSymbolRVAForName(name: String): Long = {
    val ordinal = getOrdinalForName(name)
    if (ordinal == -1) -1 else exportAddressTable(ordinal - ordinalTable.base)
  }

  /**
   * Returns a list of all export entries found in the export section
   *
   * @return a list of all export entries
   */
  def getExportEntries(): java.util.List[ExportEntry] = exportEntries.asJava

  /**
   * Returns a detailed info string that represents the inner structure of the
   * export section. That means the contents of the different tables are not
   * mapped to each other.
   *
   * @return a detailed info string
   */
  def getDetailedInfo(): String =
    s"""|--------------
    	|Export Section
    	|--------------
    	|${edataTable.getInfo}
  		|
  		|${exportAddressTable.toString}
  		|
  		|${namePointerTable.toString}
  		|
  		|${ordinalTable.toString}""".stripMargin

  /**
   * Returns a description string of the export entries found.
   *
   * @return description string
   */
  override def getInfo(): String =
    s"""|--------------
        |Export Section
        |--------------
        |
        |Name, Ordinal, RVA
        |...................
        |${exportEntries.mkString(NL)}""".stripMargin

}

object ExportSection {

  private val logger = LogManager.getLogger(ExportSection.getClass().getName())

  val maxNameEntries = 5000
  val maxOrdEntries = 5000
  private var invalidExportCount = 0

  @throws(classOf[FileFormatException])
  def apply(li: LoadInfo): ExportSection = {
    //TODO slice only headerbytes for ExportDir
    invalidExportCount = 0
    val mmBytes = li.memoryMapped
    val offset = li.fileOffset
    val exportBytes = mmBytes.slice(li.va, mmBytes.length + li.va)
    val edataTable = ExportDirectory(exportBytes, offset)
    val exportAddressTable = loadExportAddressTable(edataTable, mmBytes, li.va, offset)
    val namePointerTable = loadNamePointerTable(edataTable, mmBytes, li.va, offset)
    val ordinalTable = loadOrdinalTable(edataTable, mmBytes, li.va, offset)
    val exportEntries = loadExportEntries(li, namePointerTable, ordinalTable,
      exportAddressTable, edataTable)
    new ExportSection(edataTable, exportAddressTable, namePointerTable,
      ordinalTable, exportEntries, offset, li.loader, invalidExportCount)
  }

  /**
   * Loads the ordinal table.
   * 
   * @param edataTable export directory table
   * @param mmBytes the memory mapped bytes
   * @param virtualAddress to the start of the export section
   * @param edataOffset file offset to the export section
   * @return ordinal table
   */
  private def loadOrdinalTable(edataTable: ExportDirectory,
    mmBytes: MemoryMappedPE, virtualAddress: Long, edataOffset: Long): ExportOrdinalTable = {
    val base = edataTable(ORDINAL_BASE)
    val rva = edataTable(ORDINAL_TABLE_RVA)
    val entries = edataTable(NR_OF_NAME_POINTERS)
    val ordTableFileOffset = edataOffset + rva - virtualAddress
    if(ordTableFileOffset <= 0 || entries < 0) {
      // create empty ExportOrdinalTable
      return new ExportOrdinalTable(List.empty[Int], base.toInt, 0L)
    } 
    ExportOrdinalTable(mmBytes, base.toInt, rva, entries.toInt, virtualAddress, ordTableFileOffset)
  }

  /**
   * Loads the name pointer table.
   * 
   * @param edataTable export directory table
   * @param mmBytes the memory mapped bytes
   * @param virtualAddress to the start of the export section
   * @param edataOffset file offset to the export section
   * @return name pointer table
   */
  private def loadNamePointerTable(edataTable: ExportDirectory,
    mmBytes: MemoryMappedPE, virtualAddress: Long, edataOffset: Long): ExportNamePointerTable = {
    val nameTableRVA = edataTable(NAME_POINTER_RVA)
    val namePointers = edataTable(NR_OF_NAME_POINTERS).toInt
    val nameTableFileOffset = edataOffset + nameTableRVA - virtualAddress
    ExportNamePointerTable(mmBytes, nameTableRVA, namePointers, virtualAddress, nameTableFileOffset)
  }

  /**
   * Loads the EAT.
   *
   * @param offset file offset of the export directory table
   */
  @throws(classOf[FileFormatException])
  private def loadExportAddressTable(edataTable: ExportDirectory,
    mmBytes: MemoryMappedPE, virtualAddress: Long, offset: Long): ExportAddressTable = {
    val addrTableRVA = edataTable(EXPORT_ADDR_TABLE_RVA)
    val entries = edataTable(ADDR_TABLE_ENTRIES).toInt
    if (addrTableRVA > mmBytes.length) {
      throw new FileFormatException("invalid address table rva, can not parse export section")
    }
    val fileOffset = offset + addrTableRVA - virtualAddress
    ExportAddressTable(mmBytes, addrTableRVA, entries, virtualAddress, fileOffset)
  }

  /**
   * Loads all assumed valid export entries.
   * 
   * An export entry is assumed valid, iff the RVA translates to a fileOffset 
   * that points inside the file (0 <= offset <= filesize)
   * 
   * @param li load information
   * @param namePointerTable
   * @param ordinalTable
   * @param exportAddressTable
   * @param edataTable
   * @return list of all assumed valid export entries
   */
  private def loadExportEntries(li: LoadInfo,
    namePointerTable: ExportNamePointerTable,
    ordinalTable: ExportOrdinalTable,
    exportAddressTable: ExportAddressTable,
    edataTable: ExportDirectory): List[ExportEntry] = {
    //unpack some loadInfo data
    val optHeader = li.data.getOptionalHeader
    val virtualAddress = li.va
    val sectionLoader = li.loader
    val mmBytes = li.memoryMapped
    val file = li.data.getFile
    
    // see: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
    // "if the function's RVA is inside the exports section (as given by the
    // VirtualAddress and Size fields in the DataDirectory), the symbol is forwarded."
    def isForwarderRVA(rva: Long): Boolean = {
      val maybeEdata = optHeader.maybeGetDataDirEntry(DataDirectoryKey.EXPORT_TABLE)
      if (maybeEdata.isPresent) {
        val edata = maybeEdata.get
        rva >= edata.getVirtualAddress && rva <= edata.getVirtualAddress + edata.getDirectorySize
      } else false
    }

    def getForwarder(rva: Long): Option[String] = if (isForwarderRVA(rva)) {
      Some(getASCIIName(rva, virtualAddress, mmBytes))
    } else None

    val rvas = ListBuffer[Long]()
    val names = namePointerTable.pointerNameList.map(_._2)
    
    // limit name entries to read to maximum
    val namesLimited = if (names.length > maxNameEntries) names.take(maxNameEntries) else names
    // create name entries
    val nameEntries: List[ExportEntry] = (namesLimited map { name =>
      val rva = getSymbolRVAForName(name, exportAddressTable, ordinalTable, namePointerTable)
      isValidRVAAndCountInvalid(rva, sectionLoader, file, rvas) // only for count
      val ordinal = getOrdinalForName(name, ordinalTable, namePointerTable)
      Some(new ExportNameEntry(rva, name, ordinal, getForwarder(rva)))
    }).flatten
    
    val addresses = exportAddressTable.addresses
    val ordinalBase = edataTable.get(ExportDirectoryKey.ORDINAL_BASE)
    
    //TODO this is rather an address maximum
    val ordMax = Math.min(addresses.length, maxOrdEntries)
    // create ordinal entries
    val ordEntries = (for (
      i <- 0 until ordMax;
      if !ordinalTable.ordinals.contains(i + ordinalBase)
    ) yield {
      val rva = addresses(i)
      if (isValidRVAAndCountInvalid(rva, sectionLoader, file, rvas)) {
        val forwarder = getForwarder(rva)
        val ordinal = (i + ordinalBase).toInt
        Some(new ExportEntry(rva, ordinal, forwarder))
      } else {
        None
      }
    }).flatten
    
    //    assert(nameEntries.size == edataTable.get(ExportDirectoryKey.NR_OF_NAME_POINTERS))
    //    assert(ordEntries.size == edataTable.get(ExportDirectoryKey.ADDR_TABLE_ENTRIES) -
    //      edataTable.get(ExportDirectoryKey.NR_OF_NAME_POINTERS))
    if (!(nameEntries.size == edataTable.get(ExportDirectoryKey.NR_OF_NAME_POINTERS))) {
      logger.warn("corrupt export name entries")
    }
    if (!(ordEntries.size == edataTable.get(ExportDirectoryKey.ADDR_TABLE_ENTRIES) -
      edataTable.get(ExportDirectoryKey.NR_OF_NAME_POINTERS))) {
      logger.warn("corrupt export ordinal entries")
    }

    ordEntries.toList ::: nameEntries.toList
  }

  /**
   * Adds the rva to the rvas list. Counts up if rva invalid. Returns true iff rva is valid.
   */
  private def isValidRVAAndCountInvalid(rva: Long, loader: SectionLoader, file: File, rvas: ListBuffer[Long]): Boolean = {
    // no rva duplicates allowed TODO consider, creates false unit tests
    //    if (rvas.contains(rva)) {
    //      invalidExportCount += 1
    //      false
    //    } else {
    rvas += rva
    val offset = loader.getFileOffset(rva)
    if (offset < file.length() && offset >= 0)
      true
    else {
      invalidExportCount += 1
      false
    }
    //    }
  }

  /**
   * Returns the name for a given ordinal.
   *
   * This maps a given name of the name pointer table to the ordinal in the
   * ordinal table.
   *
   * @param name the name of an exported function
   * @return the ordinal for the given function name
   */
  private def getOrdinalForName(name: String, ordinalTable: ExportOrdinalTable,
    namePointerTable: ExportNamePointerTable): Int = {
      val addr = namePointerTable(name)
      if (addr >= 0 && addr < ordinalTable.ordinals.length)
        ordinalTable.ordinals(addr)
      else -1
  }

  /**
   * Returns the relative virtual address for a given function name.
   *
   * This maps a name of the name pointer table the corresponding address of
   * the export address table.
   *
   * @param name the name of the exported function
   * @return the rva out of the address table for a function name
   */
  private def getSymbolRVAForName(name: String, exportAddressTable: ExportAddressTable,
    ordinalTable: ExportOrdinalTable, namePointerTable: ExportNamePointerTable): Long = {
    val ordinal = getOrdinalForName(name, ordinalTable, namePointerTable)
    if (ordinal == -1 || (ordinal - ordinalTable.base) >= exportAddressTable.getNrOfAddresses) -1
    else exportAddressTable(ordinal - ordinalTable.base)
  }

  private def getASCIIName(nameRVA: Long, virtualAddress: Long,
    mmBytes: MemoryMappedPE): String = {
    val offset = nameRVA
    val nullindex = mmBytes.indexWhere(_ == 0, offset)
    new String(mmBytes.slice(offset, nullindex))
  }

  /**
   * Creates an instance of the export section by loading all necessary
   * information from the given export section bytes
   *
   * @param loadInfo the load information
   * @return instance of the export section
   */
  @throws(classOf[FileFormatException])
  def newInstance(loadInfo: LoadInfo): ExportSection = apply(loadInfo)

}
