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
package com.github.katjahahn.parser.sections.edata

import com.github.katjahahn.parser.IOUtil.{ NL }
import scala.collection.JavaConverters._
import java.io.File
import ExportDirectoryKey._
import com.github.katjahahn.parser.optheader.OptionalHeader
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.SectionHeader
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import com.github.katjahahn.parser.MemoryMappedPE
import com.github.katjahahn.parser.FileFormatException
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.PhysicalLocation
import org.apache.logging.log4j.LogManager
import com.github.katjahahn.tools.visualizer.Visualizer

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
 * @param namePointerTable containes addresses to names of exported functions
 * @param ordinalTable contains ordinal number of exported functions
 */
class ExportSection private (
  private val edataTable: ExportDirectory,
  private val exportAddressTable: ExportAddressTable,
  private val namePointerTable: ExportNamePointerTable,
  private val ordinalTable: ExportOrdinalTable,
  val exportEntries: List[ExportEntry],
  val offset: Long,
  val secLoader: SectionLoader) extends SpecialSection {

  override def getOffset(): Long = offset

  override def isEmpty(): Boolean = exportEntries.isEmpty

  private def nameLocations(): List[PhysicalLocation] = {
    namePointerTable.pointerNameList.map(p =>
      new PhysicalLocation(secLoader.getFileOffset(p._1), ExportNamePointerTable.entryLength))
  }

  def getPhysicalLocations(): java.util.List[PhysicalLocation] = if (isEmpty) List[PhysicalLocation]().asJava else
    Location.mergeContinuous(
      List(new PhysicalLocation(edataTable.fileOffset, edataTable.size),
        new PhysicalLocation(exportAddressTable.fileOffset, exportAddressTable.size),
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
   * Returns the name for a given ordinal.
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
  
  val logger = LogManager.getLogger(ExportSection.getClass().getName());

  def main(args: Array[String]): Unit = {
    val data = PELoader.loadPE(new File("/home/deque/portextestfiles/testfiles/DLL2.dll")) //TODO correct ordinal and rva of this? see tests
    val loader = new SectionLoader(data)
    val edata = loader.loadExportSection()
    println(edata.getDetailedInfo)
    println()
    println(edata.getInfo)
  }

  def apply(li: LoadInfo): ExportSection =
    apply(li.memoryMapped, li.va, li.data.getOptionalHeader(), li.loader, li.fileOffset)

  def apply(mmBytes: MemoryMappedPE, virtualAddress: Long,
    opt: OptionalHeader, sectionLoader: SectionLoader, offset: Long): ExportSection = {
    //TODO slice only headerbytes for ExportDir
    val exportBytes = mmBytes.slice(virtualAddress, mmBytes.length + virtualAddress);
    val edataTable = ExportDirectory(exportBytes, offset)
    val exportAddressTable = loadExportAddressTable(edataTable, mmBytes, virtualAddress, offset)
    val namePointerTable = loadNamePointerTable(edataTable, mmBytes, virtualAddress, offset)
    val ordinalTable = loadOrdinalTable(edataTable, mmBytes, virtualAddress, offset)
    val exportEntries = loadExportEntries(sectionLoader, namePointerTable, opt,
      ordinalTable, exportAddressTable, mmBytes, virtualAddress, edataTable)
    new ExportSection(edataTable, exportAddressTable, namePointerTable,
      ordinalTable, exportEntries, offset, sectionLoader)
  }

  private def loadOrdinalTable(edataTable: ExportDirectory,
    mmBytes: MemoryMappedPE, virtualAddress: Long, edataOffset: Long): ExportOrdinalTable = {
    val base = edataTable(ORDINAL_BASE)
    val rva = edataTable(ORDINAL_TABLE_RVA)
    val entries = edataTable(NR_OF_NAME_POINTERS)
    val fileOffset = edataOffset + rva - virtualAddress
    ExportOrdinalTable(mmBytes, base.toInt, rva, entries.toInt, virtualAddress, fileOffset)
  }

  private def loadNamePointerTable(edataTable: ExportDirectory,
    mmBytes: MemoryMappedPE, virtualAddress: Long, offset: Long): ExportNamePointerTable = {
    val nameTableRVA = edataTable(NAME_POINTER_RVA)
    val namePointers = edataTable(NR_OF_NAME_POINTERS).toInt
    val fileOffset = offset + nameTableRVA - virtualAddress
    ExportNamePointerTable(mmBytes, nameTableRVA, namePointers, virtualAddress, fileOffset)
  }

  /**
   * Loads the EAT.
   *
   * @param offset file offset of the export directory table
   */
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

  //TODO this parameter list is horrible!
  private def loadExportEntries(sectionLoader: SectionLoader,
    namePointerTable: ExportNamePointerTable, optHeader: OptionalHeader,
    ordinalTable: ExportOrdinalTable,
    exportAddressTable: ExportAddressTable, mmBytes: MemoryMappedPE,
    virtualAddress: Long, edataTable: ExportDirectory): List[ExportEntry] = {
    // see: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
    // "if the function's RVA is inside the exports section (as given by the
    // VirtualAddress and Size fields in the DataDirectory), the symbol is forwarded."
    //TODO is that approach accurate?
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

    val names = namePointerTable.pointerNameList.map(_._2)
    val nameEntries: List[ExportEntry] = names map { name =>
      val rva = getSymbolRVAForName(name, exportAddressTable, ordinalTable, namePointerTable)
      val forwarder = getForwarder(rva)
      val ordinal = getOrdinalForName(name, ordinalTable, namePointerTable)
      new ExportNameEntry(rva, name, ordinal, forwarder)
    }
    val addresses = exportAddressTable.addresses
    val ordinalBase = edataTable.get(ExportDirectoryKey.ORDINAL_BASE)
    val ordEntries = for (
      i <- 0 until addresses.length;
      if !ordinalTable.ordinals.contains(i + ordinalBase)
    ) yield {
      val rva = addresses(i)
      val forwarder = getForwarder(rva)
      val ordinal = (i + ordinalBase).toInt
      new ExportEntry(rva, ordinal, forwarder)
    }

    assert(nameEntries.size == edataTable.get(ExportDirectoryKey.NR_OF_NAME_POINTERS))
//    assert(ordEntries.size == edataTable.get(ExportDirectoryKey.ADDR_TABLE_ENTRIES) -
//      edataTable.get(ExportDirectoryKey.NR_OF_NAME_POINTERS))
    if(!(ordEntries.size == edataTable.get(ExportDirectoryKey.ADDR_TABLE_ENTRIES) -
      edataTable.get(ExportDirectoryKey.NR_OF_NAME_POINTERS))){
      logger.warn("corrup ordinal entries");
    }

    ordEntries.toList ::: nameEntries.toList
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
    namePointerTable: ExportNamePointerTable): Int =
    ordinalTable.ordinals(namePointerTable(name))

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
    if (ordinal == -1) -1 else exportAddressTable(ordinal - ordinalTable.base)
  }

  private def getASCIIName(nameRVA: Long, virtualAddress: Long,
    mmBytes: MemoryMappedPE): String = {
    val offset = nameRVA
    //TODO cast to int is insecure. actual int is unsigned, java int is signed
    val nullindex = mmBytes.indexWhere(_ == 0, offset.toInt)
    new String(mmBytes.slice(offset.toInt, nullindex))
  }

  /**
   * Creates an instance of the export section by loading all necessary
   * information from the given export section bytes
   *
   * @param loadInfo the load information
   * @return instance of the export section
   */
  def newInstance(loadInfo: LoadInfo): ExportSection = apply(loadInfo)

}
