/*******************************************************************************
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
 ******************************************************************************/
package com.github.katjahahn.sections.edata

import com.github.katjahahn.PEModule
import com.github.katjahahn.optheader.OptionalHeader
import com.github.katjahahn.sections.SectionLoader
import com.github.katjahahn.PELoader
import com.github.katjahahn.PEModule._
import scala.collection.JavaConverters._
import java.io.File
import com.github.katjahahn.optheader.WindowsEntryKey
import ExportDirTableKey._

/**
 * @author Katja Hahn
 * 
 * Represents the export section of a PE file and provides access to lists of it's inner
 * structures (export address table, ordinal table, name pointer table, 
 * data directory table) as well as access to a list of export entries fetched
 * from these structures.
 * 
 * The export section instance should be created with the {@link SectionLoader}
 * 
 * @constructor creates an export section instance 
 * @param edataTable the data directory table
 * @param exportAddressTable contains addresses to exported functions
 * @param namePointerTable containes addresses to names of exported functions
 * @param ordinalTable contains ordinal number of exported functions
 * 
 */
class ExportSection private (
  private val edataTable: ExportDirTable,
  private val exportAddressTable: ExportAddressTable,
  private val namePointerTable: ExportNamePointerTable,
  private val ordinalTable: ExportOrdinalTable) extends PEModule {

  lazy val exportEntries = { //TODO only returns named entries so far
    val names = namePointerTable.pointerNameList.map(_._2)
    names.map(name => new ExportEntry(getSymbolRVAForName(name), name, getOrdinalForName(name)))
  }
  
  /**
   * Returns the export directory table which contains general information and 
   * information about the other tables in the export section
   * 
   * @return the export directory table
   */
  def getExportDirTable(): ExportDirTable = edataTable

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
  def getOrdinalForName(name: String): Int = namePointerTable(name)
  
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
    if(ordinal == -1) -1 else exportAddressTable(ordinal - ordinalTable.base + 1)
  }
  
  /**
   * Returns a list of all export entries found in the export section
   * 
   * @return a list of all export entries
   */
  def getExportEntries(): java.util.List[ExportEntry] = exportEntries.asJava

  override def read(): Unit = {}
  
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
  		|${exportAddressTable.getInfo}
  		|
  		|${namePointerTable.getInfo}
  		|
  		|${ordinalTable.getInfo}""".stripMargin

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

  def main(args: Array[String]): Unit = {
    val data = PELoader.loadPE(new File("src/main/resources/testfiles/Lab11-03.dll")) //TODO correct ordinal and rva of this? see tests
    val loader = new SectionLoader(data)
    val edata = loader.loadExportSection()
    println(edata.getDetailedInfo)
    println()
    println(edata.getInfo)
  }

  def apply(edataBytes: Array[Byte], virtualAddress: Long,
    opt: OptionalHeader): ExportSection = {
    val edataTable = ExportDirTable(edataBytes)
    val exportAddressTable = loadExportAddressTable(edataTable, edataBytes, virtualAddress)
    val namePointerTable = loadNamePointerTable(edataTable, edataBytes, virtualAddress)
    val ordinalTable = loadOrdinalTable(edataTable, edataBytes, virtualAddress)
    new ExportSection(edataTable, exportAddressTable, namePointerTable, ordinalTable)
  }
  
  private def loadOrdinalTable(edataTable: ExportDirTable,
    edataBytes: Array[Byte], virtualAddress: Long): ExportOrdinalTable = {
    val base = edataTable(ORDINAL_BASE)
    val rva = edataTable(ORDINAL_TABLE_RVA)
    val entries = edataTable(NR_OF_NAME_POINTERS)
    ExportOrdinalTable(edataBytes, base.toInt, rva, entries.toInt, virtualAddress)
  }

  private def loadNamePointerTable(edataTable: ExportDirTable,
    edataBytes: Array[Byte], virtualAddress: Long): ExportNamePointerTable = {
    val nameTableRVA = edataTable(NAME_POINTER_RVA)
    val namePointers = edataTable(NR_OF_NAME_POINTERS).toInt
    ExportNamePointerTable(edataBytes, nameTableRVA, namePointers, virtualAddress)
  }

  private def loadExportAddressTable(edataTable: ExportDirTable,
    edataBytes: Array[Byte], virtualAddress: Long): ExportAddressTable = {
    val addrTableRVA = edataTable(EXPORT_ADDR_TABLE_RVA)
    val entries = edataTable(ADDR_TABLE_ENTRIES).toInt
    ExportAddressTable(edataBytes, addrTableRVA, entries, virtualAddress)
  }

  /**
   * Creates an instance of the export section by loading all necessary 
   * information from the given export section bytes
   *
   * @param edataBytes the bytes of the export section
   * @param virtualAddress the virtual address from the data directory entry 
   * table that points to the export section
   * @param opt optional header of the file
   * @return instance of the export section
   */
  def getInstance(edataBytes: Array[Byte], virtualAddress: Long,
    opt: OptionalHeader): ExportSection = apply(edataBytes, virtualAddress, opt)
}
