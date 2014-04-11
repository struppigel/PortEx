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

class ExportSection(
  private val edataTable: ExportDirTable,
  private val exportAddressTable: ExportAddressTable,
  private val namePointerTable: ExportNamePointerTable,
  private val ordinalTable: ExportOrdinalTable) extends PEModule {

  lazy val exportEntries = { //TODO only returns named entries so far
    val names = namePointerTable.pointerNameList.map(_._2)
    names.map(name => new ExportEntry(getSymbolRVAForName(name), name, getOrdinalForName(name)))
  }
  
  def getExportDirTable(): ExportDirTable = edataTable

  def getExportAddresses(): java.util.List[Long] = exportAddressTable.addresses.asJava

  def getPointerNameMap(): java.util.Map[Long, String] = namePointerTable.getMap.asJava

  def getNamePointers(): java.util.List[Long] = namePointerTable.pointerNameList.map(_._1).asJava
  
  def getOrdinals(): java.util.List[Int] = ordinalTable.ordinals.asJava
  
  def getOrdinalForName(name: String): Int = namePointerTable(name)
  
  def getSymbolRVAForName(name: String): Long = {
    val ordinal = getOrdinalForName(name)
    if(ordinal == -1) -1 else exportAddressTable(ordinal - ordinalTable.base + 1)
  }
  
  def getExportEntries(): java.util.List[ExportEntry] = exportEntries.asJava

  override def read(): Unit = {}
  
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
    val data = PELoader.loadPE(new File("src/main/resources/testfiles/Lab17-02.dll"))
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

  def getInstance(edataBytes: Array[Byte], virtualAddress: Long,
    opt: OptionalHeader): ExportSection = apply(edataBytes, virtualAddress, opt)
}