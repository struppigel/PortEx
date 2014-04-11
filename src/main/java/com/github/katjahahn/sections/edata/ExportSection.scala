package com.github.katjahahn.sections.edata

import com.github.katjahahn.PEModule
import com.github.katjahahn.optheader.OptionalHeader
import com.github.katjahahn.sections.SectionLoader
import com.github.katjahahn.PELoader
import java.io.File

class ExportSection(private val edataTable: ExportDirTable) extends PEModule {

  override def read(): Unit = {}
  override def getInfo(): String = edataTable.getInfo

}

object ExportSection {
  
  def main(args: Array[String]): Unit = {
    val data = PELoader.loadPE(new File("src/main/resources/testfiles/DLL1.dll"))
    val loader = new SectionLoader(data)
    val edata = loader.loadExportSection()
    println(edata.getInfo())
  }

  def apply(edataBytes: Array[Byte], virtualAddress: Long, 
      opt: OptionalHeader): ExportSection = {
    val edataTable = ExportDirTable(edataBytes)
    new ExportSection(edataTable)
  }

  def getInstance(edataBytes: Array[Byte], virtualAddress: Long, 
      opt: OptionalHeader): ExportSection = apply(edataBytes, virtualAddress, opt)
}