package com.github.katjahahn.sections.edata

import com.github.katjahahn.ByteArrayUtil._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule

class ExportNamePointerTable(private val addresses: List[Long]) extends PEModule {
  
  override def read(): Unit = {}
  override def getInfo(): String = 
    s"""|Name Pointer Table
        |....................
        |
        |${addresses.map("0x" + java.lang.Long.toHexString(_)).mkString(", ")}""".stripMargin

}

object ExportNamePointerTable {
  
  def apply(edataBytes: Array[Byte], rva: Long, entries: Int, virtualAddress: Long): ExportNamePointerTable = {
    val length = 4
    val initialOffset = (rva - virtualAddress).toInt
    val addresses = new ListBuffer[Long]()
    val end = initialOffset + entries*length
    for(offset <- initialOffset until end by length) {
      addresses += getBytesLongValue(edataBytes, offset, length)
    }
    new ExportNamePointerTable(addresses.toList)
  }
  
}