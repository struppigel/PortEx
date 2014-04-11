package com.github.katjahahn.sections.edata

import com.github.katjahahn.ByteArrayUtil._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule

class ExportAddressTable (val addresses: List[Long]) extends PEModule {
  
  def apply(i: Int): Long = addresses(i)
  
  override def read(): Unit = {}
  override def getInfo(): String = 
    s"""|Export Address Table
        |....................
        |
        |${addresses.map("0x" + java.lang.Long.toHexString(_)).mkString(", ")}""".stripMargin

}

object ExportAddressTable {
  
  def apply(edataBytes: Array[Byte], rva: Long, entries: Int, virtualAddress: Long): ExportAddressTable = {
    val length = 4
    val initialOffset = (rva - virtualAddress).toInt
    val addresses = new ListBuffer[Long]()
    val end = initialOffset + entries*length
    for(offset <- initialOffset until end by length) {
      addresses += getBytesLongValue(edataBytes, offset, length)
    }
    new ExportAddressTable(addresses.toList)
  }
  
}