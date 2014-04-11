package com.github.katjahahn.sections.edata

import com.github.katjahahn.ByteArrayUtil._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import com.github.katjahahn.PEModule._
import java.io.File
import ExportNamePointerTable._

class ExportNamePointerTable(val pointerNameMap: Map[Address, String]) extends PEModule {
  
  
  override def read(): Unit = {}
  override def getInfo(): String = 
    s"""|Name Pointer Table
        |...................
        |
        |RVA    ->  Name
        |****************
        |${pointerNameMap.map(t => ("0x" + java.lang.Long.toHexString(t._1) -> t._2)).mkString(NL)}""".stripMargin

}

object ExportNamePointerTable {
  
  type Address = Long
  
  def apply(edataBytes: Array[Byte], rva: Long, entries: Int, 
      virtualAddress: Long, file: File): ExportNamePointerTable = {
    val length = 4
    val initialOffset = (rva - virtualAddress).toInt
    val addresses = scala.collection.mutable.Map[Address, String]()
    val end = initialOffset + entries*length
    for(offset <- initialOffset until end by length) {
      val address = getBytesLongValue(edataBytes, offset, length)
      val name = getName(edataBytes, (address - virtualAddress).toInt)
      addresses += address -> name
    }
    
    new ExportNamePointerTable(addresses.toMap)
  }
  
  private def getName(edataBytes: Array[Byte], address: Int): String = {
    val end = edataBytes.indexOf('\0'.toByte, address)
    val bytes = edataBytes.slice(address, end + 1)
    new String(bytes)
  }
  
}