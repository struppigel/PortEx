package com.github.katjahahn.sections.edata

import com.github.katjahahn.ByteArrayUtil._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import com.github.katjahahn.PEModule._
import java.io.File
import ExportNamePointerTable._

class ExportNamePointerTable(val pointerNameList: List[(Address, String)]) extends PEModule {
  
  def getMap(): Map[Address, String] = pointerNameList.toMap
  
  def apply(i: Int): Long = pointerNameList(i)._1
  
  //TODO binary search!
  def apply(name: String): Int = pointerNameList.indexWhere(_._2 == name)
  
  override def read(): Unit = {}
  
  override def getInfo(): String = 
    s"""|Name Pointer Table
        |...................
        |
        |RVA    ->  Name
        |****************
        |${getMap.map(t => ("0x" + java.lang.Long.toHexString(t._1) -> t._2)).mkString(NL)}""".stripMargin

}

object ExportNamePointerTable {
  
  type Address = Long
  
  def apply(edataBytes: Array[Byte], rva: Long, entries: Int, 
      virtualAddress: Long): ExportNamePointerTable = {
    val length = 4
    val initialOffset = (rva - virtualAddress).toInt
    val addresses = new ListBuffer[(Address, String)]
    val end = initialOffset + entries*length
    for(offset <- initialOffset until end by length) {
      val address = getBytesLongValue(edataBytes, offset, length)
      val name = getName(edataBytes, (address - virtualAddress).toInt)
      addresses += ((address, name))
    }
    
    new ExportNamePointerTable(addresses.toList)
  }
  
  private def getName(edataBytes: Array[Byte], address: Int): String = {
    val end = edataBytes.indexOf('\0'.toByte, address)
    val bytes = edataBytes.slice(address, end)
    new String(bytes)
  }
  
}