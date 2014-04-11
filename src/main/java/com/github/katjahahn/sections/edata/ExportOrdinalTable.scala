package com.github.katjahahn.sections.edata

import com.github.katjahahn.ByteArrayUtil._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import com.github.katjahahn.PEModule._

class ExportOrdinalTable(val ordinals: List[Int], val base: Int) extends PEModule {
  
  def apply(i: Int): Int = ordinals(i)
  
  override def read(): Unit = {}

  override def getInfo(): String = 
    s"""|Ordinal Table
        |..............
        |
        |${ordinals.mkString(", ")}""".stripMargin

}

object ExportOrdinalTable {

  def apply(edataBytes: Array[Byte], base: Int, rva: Long, entries: Int, 
      virtualAddress: Long): ExportOrdinalTable = {
    val entrySize = 2 //in Byte
    val initialOffset = (rva - virtualAddress).toInt
    val end = entrySize * entries + initialOffset
    val ordinals = new ListBuffer[Int]
    for(offset <- initialOffset until end by entrySize) {
      val ordinal = getBytesIntValue(edataBytes, offset, entrySize)
      ordinals += ordinal
    }
    new ExportOrdinalTable(ordinals.toList, base)
  }

}