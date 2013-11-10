package com.github.katjahahn.sections.idata

import com.github.katjahahn.optheader.OptionalHeader.MagicNumber
import com.github.katjahahn.optheader.OptionalHeader.MagicNumber._
import com.github.katjahahn.PEModule
import com.github.katjahahn.PEModule._
import LookupTableEntry._

abstract class LookupTableEntry

case class OrdinalEntry(val ordNumber: Int) extends LookupTableEntry {
  override def toString(): String = "ordinal: " + ordNumber 
}
case class NameEntry(val nameRVA: Int, val hintNameEntry: HintNameEntry) extends LookupTableEntry {
  override def toString(): String = s"address: $nameRVA (0x${Integer.toHexString(nameRVA)})" + NL + hintNameEntry.toString
}
case class NullEntry() extends LookupTableEntry

object LookupTableEntry {
  
  def apply(idatabytes: Array[Byte], offset: Int, magic: MagicNumber, virtualAddress: Int): LookupTableEntry = {
    val (mask, length) = magic match {
      case PE32 => (0x80000000L, 4)
      case PE32_PLUS => (0x8000000000000000L, 8)
      case ROM => throw new IllegalArgumentException
    }
    val value = getBytesLongValue(idatabytes, offset, length)
    
    if(value == 0) {
      NullEntry()
    } else if((value & mask) == 1) {
      //TODO mask the value
      val ord = value.toInt
      OrdinalEntry(ord)
    } else {
      //TODO mask the value 
      val address = (value - virtualAddress).toInt
      val name = getASCII(address + 2, idatabytes)
      val hint = getBytesIntValue(idatabytes, address, 2)
      NameEntry(address, new HintNameEntry(hint, name))
    }  
  }
  
  private def getASCII(offset: Int, idatabytes: Array[Byte]): String = {
    val nullindex = idatabytes.indexWhere(b => b == 0, offset)
    new String(idatabytes.slice(offset, nullindex))
  }
  
  class HintNameEntry(val hint: Int, val name: String) {
    override def toString(): String = s"""hint: $hint
      |name: $name""".stripMargin
  }
  
}