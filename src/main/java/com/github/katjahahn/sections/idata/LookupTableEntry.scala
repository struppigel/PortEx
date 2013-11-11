package com.github.katjahahn.sections.idata

import com.github.katjahahn.optheader.OptionalHeader.MagicNumber
import com.github.katjahahn.optheader.OptionalHeader.MagicNumber._
import com.github.katjahahn.PEModule
import com.github.katjahahn.PEModule._
import LookupTableEntry._
import java.lang.Long.toHexString

abstract class LookupTableEntry

case class OrdinalEntry(val ordNumber: Int) extends LookupTableEntry {
  override def toString(): String = "ordinal: " + ordNumber
}
case class NameEntry(val nameRVA: Long, val hintNameEntry: HintNameEntry) extends LookupTableEntry {
  override def toString(): String =
    s"""RVA: $nameRVA (0x${toHexString(nameRVA)})
    |${hintNameEntry.toString}""".stripMargin
}
case class NullEntry() extends LookupTableEntry

object LookupTableEntry {

  def apply(idatabytes: Array[Byte], offset: Int, magic: MagicNumber, virtualAddress: Int): LookupTableEntry = {
    val (ordFlagMask, length) = magic match {
      case PE32 => (0x80000000L, 4)
      case PE32_PLUS => (0x8000000000000000L, 8)
      case ROM => throw new IllegalArgumentException
    }

    println(idatabytes.slice(offset, offset + length).mkString(" "))
    val value = getBytesLongValue(idatabytes, offset, length)

    if (value == 0) {
      NullEntry()
    } else if ((value & ordFlagMask) != 0) {
      createOrdEntry(value)
    } else {
      createNameEntry(value, idatabytes, virtualAddress)
    }
  }

  private def createNameEntry(value: Long, idatabytes: Array[Byte], virtualAddress: Int): LookupTableEntry = {
    val addrMask = 0xFFFFFFFFL
    val rva = (addrMask & value)
    println("rva: " + rva)
    val address = (rva - virtualAddress)
    println("virtual addr: " + virtualAddress)
    println("address: " + address)
    println("idata length: " + idatabytes.length)
    if(address > idatabytes.length) NullEntry()
    else //TODO allow long values
//    val hint = getBytesIntValue(idatabytes, address, 2)
//    val name = getASCII(address + 2, idatabytes)
//    NameEntry(rva.toInt, new HintNameEntry(hint, name))
    NameEntry(rva, new HintNameEntry(0, "undef"))
  }

  private def createOrdEntry(value: Long): OrdinalEntry = {
    val ordMask = 0xFFFFL
    val ord = (ordMask & value).toInt
    OrdinalEntry(ord)
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