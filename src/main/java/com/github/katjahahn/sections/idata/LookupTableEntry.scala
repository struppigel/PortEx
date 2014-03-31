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
package com.github.katjahahn.sections.idata

import com.github.katjahahn.optheader.OptionalHeader.MagicNumber
import com.github.katjahahn.optheader.OptionalHeader.MagicNumber._
import com.github.katjahahn.PEModule
import com.github.katjahahn.PEModule._
import LookupTableEntry._
import java.lang.Long.toHexString
import com.github.katjahahn.ByteArrayUtil._

abstract class LookupTableEntry

case class OrdinalEntry(val ordNumber: Int) extends LookupTableEntry {
  override def toString(): String = "ordinal: " + ordNumber
}
case class NameEntry(val nameRVA: Long, val hintNameEntry: HintNameEntry) extends LookupTableEntry {
  override def toString(): String =
    s"${hintNameEntry.name}, Hint: ${hintNameEntry.hint}, RVA: $nameRVA (0x${toHexString(nameRVA)})"
}
case class NullEntry() extends LookupTableEntry

object LookupTableEntry {

  def apply(idatabytes: Array[Byte], offset: Int, entrySize: Int, virtualAddress: Long): LookupTableEntry = {
    val ordFlagMask = if (entrySize == 4) 0x80000000L else 0x8000000000000000L
    //    println(idatabytes.slice(offset, offset + entrySize).mkString(" "))
    val value = getBytesLongValue(idatabytes, offset, entrySize)

    if (value == 0) {
      NullEntry()
    } else if ((value & ordFlagMask) != 0) {
      createOrdEntry(value)
    } else {
      createNameEntry(value, idatabytes, virtualAddress)
    }
  }

  private def createNameEntry(value: Long, idatabytes: Array[Byte], virtualAddress: Long): LookupTableEntry = {
    val addrMask = 0xFFFFFFFFL
    val rva = (addrMask & value)
    //    println("rva: " + rva)
    val address = (rva - virtualAddress)
    //    println("virtual addr: " + virtualAddress)
    //    println("address: " + address)
    //    println("idata length: " + idatabytes.length)
    if (address > idatabytes.length) NullEntry() //TODO remove
    else {
      val hint = getBytesIntValue(idatabytes, address.toInt, 2)
      val name = getASCII(address.toInt + 2, idatabytes)
      NameEntry(rva.toInt, new HintNameEntry(hint, name))
    }
  }

  private def createOrdEntry(value: Long): OrdinalEntry = {
    val ordMask = 0xFFFFL
    val ord = (ordMask & value).toInt
    OrdinalEntry(ord)
  }

  private def getASCII(offset: Int, idatabytes: Array[Byte]): String = {
    val nullindex = idatabytes.indexWhere(_ == 0, offset)
    new String(idatabytes.slice(offset, nullindex))
  }

  class HintNameEntry(val hint: Int, val name: String) {
    override def toString(): String = s"""hint: $hint
      |name: $name""".stripMargin
  }

}
