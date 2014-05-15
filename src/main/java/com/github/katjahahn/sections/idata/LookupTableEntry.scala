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
import org.apache.logging.log4j.LogManager

/**
 * Represents a lookup table entry. Every lookup table entry is either an
 * ordinal entry, a name entry or a null entry. The null entry indicates the end
 * of the lookup table.
 *
 * @author Katja Hahn
 */
abstract class LookupTableEntry {
  def toImport(): Import
}

/**
 * @constructor instantiates an ordinal entry
 * @param ordNumber
 */
case class OrdinalEntry(val ordNumber: Int) extends LookupTableEntry {
  override def toString(): String = "ordinal: " + ordNumber
  override def toImport(): Import = new OrdinalImport(ordNumber)
}

/**
 * @constructor instantiates a name entry.
 * @param nameRVA
 * @param hintNameEntry
 */
case class NameEntry(val nameRVA: Long, val hintNameEntry: HintNameEntry) extends LookupTableEntry {
  override def toString(): String =
    s"${hintNameEntry.name}, Hint: ${hintNameEntry.hint}, RVA: $nameRVA (0x${toHexString(nameRVA)})"

  override def toImport(): Import = new NameImport(nameRVA, hintNameEntry.name, hintNameEntry.hint)
}

/**
 * @constructor instantiates a null entry, which is an empty entry that
 * indicates the end of the lookup table
 */
case class NullEntry() extends LookupTableEntry {
  override def toImport(): Import = null
}

object LookupTableEntry {

  private final val logger = LogManager.getLogger(LookupTableEntry.getClass().getName())

  /**
   * Creates a lookup table entry based on the given import table bytes,
   * the size of the entry, the offset of the entry and the virtual address of
   * the import section
   *
   * @param idatabytes the bytes of the import section
   * @param offset the offset of the entry (relative to the offset of the import section)
   * @param entrySize the size of one entry (dependend on the magic number)
   * @param virtualAddress of the import section (used to calculate offsets for
   * given rva's of hint name entries)
   * @return lookup table entry
   */
  def apply(idatabytes: Array[Byte], offset: Int, entrySize: Int, virtualAddress: Long, importTableOffset: Int): LookupTableEntry = {
    val ordFlagMask = if (entrySize == 4) 0x80000000L else 0x8000000000000000L
    val value = getBytesLongValue(idatabytes, offset + importTableOffset, entrySize)

    if (value == 0) {
      NullEntry()
    } else if ((value & ordFlagMask) != 0) {
      createOrdEntry(value)
    } else {
      createNameEntry(value, idatabytes, virtualAddress, importTableOffset)
    }
  }

  private def createNameEntry(value: Long, idatabytes: Array[Byte], virtualAddress: Long, importTableOffset: Int): LookupTableEntry = {
    val addrMask = 0xFFFFFFFFL
    val rva = (addrMask & value)
    logger.debug("rva: " + rva)
    val address = (rva - virtualAddress) + importTableOffset
    logger.debug("virtual addr: " + virtualAddress)
    logger.debug("address: " + address)
    logger.debug("idata length: " + idatabytes.length)
    val hint = getBytesIntValue(idatabytes, address.toInt, 2)
    val name = getASCII(address.toInt + 2, idatabytes)
    NameEntry(rva, new HintNameEntry(hint, name))
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
