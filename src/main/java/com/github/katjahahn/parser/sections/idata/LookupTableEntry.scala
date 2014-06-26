/**
 * *****************************************************************************
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
 * ****************************************************************************
 */
package com.github.katjahahn.parser.sections.idata

import LookupTableEntry._
import java.lang.Long.toHexString
import org.apache.logging.log4j.LogManager
import com.github.katjahahn.parser.ByteArrayUtil._
import com.github.katjahahn.parser.MemoryMappedPE

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
 * Instantiates an ordinal entry
 * 
 * @param ordNumber the ordinal of the entry
 * @param rva
 * @param dirEntry
 */
case class OrdinalEntry(val ordNumber: Int, val rva: Long,
  dirEntry: DirectoryEntry) extends LookupTableEntry {
  override def toString(): String = s"ordinal: $ordNumber RVA: $rva (0x${toHexString(rva)})"
  override def toImport(): Import = new OrdinalImport(ordNumber, rva, dirEntry)
}

/**
 * Instantiates a name entry.
 * @param nameRVA
 * @param hintNameEntry
 * @param rva
 * @param dirEntry
 */
case class NameEntry(val nameRVA: Long, val hintNameEntry: HintNameEntry,
  val rva: Long, val dirEntry: DirectoryEntry) extends LookupTableEntry {
  override def toString(): String =
    s"${hintNameEntry.name}, Hint: ${hintNameEntry.hint}, nameRVA: $nameRVA (0x${toHexString(nameRVA)}), RVA: $rva (0x${toHexString(rva)})"

  override def toImport(): Import = new NameImport(rva, hintNameEntry.name, hintNameEntry.hint, nameRVA, dirEntry)
}

/**
 * Instantiates a null entry, which is an empty entry that
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
  def apply(mmbytes: MemoryMappedPE, offset: Int, entrySize: Int,
    virtualAddress: Long, rva: Long, dirEntry: DirectoryEntry): LookupTableEntry = {
    val ordFlagMask = if (entrySize == 4) 0x80000000L else 0x8000000000000000L
    try {
      //TODO remove get array call
      val value = mmbytes.getBytesLongValue(offset + virtualAddress, entrySize)
      if (value == 0) {
        NullEntry()
      } else if ((value & ordFlagMask) != 0) {
        createOrdEntry(value, rva, dirEntry)
      } else {
        createNameEntry(value, mmbytes, virtualAddress, rva, dirEntry)
      }
    } catch {
      case e: Exception =>
        logger.warn("invalid lookup table entry at rva " + rva)
        throw new FailureEntryException("invalid lookup table entry at rva " + rva)
    }
  }

  private def createNameEntry(value: Long, mmbytes: MemoryMappedPE,
    virtualAddress: Long, rva: Long, dirEntry: DirectoryEntry): LookupTableEntry = {
    val addrMask = 0xFFFFFFFFL
    val nameRVA = (addrMask & value)
    logger.debug("rva: " + nameRVA)
    val address = nameRVA
    logger.debug("virtual addr: " + virtualAddress)
    logger.debug("address: " + address)
    logger.debug("idata length: " + mmbytes.length)
    if(address + 2 > mmbytes.length) throw new FailureEntryException()
    val hint = mmbytes.getBytesIntValue(address, 2)
    val name = getASCII(address + 2, mmbytes)
    NameEntry(nameRVA, new HintNameEntry(hint, name), rva, dirEntry)
  }

  private def createOrdEntry(value: Long, rva: Long, dirEntry: DirectoryEntry): OrdinalEntry = {
    val ordMask = 0xFFFFL
    val ord = (ordMask & value).toInt
    OrdinalEntry(ord, rva, dirEntry)
  }

  private def getASCII(offset: Long, mmbytes: MemoryMappedPE): String = {
    val nullindex = mmbytes.indexWhere(_ == 0, offset)
    new String(mmbytes.slice(offset, nullindex))
  }

  class HintNameEntry(val hint: Int, val name: String) {
    override def toString(): String = s"""hint: $hint
      |name: $name""".stripMargin
  }

}
