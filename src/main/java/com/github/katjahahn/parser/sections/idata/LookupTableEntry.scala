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

import scala.collection.JavaConverters._
import LookupTableEntry._
import java.lang.Long.toHexString
import org.apache.logging.log4j.LogManager
import com.github.katjahahn.parser.ByteArrayUtil._
import com.github.katjahahn.parser.MemoryMappedPE
import com.github.katjahahn.parser.Location

/**
 * Represents a lookup table entry. Every lookup table entry is either an
 * ordinal entry, a name entry or a null entry. The null entry indicates the end
 * of the lookup table.
 *
 * @author Katja Hahn
 *
 * @param size
 * @param offset
 */
abstract class LookupTableEntry(val size: Int, val offset: Long) {

  val location = new Location(offset, size)

  /**
   * Converts the lookup table entry to an import instance.
   *
   * @returns import instance
   */
  def toImport(): Import

}

/**
 * Instantiates an ordinal entry.
 *
 * @param ordNumber the ordinal of the entry
 * @param rva the symbol's address
 * @param dirEntry the directory entry
 * @param size
 * @param offset
 */
case class OrdinalEntry(val ordNumber: Int, val rva: Long,
  dirEntry: DirectoryEntry, override val size: Int,
  override val offset: Long) extends LookupTableEntry(size, offset) {

  /**
   * {@inheritDoc}
   */
  override def toString(): String = s"ordinal: $ordNumber RVA: $rva (0x${toHexString(rva)})"

  /**
   * {@inheritDoc}
   */
  override def toImport(): Import = new OrdinalImport(ordNumber, rva, dirEntry, List(location).asJava)
}

/**
 * Instantiates a name entry.
 *
 * @param nameRVA address to the name
 * @param hintNameEntry hint name entry instance
 * @param rva address to the imported symbol
 * @param dirEntry directory entry instance
 * @param size
 * @param offset the file offset
 */
case class NameEntry(val nameRVA: Long, val hintNameEntry: HintNameEntry,
  val rva: Long, val dirEntry: DirectoryEntry, override val size: Int, override val offset: Long)
  extends LookupTableEntry(size, offset) {

  /**
   * {@inheritDoc}
   */
  override def toString(): String =
    s"${hintNameEntry.name}, Hint: ${hintNameEntry.hint}, nameRVA: $nameRVA (0x${toHexString(nameRVA)}), RVA: $rva (0x${toHexString(rva)})"

  /**
   * {@inheritDoc}
   */
  override def toImport(): Import =
    new NameImport(rva, hintNameEntry.name, hintNameEntry.hint, nameRVA, dirEntry, List(location).asJava)
}

/**
 * Instantiates a null entry, which is an empty entry that
 * indicates the end of the lookup table
 *
 * @param size
 * @param offset
 */
case class NullEntry(override val size: Int, override val offset: Long)
  extends LookupTableEntry(size, offset) {
  /**
   * {@inheritDoc}
   */
  override def toImport(): Import = null
}

object LookupTableEntry {

  private final val logger = LogManager.getLogger(LookupTableEntry.getClass().getName())

  /**
   * Creates a lookup table entry based on the given import table bytes,
   * the size of the entry, the offset of the entry and the virtual address of
   * the import section
   *
   * @param mmbytes memory mapped PE
   * @param entryRVA address to the lookuptable entry relative to iltRVA
   * @param entrySize the size of one entry
   * @param virtualAddress the address to the import section
   * @param iltRVA address to the last ILT or the IAT
   * @param dirEntry the directory entry
   * @param fileOffset the file offset to the lookup table entry to create
   * @return lookup table entry
   */
  def apply(mmbytes: MemoryMappedPE, entryRVA: Int, entrySize: Int,
    virtualAddress: Long, iltRVA: Long, dirEntry: DirectoryEntry, fileOffset: Long): LookupTableEntry = {
    val ordFlagMask = if (entrySize == 4) 0x80000000L else 0x8000000000000000L
    try {
      //TODO remove get array call
      val value = mmbytes.getBytesLongValue(entryRVA + virtualAddress, entrySize)
      if (value == 0) {
        NullEntry(entrySize, fileOffset)
      } else if ((value & ordFlagMask) != 0) {
        createOrdEntry(value, iltRVA, dirEntry, entrySize, fileOffset)
      } else {
        createNameEntry(value, mmbytes, virtualAddress, iltRVA, dirEntry, entrySize, fileOffset)
      }
    } catch {
      case e: Exception =>
        logger.warn("invalid lookup table entry at ilt rva " + iltRVA)
        throw new FailureEntryException("invalid lookup table entry at ilt rva " + iltRVA)
    }
  }

  private def createNameEntry(value: Long, mmbytes: MemoryMappedPE,
    virtualAddress: Long, rva: Long, dirEntry: DirectoryEntry, entrySize: Int, offset: Long): LookupTableEntry = {
    val addrMask = 0xFFFFFFFFL
    val nameRVA = (addrMask & value)
    logger.debug("rva: " + nameRVA)
    val address = nameRVA
    logger.debug("virtual addr: " + virtualAddress)
    logger.debug("address: " + address)
    logger.debug("idata length: " + mmbytes.length)
    if (address + 2 > mmbytes.length) throw new FailureEntryException()
    val hint = mmbytes.getBytesIntValue(address, 2)
    val name = getASCII(address + 2, mmbytes)
    val hintOffset = mmbytes.getPhysforVir(nameRVA)
    NameEntry(nameRVA, new HintNameEntry(hint, name, hintOffset), rva, dirEntry, entrySize, offset: Long)
  }

  private def createOrdEntry(value: Long, rva: Long, dirEntry: DirectoryEntry, entrySize: Int, offset: Long): OrdinalEntry = {
    val ordMask = 0xFFFFL
    val ord = (ordMask & value).toInt
    OrdinalEntry(ord, rva, dirEntry, entrySize, offset)
  }

  private def getASCII(offset: Long, mmbytes: MemoryMappedPE): String = {
    val nullindex = mmbytes.indexWhere(_ == 0, offset)
    new String(mmbytes.slice(offset, nullindex))
  }

  class HintNameEntry(val hint: Int, val name: String, val fileOffset: Long) {
    override def toString(): String = s"""hint: $hint
      |name: $name""".stripMargin
      
    def size(): Long = name.length() + 2
  }

}
