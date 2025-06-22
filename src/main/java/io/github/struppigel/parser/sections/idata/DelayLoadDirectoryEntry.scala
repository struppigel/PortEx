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
package io.github.struppigel.parser.sections.idata

import io.github.struppigel.parser.IOUtil.{NL, SpecificationFormat}
import io.github.struppigel.parser.optheader.OptionalHeader.MagicNumber._
import io.github.struppigel.parser.sections.SectionLoader.LoadInfo
import DelayLoadDirectoryEntry._
import DelayLoadDirectoryKey._
import io.github.struppigel.parser.optheader.WindowsEntryKey
import io.github.struppigel.parser.{IOUtil, StandardField}
import io.github.struppigel.parser.{MemoryMappedPE, PhysicalLocation}
import org.apache.logging.log4j.LogManager

import java.lang.Long.toHexString
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

class DelayLoadDirectoryEntry private (
  private val entries: Map[DelayLoadDirectoryKey, StandardField],
  private val offset: Long,
  val name: String,
  private val lookupTableEntries: List[LookupTableEntry]) {

  def apply(key: DelayLoadDirectoryKey): Long = entries(key).getValue

  /**
   * Returns a list of all file locations where directory entries are found
   */
  def getPhysicalLocations(): List[PhysicalLocation] = new PhysicalLocation(offset, delayDirSize) ::
    //collect lookupTableEntry locations
    (for (entry <- lookupTableEntries) yield new PhysicalLocation(entry.offset, entry.size)) :::
    //collect HintNameEntry locations
    (lookupTableEntries collect {
      case e: NameEntry =>
        new PhysicalLocation(e.hintNameEntry.fileOffset, e.hintNameEntry.size)
    })
  
  def lookupTableEntriesSize: Int = lookupTableEntries.size

  def getInfo(): String = s"""${entries.values.mkString(NL)}
    |ASCII name: $name
    |
    |lookup table entries for $name
    |--------------------------------------
    |
    |${lookupTableEntries.mkString(NL)}""".stripMargin

  override def toString(): String = getInfo()

  /**
   * Converts the directory entry to an ImportDLL instance
   */
  def toImportDLL(): ImportDLL = {
    val nameImports = lookupTableEntries collect { case i: NameEntry => i.toImport.asInstanceOf[NameImport] }
    val ordImports = lookupTableEntries collect { case i: OrdinalEntry => i.toImport.asInstanceOf[OrdinalImport] }
    val timedateStamp = entries.get(DelayLoadDirectoryKey.TIME_STAMP).get.getValue
    new ImportDLL(name, nameImports.asJava, ordImports.asJava, timedateStamp)
  }

}

object DelayLoadDirectoryEntry {

  private final val logger = LogManager.getLogger(DelayLoadDirectoryEntry.getClass().getName())
  private val delayLoadSpec = "delayimporttablespec"
  val delayDirSize = 32

  def apply(loadInfo: LoadInfo, nr: Int): DelayLoadDirectoryEntry = {
    val mmbytes = loadInfo.memoryMapped
    val entryFileOffset = loadInfo.fileOffset + nr * delayDirSize
    val va = loadInfo.va
    val readAddress = va + nr * delayDirSize
    val format = new SpecificationFormat(0, 1, 2, 3)
    val delayLoadBytes = mmbytes.slice(readAddress, readAddress + delayDirSize)
    val entries = IOUtil.readHeaderEntries(classOf[DelayLoadDirectoryKey],
      format, delayLoadSpec, delayLoadBytes, entryFileOffset).asScala.toMap

    val name = getNameByAddressTesting(loadInfo, entries)
    logger.debug(s"va: 0x${toHexString(va)}, read addr: 0x${toHexString(readAddress)}, entries: ${entries.size}, name: $name, entry file offset: 0x${toHexString(entryFileOffset)}")

    try {
      val lookupTableEntries = readLookupTableEntries(entries, loadInfo, false)
      if(lookupTableEntries.isEmpty) return new DelayLoadDirectoryEntry(entries, entryFileOffset, name, readLookupTableEntries(entries, loadInfo, true))
      else return new DelayLoadDirectoryEntry(entries, entryFileOffset, name, lookupTableEntries)
    } catch {
      case e: FailureEntryException => logger.warn(
        "Invalid LookupTableEntry found, parsing aborted, " + e.getMessage())
    }
    // No lookup table entries read
    new DelayLoadDirectoryEntry(entries, entryFileOffset, name, Nil)
  }

  // entries are sometimes VAs and sometimes RVAs, we determine the name by testing which one works
  private def getNameByAddressTesting(loadInfo: LoadInfo, entries: Map[DelayLoadDirectoryKey, StandardField]): String = {
    try {
      // use RVA first because that is according to specification
      val nameRVA = calculateRVA(loadInfo, false, entries, NAME)
      logger.debug(s"name rva: 0x" + toHexString(nameRVA))
      val name = getASCIIName(nameRVA, loadInfo.memoryMapped)
      logger.debug("name " + name)
      if(!name.isEmpty) return name
    } catch {
      case e: IllegalArgumentException => logger.info(e.getMessage())
    }
    try {
      // RVA did not work, so use VA
      val nameVA = calculateRVA(loadInfo, true, entries, NAME)
      logger.debug(s"name va: 0x" + toHexString(nameVA))
      return getASCIIName(nameVA, loadInfo.memoryMapped)
    } catch {
      case e: IllegalArgumentException => logger.warn(e.getMessage())
    }
    // return empty string if nothing works
    ""
  }

  private def getImageBase(loadInfo : LoadInfo) : Long =
    loadInfo.data.getOptionalHeader.get(WindowsEntryKey.IMAGE_BASE)

  private def calculateRVA(loadInfo: LoadInfo, useVA : Boolean, entries : Map[DelayLoadDirectoryKey, StandardField], key: DelayLoadDirectoryKey): Long = {
    val value = entries(key).getValue
    val base = getImageBase(loadInfo)
    if(useVA && base <= value) value - base
    else value
  }

  private def getASCIIName(nameAddress: Long,
                           mmbytes: MemoryMappedPE ): String = {
    val voffset = nameAddress
    val nullindex = mmbytes.indexWhere(_ == 0, voffset)
    if(nullindex <= 0) throw new IllegalArgumentException(s"Cannot read name at address 0x${toHexString(nameAddress)} because there is none")
    new String(mmbytes.slice(voffset, nullindex))
  }

  private def readLookupTableEntries(entries: Map[DelayLoadDirectoryKey, StandardField],
    loadInfo: LoadInfo, useVAs : Boolean): List[LookupTableEntry] = {
    val virtualAddress = loadInfo.va
    val mmbytes = loadInfo.memoryMapped
    val magicNumber = loadInfo.data.getOptionalHeader.getMagicNumber()
    val fileOffset = loadInfo.fileOffset
    var entry: LookupTableEntry = null
    val iRVA = calculateRVA(loadInfo, useVAs, entries, DELAY_IMPORT_NAME_TABLE)
    var offset = iRVA - virtualAddress
    var relOffset = iRVA
    val iVA = iRVA + loadInfo.data.getOptionalHeader.get(WindowsEntryKey.IMAGE_BASE)
    val lookupTableEntries = ListBuffer[LookupTableEntry]()
    logger.debug("offset: 0x" + toHexString(offset) + " rva: 0x" + toHexString(iRVA) + " byteslength: " +
      mmbytes.length() + " virtualAddress 0x" + toHexString(loadInfo.va))
    val EntrySize = magicNumber match {
      case PE32 => 4
      case PE32_PLUS => 8
      case ROM => throw new IllegalArgumentException("ROM file format not covered by PortEx")
      case UNKNOWN => throw new IllegalArgumentException("Unknown magic number, can not parse delay-load imports")
    }
    do {
      //TODO get fileoffset for entry from mmbytes instead of this to avoid fractionated section issues ?
      val entryFileOffset = fileOffset + offset
      //val entryFileOffset = mmbytes.getPhysforVir(iRVA) //doesn't work
      //FIXME dummy
      val dummy = new DirectoryEntry(null, 0)
      entry = LookupTableEntry(loadInfo, mmbytes, offset.toInt, EntrySize,
        virtualAddress, relOffset, iVA, dummy, entryFileOffset)
      if (!entry.isInstanceOf[NullEntry]) lookupTableEntries += entry

      offset += EntrySize
      relOffset += EntrySize
    } while (!entry.isInstanceOf[NullEntry])
    lookupTableEntries.toList
  }

}