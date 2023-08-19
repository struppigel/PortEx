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

import com.github.katjahahn.parser.IOUtil.{NL, SpecificationFormat}
import com.github.katjahahn.parser.{IOUtil, MemoryMappedPE, PhysicalLocation, StandardField}
import com.github.katjahahn.parser.optheader.OptionalHeader.MagicNumber._
import com.github.katjahahn.parser.optheader.WindowsEntryKey
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.sections.idata.DelayLoadDirectoryEntry._
import com.github.katjahahn.parser.sections.idata.DelayLoadDirectoryKey._
import org.apache.logging.log4j.LogManager

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
    val nameRVA = entries(NAME).getValue.toInt
    val name = getASCIIName(nameRVA, va, mmbytes)
    try {
      val lookupTableEntries = readLookupTableEntries(entries, loadInfo)
      return new DelayLoadDirectoryEntry(entries, entryFileOffset, name, lookupTableEntries)
    } catch {
      case e: FailureEntryException => logger.error(
        "Invalid LookupTableEntry found, parsing aborted, " + e.getMessage())
    }
    // No lookup table entries read
    return new DelayLoadDirectoryEntry(entries, entryFileOffset, name, Nil)
  }

  private def readLookupTableEntries(entries: Map[DelayLoadDirectoryKey, StandardField],
    loadInfo: LoadInfo): List[LookupTableEntry] = {
    val virtualAddress = loadInfo.va
    val mmbytes = loadInfo.memoryMapped
    val magicNumber = loadInfo.data.getOptionalHeader.getMagicNumber()
    val fileOffset = loadInfo.fileOffset
    var entry: LookupTableEntry = null
    var iRVA = entries(DELAY_IMPORT_NAME_TABLE).getValue
    var offset = iRVA - virtualAddress
    var relOffset = iRVA
    var iVA = iRVA + loadInfo.data.getOptionalHeader.get(WindowsEntryKey.IMAGE_BASE)
    val lookupTableEntries = ListBuffer[LookupTableEntry]()
    logger.debug("offset: " + offset + " rva: " + iRVA + " byteslength: " +
      mmbytes.length() + " virtualAddress " + virtualAddress)
    val EntrySize = magicNumber match {
      case PE32 => 4
      case PE32_PLUS => 8
      case ROM => throw new IllegalArgumentException("ROM file format not covered by PortEx")
      case UNKNOWN => throw new IllegalArgumentException("Unknown magic number, can not parse delay-load imports")
    }
    do {
      //TODO get fileoffset for entry from mmbytes instead of this to avoid
      //fractionated section issues ?
      val entryFileOffset = fileOffset + offset
      //val entryFileOffset = mmbytes.getPhysforVir(iRVA) //doesn't work
      //FIXME dummy
      val dummy = new DirectoryEntry(null, 0)
      entry = LookupTableEntry(mmbytes, offset.toInt, EntrySize,
        virtualAddress, relOffset, iVA, dummy, entryFileOffset)
      if (!entry.isInstanceOf[NullEntry]) lookupTableEntries += entry
      offset += EntrySize
      relOffset += EntrySize
    } while (!entry.isInstanceOf[NullEntry])
    lookupTableEntries.toList
  }

  private def getASCIIName(nameRVA: Int, virtualAddress: Long,
    mmbytes: MemoryMappedPE): String = {
    val offset = nameRVA
    val nullindex = mmbytes.indexWhere(_ == 0, offset)
    new String(mmbytes.slice(offset, nullindex))
  }
}