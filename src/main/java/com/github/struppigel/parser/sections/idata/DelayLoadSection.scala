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
package com.github.struppigel.parser.sections.idata

import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import DelayLoadSection._
import com.github.struppigel.parser.{Location, PhysicalLocation}
import com.github.struppigel.parser.sections.SpecialSection
import org.apache.logging.log4j.LogManager

import java.lang.Long.toHexString
import scala.collection.JavaConverters._

class DelayLoadSection(
    private val delayLoadTable: DelayLoadTable, 
    private val offset: Long) extends SpecialSection {

  override def isEmpty(): Boolean = delayLoadTable.isEmpty

  override def getOffset(): Long = offset

  override def getInfo(): String = delayLoadTable.mkString("\n\n")
  
  /**
   * @return a list of all import entries found
   */
  def getImports(): java.util.List[ImportDLL] =
    delayLoadTable.map(e => e.toImportDLL).asJava
    
  /**
   *
   * @return a list with all locations the import information has been written to.
   */
  //TODO include IAT and ILT, add string locations
  def getPhysicalLocations(): java.util.List[PhysicalLocation] = {
    val ranges = Location.mergeContinuous(delayLoadTable.foldRight(
        List[PhysicalLocation]())((entry, list) => entry.getPhysicalLocations ::: list))
    ranges.asJava
  }

}

object DelayLoadSection {

  private final val logger = LogManager.getLogger(DelayLoadSection.getClass().getName())
  private final val dirEntryMax = 10000

  type DelayLoadTable = List[DelayLoadDirectoryEntry]

  def apply(loadInfo: LoadInfo): DelayLoadSection = {
    val delayLoadTable = readDirEntries(loadInfo)
    logger.debug("delay load table size " + delayLoadTable.size)
    new DelayLoadSection(delayLoadTable, loadInfo.fileOffset)
  }

  private def readDirEntries(loadInfo: LoadInfo, nr: Int = 0): List[DelayLoadDirectoryEntry] = {
    val mmbytes = loadInfo.memoryMapped
    val virtualAddress = loadInfo.va
    val delayDirSize = DelayLoadDirectoryEntry.delayDirSize
    val from = nr * delayDirSize + virtualAddress
    val until = from + delayDirSize
    val entrybytes = mmbytes.slice(from, until)
    logger.debug(s"va: 0x${toHexString(virtualAddress)}, from: 0x${toHexString(from)}, until: 0x${toHexString(until)}")
    if (entrybytes.length < delayDirSize) return Nil

    /*
     * @return true iff the given entry is not the last empty entry or null entry
     */
    def isEmpty(entry: DelayLoadDirectoryEntry): Boolean =
      entry.lookupTableEntriesSize == 0
      
    val entry = DelayLoadDirectoryEntry(loadInfo, nr)
    logger.debug("lookup table entry size " + entry.lookupTableEntriesSize)
    if (isEmpty(entry) || nr >= dirEntryMax) Nil else
      entry :: readDirEntries(loadInfo, nr + 1)
  }

  def newInstance(loadInfo: LoadInfo): DelayLoadSection = apply(loadInfo)

}