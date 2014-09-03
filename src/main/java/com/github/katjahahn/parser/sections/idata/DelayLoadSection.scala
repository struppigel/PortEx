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

import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.StandardField
import DelayLoadSection._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.MemoryMappedPE
import org.apache.logging.log4j.LogManager
import com.github.katjahahn.parser.optheader.OptionalHeader
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.PhysicalLocation

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
    ranges.toList.asJava
  }

}

object DelayLoadSection {

  private final val logger = LogManager.getLogger(DelayLoadSection.getClass().getName())

  type DelayLoadTable = List[DelayLoadDirectoryEntry]

  def apply(loadInfo: LoadInfo): DelayLoadSection = {
    val delayLoadTable = readDirEntries(loadInfo)
    new DelayLoadSection(delayLoadTable, loadInfo.fileOffset)
  }

  private def readDirEntries(loadInfo: LoadInfo): List[DelayLoadDirectoryEntry] = {
    val delayDirSize = DelayLoadDirectoryEntry.delayDirSize
    val directoryTable = ListBuffer[DelayLoadDirectoryEntry]()
    var isLastEntry = false
    var i = 0
    do {
      logger.debug(s"reading ${i + 1}. entry")
      readDirEntry(i, loadInfo) match {
        case Some(entry) =>
          logger.debug("------------start-----------")
          logger.debug("dir entry read: " + entry)
          logger.debug("------------end-------------")
          directoryTable += entry
        case None => isLastEntry = true
      }
      i += 1
    } while (!isLastEntry)
    directoryTable.toList
  }

  var counter = 0

  private def readDirEntry(nr: Int, loadInfo: LoadInfo): Option[DelayLoadDirectoryEntry] = {
    val mmbytes = loadInfo.memoryMapped
    val virtualAddress = loadInfo.va
    val delayDirSize = DelayLoadDirectoryEntry.delayDirSize
    val from = nr * delayDirSize + virtualAddress
    logger.debug("reading from: " + from)
    val until = from + delayDirSize
    logger.debug("reading until: " + until)
    val entrybytes = mmbytes.slice(from, until)
    if (entrybytes.length < delayDirSize) return None

    /**
     * @return true iff the given entry is not the last empty entry or null entry
     */
    def isEmpty(entry: DelayLoadDirectoryEntry): Boolean =
      entry(DelayLoadDirectoryKey.MODULE_HANDLE) == 0
    val entry = DelayLoadDirectoryEntry(loadInfo, nr)
    if (isEmpty(entry)) None else
      Some(entry)
  }

  def newInstance(loadInfo: LoadInfo): DelayLoadSection = apply(loadInfo)

}