/**
 * *****************************************************************************
 * Copyright 2024 Karsten Philipp Boris Hahn
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
import com.github.struppigel.parser.{IOUtil, PhysicalLocation}
import com.github.struppigel.parser.sections.SpecialSection
import org.apache.logging.log4j.LogManager

import scala.collection.JavaConverters._

class BoundImportSection private (
    private val entries: List[BoundImportDescriptor],
    private val offset: Long) extends SpecialSection {

  def getEntries(): java.util.List[BoundImportDescriptor] = entries.asJava

  /**
   * {@inheritDoc}
   */
  override def getOffset(): Long = offset

  /**
   * {@inheritDoc}
   */
  override def isEmpty(): Boolean = false

  /**
   *
   * @return a list with all locations the import information has been written to.
   */
  def getPhysicalLocations(): java.util.List[PhysicalLocation] =
    entries.map(b => b.getPhysicalLocation()).asJava

  /**
   * Returns a decription of all entries in the bound import section.
   *
   * @return a description of all entries in the bound import section
   */
  override def getInfo(): String =
    s"""|--------------
        |Bound Imports
        |--------------
        |
        |${entries.mkString(IOUtil.NL)}""".stripMargin

}

object BoundImportSection {

  private val MAX_ENTRIES = 10000
  private final val logger = LogManager.getLogger(BoundImportSection.getClass().getName())

  def apply(loadInfo: LoadInfo): BoundImportSection = {

    val entries = readEntries(loadInfo)
    val rawOffset = loadInfo.fileOffset
    new BoundImportSection(entries, rawOffset)
    }

  private def readEntries(loadInfo: LoadInfo, number: Int = 0): List[BoundImportDescriptor] = {
    val descriptor = BoundImportDescriptor(loadInfo, number)
    if(descriptor.isEmpty()) Nil
    else if (number == MAX_ENTRIES) { logger.warn("maximum number of BoundImportDescriptors reached") ; Nil }
    else descriptor :: readEntries(loadInfo, number + 1)
  }


  /**
   * The instance of this class is usually created by the section loader.
   *
   * @param loadInfo
   * @return ImportSection instance
   */
  def newInstance(loadInfo: LoadInfo): BoundImportSection = apply(loadInfo)

}