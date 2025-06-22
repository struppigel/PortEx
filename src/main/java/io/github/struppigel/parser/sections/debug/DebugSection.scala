/**
 * *****************************************************************************
 * Copyright 2014 Karsten Hahn
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
package io.github.struppigel.parser.sections.debug

import io.github.struppigel.parser.sections.SectionLoader.LoadInfo
import io.github.struppigel.parser.optheader.DataDirectoryKey
import io.github.struppigel.parser.{FileFormatException, IOUtil, PEData, StandardField}
import io.github.struppigel.parser.sections.{SectionLoader, SpecialSection}
import io.github.struppigel.parser.{MemoryMappedPE, PhysicalLocation}
import org.apache.logging.log4j.LogManager

import java.util.Optional
import scala.collection.JavaConverters._

/**
 * @author Karsten Hahn
 *
 * Represents the debug section of the PE.
 * @param directoryTable the debug directory
 * @param typeDescription the description string for the debug information type
 * @param offset the file offset to the debug directory
 */
class DebugSection private (
  private val entries: List[DebugDirectoryEntry],
  val offset: Long,
  val size: Long) extends SpecialSection {

  def getEntries(): java.util.List[DebugDirectoryEntry] = entries.asJava

  override def getOffset(): Long = offset

  def getSize(): Long = size

  def getCodeView(): Optional[CodeviewInfo] = {
    val entry = entries.find(_.getDebugType() == DebugType.CODEVIEW)
    if(entry.isDefined) {
      val s = entry.get
      if( s.hasCodeView() )
        return Optional.of(s.getCodeView())
    }
    Optional.empty();
  }

  def isReproBuild() : Boolean = !entries.filter(_.getDebugType() == DebugType.REPRO ).isEmpty

  def hasExtendedDllCharacteristics() : Boolean = !entries.filter(_.getDebugType() == DebugType.EX_DLLCHARACTERISTICS ).isEmpty

  def getExtendedDllCharacteristics() : Optional[ExtendedDLLCharacteristics] = {
    val entry = entries.find(_.getDebugType() == DebugType.EX_DLLCHARACTERISTICS)
    if(entry.isDefined) {
      return Optional.of(entry.get.getExtendedDLLCharacteristics())
    }
    Optional.empty();
  }

  def getPhysicalLocations(): java.util.List[PhysicalLocation] = {
    if (!entries.isEmpty) {
      val preEntries = entries.map(_.getPhysicalLocations().asScala.toList).flatten
      return (preEntries :+ new PhysicalLocation(offset, getSize)).asJava
    }
    return (new PhysicalLocation(offset, getSize) :: Nil).asJava
  }

  override def isEmpty: Boolean = entries.isEmpty

  override def getInfo(): String =
    s"""|-------------
        |Debug Section
        |-------------
        |
        |${
      entries.map(_.getInfo()).mkString(IOUtil.NL)}
        |""".stripMargin
}

object DebugSection {

  val logger = LogManager.getLogger(DebugSection.getClass().getName())

  type DebugDirectory = Map[DebugDirectoryKey, StandardField]

  val debugDirEntrySize = 28

  private val debugspec = "debugdirentryspec"

  /**
   * Creates an instance of the DebugSection for the given debug bytes.
   *
   * @param loadInfo the load information
   * @return debugsection instance
   */
  def newInstance(li: LoadInfo): DebugSection = {
    val size = li.data.getOptionalHeader.getDataDirectory.get(DataDirectoryKey.DEBUG).getDirectorySize
    apply(li.memoryMapped, li.fileOffset, li.va, li.data, size)
  }

  /**
   * Loads the debug section and returns it.
   *
   * This is just a shortcut to loading the section using the {@link SectionLoader}
   *
   * @return instance of the debug section
   */
  def load(data: PEData): DebugSection =
    new SectionLoader(data).loadDebugSection()

  def apply(mmbytes: MemoryMappedPE, offset: Long, virtualAddress: Long, data: PEData, size: Long): DebugSection = {
    val maybeOffset = (new SectionLoader(data)).maybeGetFileOffset(virtualAddress)
    if(!maybeOffset.isPresent()) throw new FileFormatException("Debug Directory not in section") //TODO anomaly?
    val endOfDebug = virtualAddress + size
    val entries = (for(dirVA <- virtualAddress until endOfDebug by debugDirEntrySize) yield
      DebugDirectoryEntry(mmbytes, offset + (dirVA - virtualAddress), dirVA, data)
    ).toList

    new DebugSection(entries, offset, size)
  }
}