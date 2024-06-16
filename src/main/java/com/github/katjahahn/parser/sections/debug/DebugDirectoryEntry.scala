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
package com.github.katjahahn.parser.sections.debug

import com.github.katjahahn.parser.IOUtil._
import com.github.katjahahn.parser._
import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.sections.debug.DebugDirectoryKey._
import com.github.katjahahn.parser.sections.debug.DebugSection._
import org.apache.logging.log4j.LogManager

import java.util.Date
import scala.collection.JavaConverters._

/**
 * @author Karsten Hahn
 *
 * Represents the debug section of the PE.
 * @param directoryTable the debug directory
 * @param typeDescription the description string for the debug information type
 * @param offset the file offset to the debug directory
 */
class DebugDirectoryEntry private (
                             private val directoryTable: DebugDirectory,
                             private val typeDescription: String,
                             private val debugType: DebugType,
                             val offset: Long,
                             private val maybeCodeView: Option[CodeviewInfo],
                             private val maybeRepro: Option[ReproInfo],
                             private val maybeExDll: Option[ExtendedDLLCharacteristics]) {

  def getOffset(): Long = offset

  def getSize(): Long = debugDirEntrySize

  def getCodeView(): CodeviewInfo =
    if (maybeCodeView.isDefined) maybeCodeView.get
    else throw new IllegalStateException("Code View structure not valid")

  def getRepro(): ReproInfo =
    if (maybeRepro.isDefined) maybeRepro.get
  else throw new IllegalStateException("Repro info does not exist")

  def getExtendedDLLCharacteristics(): ExtendedDLLCharacteristics =
    if (maybeExDll.isDefined) maybeExDll.get
    else throw new IllegalStateException("Extended DLL characteristics do not exist")

  def getReproHash(): Array[Byte] =
    if(maybeRepro.isDefined) maybeRepro.get.reproHash
    else throw new IllegalStateException("Repro hash does not exist")

  def getReproHashString(): String = ByteArrayUtil.byteToHex(getReproHash())

  def getDirectoryTable(): java.util.Map[DebugDirectoryKey, StandardField] =
    directoryTable.asJava

  def getPhysicalLocations(): java.util.List[PhysicalLocation] = {
    if (maybeCodeView.isDefined) {
      return (getCodeView().getPhysicalLocations().asScala.toList :+ new PhysicalLocation(offset, getSize)).asJava
    }
    return (new PhysicalLocation(offset, getSize) :: Nil).asJava
  }

  def isEmpty: Boolean = directoryTable.isEmpty

  def getInfo(): String =
    s"""|-------------
        |Debug Entry
        |-------------
        |
        |${
      directoryTable.values.map(s => s.getKey() match {
        case TYPE            => "Type: " + typeDescription
        case TIME_DATE_STAMP => "Time date stamp: " + getTimeDateStamp().toString
        case _               => s.toString
      }).mkString(NL)}
        |${if (maybeCodeView.isDefined) maybeCodeView.get.getInfo else ""}${if (maybeRepro.isDefined) maybeRepro.get.getInfo else ""}${if (maybeExDll.isDefined) maybeExDll.get.getInfo else ""}
        |""".stripMargin

  /**
   * Returns a date object of the time date stamp in the debug section.
   *
   * @return date of the time date stamp
   */
  def getTimeDateStamp(): Date = new Date(get(TIME_DATE_STAMP) * 1000)

  /**
   * Returns a long value of the given key or null if the value doesn't exist.
   *
   * @param key the header key
   * @return long value for the given key of null if it doesn't exist.
   */
  def get(key: DebugDirectoryKey): java.lang.Long =
    if (directoryTable.contains(key))
      directoryTable(key).getValue else null

  /**
   * Returns a string of the type description
   *
   * @return type description string
   */
  def getTypeDescription(): String = typeDescription

  def getDebugType(): DebugType = debugType

}

object DebugDirectoryEntry {

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
  def newInstance(li: LoadInfo): DebugDirectoryEntry =
    apply(li.memoryMapped, li.fileOffset, li.va, li.data)


  def apply(mmbytes: MemoryMappedPE, offset: Long, virtualAddress: Long, data: PEData): DebugDirectoryEntry = {
    val format = new SpecificationFormat(0, 1, 2, 3)
    val debugbytes = mmbytes.slice(virtualAddress, virtualAddress + debugDirEntrySize)
    val entries = IOUtil.readHeaderEntries(classOf[DebugDirectoryKey],
      format, debugspec, debugbytes, offset).asScala.toMap
    val debugTypeValue = entries(DebugDirectoryKey.TYPE).getValue
    try {
      val debugType = DebugType.getForValue(debugTypeValue)
      val ptrToRawData = entries(POINTER_TO_RAW_DATA).getValue
      val codeview = CodeviewInfo(ptrToRawData, data.getFile)
      val exDllChar = if(debugType == DebugType.EX_DLLCHARACTERISTICS ) ExtendedDLLCharacteristics(ptrToRawData, data) else None
      val repro = if(debugType == DebugType.REPRO ) Some(ReproInfo(ptrToRawData, data)) else None
      new DebugDirectoryEntry(entries, debugType.getDescription, debugType, offset, codeview, repro, exDllChar)
    } catch {
      case e: IllegalArgumentException =>
        logger.warn("no debug type description found!")
        val description = s"${entries(DebugDirectoryKey.TYPE).getValue} no description available"
        new DebugDirectoryEntry(entries, description, DebugType.UNKNOWN, offset, None, None, None)
    }
  }
}