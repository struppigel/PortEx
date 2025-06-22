/**
 * *****************************************************************************
 * Copyright 2022 Karsten Hahn
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
package io.github.struppigel.parser.sections.clr

import io.github.struppigel.parser.IOUtil._
import io.github.struppigel.parser.sections.SectionLoader.LoadInfo
import CLIHeaderKey._
import CLRSection.cliHeaderSize
import io.github.struppigel.parser.sections.SpecialSection
import io.github.struppigel.parser.{FileFormatException, IOUtil, PEData, StandardField}
import io.github.struppigel.parser.{MemoryMappedPE, PhysicalLocation}

import java.util
import scala.collection.JavaConverters._

class CLRSection(val cliHeader: Map[CLIHeaderKey, StandardField],
                 val metadataRoot: MetadataRoot,
                 private val fileOffset: Long) extends SpecialSection {

  def getCliHeaderEntries: util.Map[CLIHeaderKey, StandardField] = cliHeader.asJava

  def getMetadataRoot: MetadataRoot = metadataRoot
  /**
   * Returns whether the special section has no entries.
   *
   * @return true if no entries, false otherwise
   */
  override def isEmpty: Boolean = cliHeader.isEmpty

  /**
   * Returns a list of physical address ranges this special section is parsed from.
   *
   * @return list of locations
   */
  override def getPhysicalLocations: util.List[PhysicalLocation] =
    (new PhysicalLocation(fileOffset, cliHeaderSize) :: metadataRoot.getPhysicalLocations).asJava

  /**
   * Returns the file offset for the beginning of the module.
   *
   * @return file offset for the beginning of the module
   */
  override def getOffset: Long = fileOffset

  /**
   * Returns a description string of the {@link CLRSection}.
   *
   * @return description string
   */
  override def getInfo: String = {
    val flagsField = cliHeader.get(FLAGS)
    val flagsVal = {
      if (flagsField.isDefined) flagsField.get.getValue else 0
    }
    val flagsList = ComImageFlag.getAllFor(flagsVal).asScala
    "CLI Header:" + NL +
      "-----------" + NL +
      cliHeader.values.mkString(NL) + NL +
      "Flags:" + NL +
      "\t* " + flagsList.map(_.getDescription).mkString(NL + "\t* ") + NL + NL +
      metadataRoot.getInfo
  }
}

object CLRSection {
  val cliHeaderSpec = "cliheaderspec"
  val cliHeaderSize = 0x48 //always this value acc. to specification

  def apply(mmbytes: MemoryMappedPE, offset: Long, virtualAddress: Long, data: PEData): CLRSection = {
    // load CLI Header
    val cliHeaderSize = 0x48 //always this value acc. to specification
    val clibytes = mmbytes.slice(virtualAddress, virtualAddress + cliHeaderSize)
    val format = new SpecificationFormat(0, 1, 2, 3)
    val cliHeader = IOUtil.readHeaderEntries(classOf[CLIHeaderKey],
      format, cliHeaderSpec, clibytes, offset).asScala.toMap
    val metadataVA = getValOrThrow(cliHeader, META_DATA_RVA)
    val metadataSize = getValOrThrow(cliHeader, META_DATA_SIZE)
    val metaRoot = MetadataRoot(mmbytes, data, metadataVA, metadataSize)
    val clr = new CLRSection(cliHeader, metaRoot, offset)
    clr
  }

  private def getValOrThrow(map: Map[CLIHeaderKey, StandardField], key: CLIHeaderKey): Long = {
    map.getOrElse(key, throw new FileFormatException("Key not found " + key)).getValue
  }

  /**
   * Creates an instance of the DebugSection for the given debug bytes.
   *
   * @param li the load information
   * @return debugsection instance
   */
  def newInstance(li: LoadInfo): CLRSection = {
    apply(li.memoryMapped, li.fileOffset, li.va, li.data)
  }


}
