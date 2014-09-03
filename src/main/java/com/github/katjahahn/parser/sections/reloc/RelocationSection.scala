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

package com.github.katjahahn.parser.sections.reloc

import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.optheader.WindowsEntryKey
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.Location
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.PhysicalLocation

class RelocationSection(
  private val blocks: List[BaseRelocBlock],
  private val offset: Long) extends SpecialSection {

  override def getInfo(): String = blocks.mkString("\n")

  override def isEmpty(): Boolean = blocks.isEmpty

  override def getOffset(): Long = 0
  
  def getRelocBlocks(): java.util.List[BaseRelocBlock] = blocks.asJava

  def getPhysicalLocations(): java.util.List[PhysicalLocation] =
    blocks.flatMap(b => b.getLocations).asJava

}

object RelocationSection {

  def apply(loadInfo: LoadInfo): RelocationSection = {
    val opt = loadInfo.data.getOptionalHeader
    val tableSize = opt.getDataDirEntries().get(DataDirectoryKey.BASE_RELOCATION_TABLE).getDirectorySize()
    val blocks = readBlocks(tableSize, loadInfo)
    new RelocationSection(blocks, loadInfo.fileOffset)
  }

  private def readBlocks(tableSize: Long, loadInfo: LoadInfo): List[BaseRelocBlock] = {
    val mmBytes = loadInfo.memoryMapped
    val va = loadInfo.va
    val blocks = ListBuffer[BaseRelocBlock]()
    var offset = 0
    while (offset < tableSize) {
      val fileOffset = mmBytes.getPhysforVir(va + offset)
      val length = 4
      val fieldSize = 2
      val pageRVA = mmBytes.getBytesLongValue(va + offset, length)
      offset += length
      val blockSize = mmBytes.getBytesLongValue(va + offset, length)
      offset += length
      val fields = ListBuffer[BlockEntry]()
      val nrOfRelocs = ((blockSize - (length * 2)) / fieldSize).toInt
      for (i <- 0 until nrOfRelocs) {
        val fieldValue = mmBytes.getBytesIntValue(va + offset, fieldSize)
        fields += BlockEntry(fieldValue)
        offset += fieldSize
      }
      blocks += new BaseRelocBlock(fileOffset, pageRVA, blockSize, fields.toList)
    }
    blocks.toList
  }

  def newInstance(loadInfo: LoadInfo): RelocationSection =
    apply(loadInfo)
}