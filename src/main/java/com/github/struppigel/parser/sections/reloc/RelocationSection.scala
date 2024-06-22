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

package com.github.struppigel.parser.sections.reloc

import com.github.struppigel.parser.IOUtil.NL
import com.github.struppigel.parser.ScalaIOUtil.hex
import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import com.github.struppigel.parser.PhysicalLocation
import com.github.struppigel.parser.optheader.DataDirectoryKey
import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import com.github.struppigel.parser.sections.SpecialSection
import org.apache.logging.log4j.LogManager

import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer

class RelocationSection(
  private val blocks: List[BaseRelocBlock],
  private val offset: Long) extends SpecialSection {

  override def getInfo(): String = blocks.mkString(NL)

  override def isEmpty(): Boolean = blocks.isEmpty

  override def getOffset(): Long = 0

  def getRelocBlocks(): java.util.List[BaseRelocBlock] = blocks.asJava

  def getPhysicalLocations(): java.util.List[PhysicalLocation] =
    blocks.flatMap(b => b.getLocations).asJava

}

object RelocationSection {
  
  private val logger = LogManager.getLogger(RelocationSection.getClass().getName())

  // set maximum to avoid endless parsing, e.g., in corkami's foldedhdr.exe
  val maxblocks = 10000
  // set maximum to avoid almost endless parsing, e.g., in corkami's reloccrypt.exe
  val maxRelocsPerBlock = 10000

  def apply(loadInfo: LoadInfo): RelocationSection = {
    val opt = loadInfo.data.getOptionalHeader
    val tableSize = opt.getDataDirectory().get(DataDirectoryKey.BASE_RELOCATION_TABLE).getDirectorySize()
    val blocks = readBlocks(tableSize, loadInfo)
    new RelocationSection(blocks, loadInfo.fileOffset)
  }

  private def readBlocks(tableSize: Long, loadInfo: LoadInfo): List[BaseRelocBlock] = {
    val mmBytes = loadInfo.memoryMapped
    val va = loadInfo.va
    val blocks = ListBuffer[BaseRelocBlock]()
    var offset = 0
    while (offset < tableSize && blocks.size < maxblocks) {
      val fileOffset = mmBytes.virtToPhysAddress(va + offset)
      val length = 4
      val fieldSize = 2
      val pageRVA = mmBytes.getBytesLongValue(va + offset, length)
      offset += length
      val blockSize = mmBytes.getBytesLongValue(va + offset, length)
      offset += length
      val fields = ListBuffer[BlockEntry]()
      val nrOfRelocs = ((blockSize - (length * 2)) / fieldSize).toInt
      val limitedRelocs = if (nrOfRelocs <= maxRelocsPerBlock) nrOfRelocs else {
        logger.warn(s"Too many relocations ($nrOfRelocs) for block at offset ${hex(fileOffset)}. Limit set.")
        maxRelocsPerBlock
      }
      for (i <- 0 until limitedRelocs) {
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