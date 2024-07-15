/**
 * *****************************************************************************
 * Copyright 2024 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */

package com.github.struppigel.parser.sections.idata

import com.github.struppigel.parser.IOUtil.SpecificationFormat
import com.github.struppigel.parser.{IOUtil, MemoryMappedPE, PhysicalLocation, StandardField}
import com.github.struppigel.parser.sections.SectionLoader.LoadInfo
import com.github.struppigel.parser.sections.idata.BoundImportDescriptor.boundDescriptorSize
import org.apache.logging.log4j.LogManager

import java.lang.Long.toHexString
import scala.collection.JavaConverters._

class BoundImportDescriptor(val entries: Map[BoundImportDescriptorKey, StandardField],
                            val number: Int,
                            val rawOffset: Long,
                            val name : String ) {

  def getEntries() : java.util.Map[BoundImportDescriptorKey, StandardField] = entries.asJava

  def get(key: BoundImportDescriptorKey): Long = entries(key).getValue

  def getName(): String = name

  def isEmpty(): Boolean = entries.values.forall( _.getValue == 0L)

  def getPhysicalLocation(): PhysicalLocation = new PhysicalLocation(rawOffset, boundDescriptorSize)

  def getInfo(): String =
    s"${number}. Raw offset: 0x${toHexString(rawOffset)}, Name: ${name}, ${entries.values.map(v => s"${v.getDescription}: 0x${toHexString(v.getValue)}").mkString(", ")}"

  override def toString(): String = getInfo()

}

object BoundImportDescriptor {

    private final val logger = LogManager.getLogger(BoundImportDescriptor.getClass().getName())
    private val boundImportSpec = "boundimportdesc"
    val boundDescriptorSize = 8

    def apply(loadInfo: LoadInfo, nr: Int): BoundImportDescriptor = {
      // prepare values
      val format = new SpecificationFormat(0, 1, 2, 3)
      val mmbytes = loadInfo.memoryMapped
      val entryFileOffset = loadInfo.fileOffset + nr * boundDescriptorSize
      val readAddress = loadInfo.va + nr * boundDescriptorSize
      val boundBytes = mmbytes.slice(readAddress, readAddress + boundDescriptorSize)
      // load descriptor entries
      val entries = IOUtil.readHeaderEntries(classOf[BoundImportDescriptorKey],
        format, boundImportSpec, boundBytes, entryFileOffset).asScala.toMap
      // load name of bound DLL
      val nameRVA = loadInfo.va + entries.get(BoundImportDescriptorKey.OFFSET_MODULE_NAME).get.getValue
      val name = getASCIIName(nameRVA, mmbytes)

      new BoundImportDescriptor(entries, nr, entryFileOffset, name)
    }

  private def getASCIIName(nameRVA: Long,
                           mmbytes: MemoryMappedPE): String = {
    val offset = nameRVA
    val nullindex = mmbytes.indexWhere(_ == 0, offset)
    new String(mmbytes.slice(offset, nullindex))
  }

}