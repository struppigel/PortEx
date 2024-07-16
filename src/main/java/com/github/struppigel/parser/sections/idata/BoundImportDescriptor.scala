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
    val desc = loadDescriptor(loadInfo, nr)
    // read addresses as file offsets instead
    // that is because older files use offsets instead of RVAs
    if(desc.isEmpty()) loadDescriptor(loadInfo, nr, true)
    else desc
  }

  private def loadDescriptor(loadInfo : LoadInfo, nr : Int, useRaw : Boolean = false): BoundImportDescriptor = {
    // prepare values
    val format = new SpecificationFormat(0, 1, 2, 3)
    val mmbytes = loadInfo.memoryMapped
    val entryFileOffset = loadInfo.fileOffset + nr * boundDescriptorSize
    try {
      val readAddress = calculateReadAddress(loadInfo, nr, useRaw)
      val boundBytes = mmbytes.slice(readAddress, readAddress + boundDescriptorSize)
      // load descriptor entries
      val entries = IOUtil.readHeaderEntries(classOf[BoundImportDescriptorKey],
        format, boundImportSpec, boundBytes, entryFileOffset).asScala.toMap

      // load name of bound DLL
      val nameRVA = calculateNameRVA(loadInfo, useRaw, entries)
      val name = getASCIIName(nameRVA, mmbytes)
      logger.debug(s" entry file offset 0x${toHexString(entryFileOffset)}, entry size: ${entries.size}, read address: 0x${toHexString(readAddress)}, name address 0x${toHexString(nameRVA)}")
      new BoundImportDescriptor(entries, nr, entryFileOffset, name)
    } catch {
      case e: IllegalArgumentException => logger.warn(e.getMessage()); emptyDescriptor()
    }
  }

  private def emptyDescriptor(): BoundImportDescriptor = new BoundImportDescriptor(Map.empty, 0, 0, "")

  private def calculateReadAddress(loadInfo : LoadInfo, nr : Int, useRaw : Boolean): Long =
    if (useRaw) {
      val addr = loadInfo.fileOffset + nr * boundDescriptorSize
      val addresses = loadInfo.memoryMapped._physToVirtAddresses(addr)
      if(addresses.isEmpty) throw new IllegalArgumentException(s"Read address ${addr} invalid")
      addresses.head
    }
    else loadInfo.va + nr * boundDescriptorSize

  private def calculateNameRVA(loadInfo: LoadInfo, useRaw : Boolean, entries : Map[BoundImportDescriptorKey, StandardField]): Long =
    if(useRaw) {
      val addr = loadInfo.fileOffset + entries.get(BoundImportDescriptorKey.OFFSET_MODULE_NAME).get.getValue
      val addresses = loadInfo.memoryMapped._physToVirtAddresses(addr)
      if(addresses.isEmpty) throw new IllegalArgumentException(s"Name address ${addr} invalid")
      logger.debug("raw name addr 0x" + toHexString(addr) + " virt addr 0x" + toHexString(addresses.head) + " size " + addresses.size)
      addresses.head
    }
    else loadInfo.va + entries.get(BoundImportDescriptorKey.OFFSET_MODULE_NAME).get.getValue


  private def getASCIIName(nameAddress: Long,
                           mmbytes: MemoryMappedPE ): String = {
    val voffset = nameAddress
    val nullindex = mmbytes.indexWhere(_ == 0, voffset)
    if(nullindex <= 0) throw new IllegalArgumentException(s"Cannot read name at address ${nameAddress} because there is none")
    new String(mmbytes.slice(voffset, nullindex))
  }

}