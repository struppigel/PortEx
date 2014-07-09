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
package com.github.katjahahn.parser.sections.rsrc
import ResourceDataEntry._
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.ByteArrayUtil._
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.MemoryMappedPE
import com.github.katjahahn.parser.Location

/**
 * Represents a data entry of a resource.
 *
 * @author Katja Hahn
 *
 * @param data the header of the data entry
 */
class ResourceDataEntry private (val data: Map[ResourceDataEntryKey, StandardField],
  entryOffset: Long, mmBytes: MemoryMappedPE, virtualAddress: Long) {

  lazy val headerLoc = new Location(entryOffset, size)
  private lazy val resourceBytesLoc = {
    val rva = data(ResourceDataEntryKey.DATA_RVA).value
    val offset = mmBytes.getPhysforVir(rva)
    val size = data(ResourceDataEntryKey.SIZE).value
    new Location(offset, size)
  }

  def locations(): List[Location] = headerLoc :: resourceBytesLoc :: Nil //TODO add resource bytes

  override def toString(): String =
    s"""|${data.values.map(_.toString()).mkString("\n")}
        |
        |${new String(readResourceBytes)}
        |""".stripMargin

  /**
   * @return the byte array representing the resource
   */
  def readResourceBytes(): Array[Byte] = {
    val address = data(ResourceDataEntryKey.DATA_RVA).value
    val length = data(ResourceDataEntryKey.SIZE).value + address
    mmBytes.slice(address, length)
  }

}

object ResourceDataEntry {

  /**
   * The size of an entry is {@value}
   */
  val size = 16

  /**
   * The name of the specification file
   */
  private val specLocation = "resourcedataentryspec"

  /**
   * Reads and returns a resource data entry instance based on the entryBytes
   *
   * @param entryBytes the byte array containing the entry
   * @param entryOffset the file offset of the entry start
   * @return a resource data entry instance
   */
  def apply(entryBytes: Array[Byte], entryOffset: Long, mmBytes: MemoryMappedPE,
    virtualAddress: Long): ResourceDataEntry = {
    val spec = IOUtil.readMap(specLocation).asScala.toMap
    //TODO use IOUtil.readHeader ...
    val data = for ((sKey, sVal) <- spec) yield {
      val key = ResourceDataEntryKey.valueOf(sKey)
      val relFieldOffset = Integer.parseInt(sVal(1))
      val length = Integer.parseInt(sVal(2))
      if (relFieldOffset + length > entryBytes.length) {
        throw new IllegalArgumentException("unable to read resource data entry")
      }
      val value = getBytesLongValue(entryBytes, relFieldOffset, length)
      val description = sVal(0)
      val absFieldOffset = relFieldOffset + entryOffset
      (key, new StandardField(key, description, value, absFieldOffset, length))
    }
    new ResourceDataEntry(data, entryOffset, mmBytes, virtualAddress)
  }
}
