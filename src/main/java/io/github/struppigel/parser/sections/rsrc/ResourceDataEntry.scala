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
package io.github.struppigel.parser.sections.rsrc

import io.github.struppigel.parser.IOUtil.SpecificationFormat
import ResourceDataEntry._
import io.github.struppigel.parser.{Header, IOUtil, StandardField}
import io.github.struppigel.parser.{MemoryMappedPE, PhysicalLocation}

import scala.collection.JavaConverters._

/**
 * Represents a data entry of a resource.
 *
 * @author Katja Hahn
 *
 * @param data the header of the data entry
 * @param entryOffset the file offset to the resource data entry
 * @param mmBytes the memory mapped PE
 * @param virtualAddress the rva to the resource table
 */
class ResourceDataEntry private (val data: Map[ResourceDataEntryKey, StandardField],
                                 entryOffset: Long, mmBytes: MemoryMappedPE, virtualAddress: Long) extends Header[ResourceDataEntryKey] {

  /** physical location of the header */
  private lazy val headerLoc = new PhysicalLocation(entryOffset, entrySize)

  /**
   * {@inheritDoc}
   */
  override def get(key: ResourceDataEntryKey): Long =
    if (data.contains(key)) data(key).getValue
    else throw new IllegalArgumentException("key " + key + " does not exist!")

  /**
   * {@inheritDoc}
   */
  override def getField(key: ResourceDataEntryKey): StandardField =
    if (data.contains(key)) data(key)
    else throw new IllegalArgumentException("key " + key + " does not exist!")

  /**
   * {@inheritDoc}
   */
  override def getInfo(): String = this.toString()

  /**
   * {@inheritDoc}
   */
  override def getOffset(): Long = entryOffset

  /**
   * Returns the physical location of the resource data.
   *
   * @return location of the resource
   */
  def getResourceLocation(): PhysicalLocation = {
    // fetch RVA of resource
    val rva = data(ResourceDataEntryKey.DATA_RVA).getValue
    // calculate file offset using memory-mapped PE
    val offset = mmBytes.virtToPhysAddress(rva)
    // fetch size of resource
    val size = data(ResourceDataEntryKey.SIZE).getValue
    // create and return location
    new PhysicalLocation(offset, size)
  }

  /**
   * Returns all file locations of the resource data entry
   *
   * @return all physical locations of the resource data entry
   */
  def locations(): List[PhysicalLocation] = headerLoc ::
    getResourceLocation() :: Nil

  /**
   * {@inheritDoc}
   */
  override def toString(): String =
    s"""|${data.values.map(_.toString()).mkString("\n")}
        |""".stripMargin

  /**
   * Reads the resource bytes from disk and returns them.
   *
   * @return the byte array representing the resource
   * FIXME this is a mistake, use streams
   * @Beta
   */
  def getVirtResourceLoc(): Array[Byte] = {
    val address = data(ResourceDataEntryKey.DATA_RVA).getValue
    val end = data(ResourceDataEntryKey.SIZE).getValue + address
    //    mmBytes.slice(address, end)
    Array()
  }

}

object ResourceDataEntry {

  /**
   * The size of an entry is {@value}
   */
  val entrySize = 16

  /**
   * The name of the specification file
   */
  private val specLocation = "resourcedataentryspec"

  /**
   * Reads and returns a resource data entry instance based on the entryBytes
   *
   * @param entryBytes the byte array containing the entry
   * @param entryOffset the file offset of the entry start
   * @param mmBytes the memory mapped PE
   * @param virtualAddress the rva to the resource table
   * @return a resource data entry instance
   */
  def apply(entryBytes: Array[Byte], entryOffset: Long, mmBytes: MemoryMappedPE,
            virtualAddress: Long): ResourceDataEntry = {
    val format = new SpecificationFormat(0, 1, 2, 3)
    val data = IOUtil.readHeaderEntries(classOf[ResourceDataEntryKey], format,
      specLocation, entryBytes, entryOffset).asScala.toMap
    new ResourceDataEntry(data, entryOffset, mmBytes, virtualAddress)
  }
}
