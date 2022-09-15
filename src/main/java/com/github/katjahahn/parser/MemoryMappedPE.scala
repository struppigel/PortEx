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
package com.github.katjahahn.parser

import java.io.RandomAccessFile
import java.nio.file.Files
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.optheader.OptionalHeader
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.sections.SectionTable
import com.github.katjahahn.parser.MemoryMappedPE._
import com.github.katjahahn.parser.ScalaIOUtil._
import java.io.File
import org.apache.logging.log4j.LogManager
import com.github.katjahahn.parser.optheader.WindowsEntryKey

/**
 * Represents the PE file content as it is mapped to memory.
 * <p>
 * The bytes are read from file only on request, making it possible to map large files.
 * Only maps section bytes for now. No file headers.
 *
 * @author Katja Hahn
 *
 * @param mappings A list of section mappings, in ascending order of virtual addresses
 * @param data the PEData instance of the file
 */
class MemoryMappedPE(
  private val mappings: List[Mapping],
  private val data: PEData) {

  /**
   * Determines how many bytes are read at once while checking indexWhere and indexOf.
   */
  private val chunkSize = 1024

  /**
   * Returns the virtual offset for the given physical address, if it is within
   * a mapping. Otherwise -1 is returned.
   * <p>
   * Spits out a warning if several matching virtual addresses are found and
   * returns the last one.
   * <p>
   * @Beta This method is subject to change
   * @TODO remove -1 as return value
   *
   * @param physAddr physical address
   * @return virtual address for physAddr, -1 if it does not exist
   */
  def physToVirtAddress(physAddr: Long): Long = {
    val addresses = _physToVirtAddresses(physAddr)
    // VA doesn't exist, return -1
    if (addresses.isEmpty) -1
    else {
      if (addresses.size > 1) {
        logger.warn(s"Caution: Several mappings for the file offset (${hex(physAddr)}) found.")
      }
      addresses.last
    }
  }

  /**
   * Returns all virtual addresses that are mapped to this physical address.
   * <p>
   * Scala method. Use physToVirtAddress(Long) for Java.
   * <p>
   * @Beta This method is subject to change
   *
   * @param physAddr the physical address
   * @return list of virtual addresses that are mapped to physAddr
   */
  def _physToVirtAddresses(physAddr: Long): List[Long] = {
    // find mapping that contains physAddr
    val matchedMappings = mappings.filter(m => m.physRange.contains(physAddr))
    // return virtual addresses
    matchedMappings.map(m => m.virtRange.start + (physAddr - m.physRange.start))
  }

  /**
   * Returns the physical offset for the given virtual address, if it is within
   * a mapping. Otherwise -1 is returned.
   * <p>
   * Spits out a warning if several matching physical addresses are found and
   * returns the last one.
   * <p>
   * @Beta This method is subject to change
   * @param va the virtual address
   * @return file offset for the VA, -1 if it does not exist
   */
  def virtToPhysAddress(va: Long): Long = {
    val addresses = _virtToPhysAddresses(va)
    // VA doesn't exist, return -1
    if (addresses.isEmpty) -1
    else {
      if (addresses.size > 1) {
        logger.warn(s"Caution: Several mappings for the VA (${hex(va)}) found, that means the VA is overwritten.")
      }
      addresses.last
    }
  }

  /**
   * Returns all physical addresses that are mapped to the VA.
   * <p>
   * @Beta This method is subject to change
   * @param va the virtual address
   * @return list of file offsets
   */
  def virtToPhysAddresses(va: Long): java.util.List[Long] = _virtToPhysAddresses(va).asJava

  /**
   * Returns all physical addresses that are mapped to the VA.
   * <p>
   * Scala method. Use virtToPhysAddress(Long) for Java.
   * <p>
   * @Beta This method is subject to change
   * @param va the virtual address
   * @return list of file offsets
   */
  def _virtToPhysAddresses(va: Long): List[Long] = {
    // find mapping that contains VA
    val matchedMappings = mappings.filter(m => m.virtRange.contains(va))
    // return physical addresses
    matchedMappings.map(m => m.physRange.start + (va - m.virtRange.start))
  }

  /**Array-like methods**/

  /**
   * Returns byte at position i.
   * <p>
   * Scala method. Use get() for Java.
   *
   * @param i virtual index/position
   * @return byte at position i
   */
  def apply(i: Long): Byte = {
    // find a mapping that contains i
    val mapping = mappings.find(m => m.virtRange.contains(i))
    mapping match {
      case Some(m) => m(i)
      // no mapping found, return 0 for unmapped virtual location
      case None => 0.toByte
    }
  }

  /**
   * Returns byte at position i.
   *
   * @param i virtual index/position
   * @return byte at position i
   */
  def get(i: Long): Byte = apply(i)

  /**
   * Returns the size of the memory mapped information.
   * <p>
   * Bytes above that size are always 0.
   *
   * @return size of memory mapped information
   */
  def length(): Long = if (mappings.isEmpty) 0L else mappings.last.virtRange.end

  /**
   * Returns a byte array of the specified segment.
   * <p>
   * The distance until-from has to be in Integer range.
   *
   * @param from the virtual start offset
   * @param until the virtual end offset
   * @return byte array containing the elements greater than or equal to index
   * from extending up to (but not including) index until
   */
  def slice(from: Long, until: Long): Array[Byte] = {
    require((until - from) == (until - from).toInt)
    // fetch all mappings for that range
    val sliceMappings = mappingsInRange(new VirtRange(from, until))
    // create zero filled array
    val bytes = zeroBytes((until - from).toInt)
    // fill byte array with actual values
    sliceMappings.foreach { mapping =>
      // determine range of bytes to be read for this mapping
      val start = Math.max(mapping.virtRange.start, from)
      val end = Math.min(mapping.virtRange.end, until)
      // read bytes
      val mappedBytes = mapping(start, (end - start).toInt)
      // write bytes into result-array
      for (i <- 0 until mappedBytes.length) {
        // calculate index to write the byte to
        val index = (start - from).toInt + i
        bytes(index) = mappedBytes(i)
      }
    }
    bytes
  }

  /**
   * Filters all mappings that are relevant for the range.
   * <p>
   * Relevant means the mapping maps VAs of that range to physical addresses
   *
   * @param range the virtual range
   */
  private def mappingsInRange(range: VirtRange): List[Mapping] = {
    val (from, until) = range.unpack
    mappings.filter(m => m.virtRange.end >= from && m.virtRange.start <= until)
  }

  /**
   * Returns the index of the first byte that satisfies the condition, returns -1
   * if no such byte was found.
   *
   * @param p the function that specifies the condition
   * @param from virtual offset to start searching from
   * @return index of the first byte that satisfies the condition,
   *         -1 if no byte satisfies the condition
   */
  def indexWhere(p: Byte => Boolean, from: Long): Long = {
    // no byte found, from exceeds MemoryMappedPE length, return -1
    if (from > length) -1
    else {
      // read chunkSize bytes
      val bytes = slice(from, from + chunkSize)
      // get index for first byte that satisfies the condition
      val index = bytes.indexWhere(p)
      // no such byte found, recursive call to search the rest
      if (index == -1) {
        val nextIndex = this.indexWhere(p, from + chunkSize)
        // if no byte of the rest satisfies the condition, return -1
        // otherwise update the found index with chunkSize and return it
        if (nextIndex == -1) -1 else chunkSize + nextIndex
      } else {
        // byte was found in current chunk, update index with the starting VA
        from + index
      }
    }
  }

  /**
   * Returns the index of the first byte that has the value.
   *
   * @param value value of the byte searched for
   * @param from offset to start searching from
   * @return index of the first byte that has the value
   */
  def indexOf(elem: Byte, from: Long): Long =
    indexWhere(((b: Byte) => b == elem), from)

  /**ByteArrayUtil methods**/

  /**
   * Retrieves the integer value of the bytes in the memory mapped PE given by
   * offset and length.
   * <p>
   * The values are considered little endian.
   * <p>
   * Length must be between 1 and 4 inclusive.
   *
   * @param offset
   *            the index to start reading the integer value from
   * @param length
   *            the number of bytes used to convert to int
   * @return int value
   */
  def getBytesIntValue(offset: Long, length: Int): Int = {
    assert(length <= 4 && length > 0)
    ByteArrayUtil.bytesToInt(this.slice(offset, offset + length))
  }

  /**
   * Retrieves the integer value of the bytes in the memory mapped PE given by
   * offset and length.
   * <p>
   * The values are considered little endian.
   * <p>
   * Length must be between 1 and 8 inclusive.
   *
   * @param offset
   *            the index to start reading the long value from
   * @param length
   *            the number of bytes used to convert to long
   * @return long value
   */
  def getBytesLongValue(offset: Long, length: Int): Long = {
    assert(length <= 8 && length > 0)
    ByteArrayUtil.bytesToLong(this.slice(offset, offset + length))
  }

}

/**
 * Responsible for creating the memory mappings
 */
object MemoryMappedPE {

  private val logger = LogManager.getLogger(MemoryMappedPE.getClass().getName())

  /**
   * Creates a representation of the PE content as it is mapped into memory
   *
   * @param data the PEData object
   * @param secLoader the section loader instance
   * @returns a memory mapped PE
   */
  def newInstance(data: PEData, secLoader: SectionLoader): MemoryMappedPE =
    apply(data, secLoader)

  /**
   * Creates a representation of the PE content as it is mapped into memory
   *
   * @param data the PEData object
   * @param secLoader the section loader instance
   * @returns a memory mapped PE
   */
  def apply(data: PEData, secLoader: SectionLoader): MemoryMappedPE = {
    val mappings = readMemoryMappings(data, secLoader)
    new MemoryMappedPE(mappings, data)
  }

  /**
   * Reads and returns the memory mappings for the sections.
   *
   * @param data the PEData object
   * @param secLoader the section loader instance
   * @returns a list of mappings
   */
  private def readMemoryMappings(data: PEData, secLoader: SectionLoader): List[Mapping] = {
    val optHeader = data.getOptionalHeader
    /* in low alignment mode all virtual addresses equal their physical counterparts
       thus, the whole file is mapped as is */
    if (optHeader.isLowAlignmentMode()) {
      val filesize = data.getFile.length
      List(new Mapping(new VirtRange(0, filesize), new PhysRange(0, filesize), data))
    } else {
      /* not low alignment mode, so mappings are applied per section */
      val mappings = getHeaderMappings(secLoader, data) ++ getSectionMappings(secLoader, data)
      // sort mappings to be in ascending order for their virtual start
      val sorted = mappings.sortBy(m => m.virtRange.start)
      sorted.toList
    }
  }

  /**
   * Returns the header mappings of the file.
   *
   * @param secLoader the section loader instance
   * @param data the PEData object
   * @return list of header mapping(s)
   */
  private def getHeaderMappings(secLoader: SectionLoader,
    data: PEData): List[Mapping] = {
    val table = data.getSectionTable
    val lowAlign = data.getOptionalHeader.isLowAlignmentMode
    if (table.getNumberOfSections() > 0) {
      // size of headers is also size of header mapping
      val sizeOfHeaders = data.getOptionalHeader.get(WindowsEntryKey.SIZE_OF_HEADERS)
      // virtual end of header mapping marked by VA of first section
      val vEnd = table.getSectionHeader(1).getAlignedVirtualAddress(lowAlign) - 1
      // virtual start of headers
      val vStart = vEnd - sizeOfHeaders
      /* create mapping with ranges */
      val virtRange = new VirtRange(vStart, vEnd)
      val pStart = data.getPESignature().getOffset()
      logger.debug("pesig offset: " + pStart)
      val pEnd = pStart + sizeOfHeaders
      val physRange = new PhysRange(pStart, pEnd)
      logger.debug("header mapping (v --> p): " + virtRange + " --> " + physRange) //TODO remove
      List(new Mapping(virtRange, physRange, data))
    } else Nil //TODO add mapping
  }

  /**
   * Returns the section mappings of the file.
   * 
   * @param secLoader the section loader instance
   * @param data the PEData object
   * @return list of section mapping(s)
   */
  private def getSectionMappings(secLoader: SectionLoader,
    data: PEData): ListBuffer[Mapping] = {
    val table = data.getSectionTable
    val mappings = ListBuffer[Mapping]()
    val lowAlign = data.getOptionalHeader.isLowAlignmentMode
    // get all valid section headers
    for (header <- table.getSectionHeaders().asScala if secLoader.isValidSection(header)) {
      val readSize = secLoader.getReadSize(header)
      /* calculate physical range */
      val pStart = header.getAlignedPointerToRaw(lowAlign)
      val pEnd = pStart + readSize
      val physRange = new PhysRange(pStart, pEnd)
      /* calculate virtual range */
      val vStart = header.getAlignedVirtualAddress(lowAlign)
      val vEnd = vStart + readSize
      val virtRange = new VirtRange(vStart, vEnd)
      logger.debug("section mapping (v --> p): " + virtRange + " --> " + physRange) //TODO remove
      // add mapping to list
      mappings += new Mapping(virtRange, physRange, data)
    }
    mappings
  }
}