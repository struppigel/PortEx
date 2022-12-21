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

import com.github.katjahahn.parser.Mapping._
import com.github.katjahahn.parser.ScalaIOUtil._

import java.io.RandomAccessFile

/**
 * Maps all addresses of a virtual range to all addresses of the physical range.
 * <p>
 * Both ranges have to be of the same size.
 * The bytes are read from file only on request, making it possible to map large files.
 *
 * @author Katja Hahn
 *
 * @param virtRange the virtual address range
 * @param physRange the physical address range
 * @param data the PEData object the mapping belongs to
 */
class Mapping(val virtRange: VirtRange, val physRange: PhysRange, private val data: PEData) {
  require(virtRange.end - virtRange.start == physRange.end - physRange.start)

  /**
   * The chunks of bytes that make up the Mapping
   */
  private val chunks = {
    // number of chunks needed for the mapped physical space
    val nrOfChunks = Math.ceil((physRange.end - physRange.start) / defaultChunkSize.toDouble).toInt
    // set start as the physical start of the mapped space
    var start = physRange.start
    for (i <- 1 to nrOfChunks) yield {
      var size = {
        // set to default chunk size unless current chunk exceeds the physical 
        // end of mapped space
        if ((i * defaultChunkSize + physRange.start) > physRange.end) {
          // only happens to last chunk
          assert(i == nrOfChunks)
          // cut excess
          (physRange.end - start).toInt
        } else defaultChunkSize
      }
      // create chunk
      val chunk = new Chunk(start, size, data)
      // move the starting point for the next chunk for one chunk-size
      start += size
      chunk
    }
  }

  /**
   * Returns the byte at the virtual offset.
   * Requires the offset to be within the virtual range of the mapping.
   *
   * @param virtOffset the virtual offset to read the byte from
   * @return byte at virtOffset
   */
  def apply(virtOffset: Long): Byte = {
    require(virtRange.contains(virtOffset))
    val pStart = physRange.start
    // relative offset from the start of the virtual range
    val relOffset = virtOffset - virtRange.start
    // absolute file offset to start reading from
    val readLocation = pStart + relOffset
    /* read using the chunks */
    if (useChunks) {
      readByteFromChunk(readLocation, relOffset)
    } else {
      /* read directly from file */
      readByteFromFile(readLocation)
    }
  }

  /**
   * Reads one byte from the fileOffset.
   *
   * @param fileOffset the physical address to read the byte from
   * @return byte
   */
  private def readByteFromFile(fileOffset: Long): Byte = {
    val file = data.getFile
    using(new RandomAccessFile(file, "r")) { raf =>
      raf.seek(fileOffset)
      raf.readByte()
    }
  }

  /**
   * Reads size bytes from the file.
   *
   * @param virtOffset the virtual address to read from
   * @param size number of bytes to read
   * @return array containing size bytes read from virtOffset
   */
  private def readBytesFromFile(virtOffset: Long, size: Int): Array[Byte] = {
    // relative offset from the virtual start of the current mapping
    val relOffset = virtOffset - virtRange.start
    // calculate file offset to start reading from
    val readLocation = physRange.start + relOffset
    val file = data.getFile
    using(new RandomAccessFile(file, "r")) { raf =>
      raf.seek(readLocation)
      // cut down read bytes if offset and size exceed the file length
      val length = (Math.min(readLocation + size, file.length) - readLocation).toInt
      // fill array with 0
      val bytes = zeroBytes(length)
      // read bytes
      raf.readFully(bytes)
      // append 0 bytes to array that where cut while calculating length
      val result = bytes ++ zeroBytes(size - bytes.length)
      assert(result.length == size)
      result
    }
  }

  /**
   * Reads one byte from a chunk.
   *
   * @param fileOffset the physical address to read the byte from
   * @param relOffset the relative offset from the beginning of the present mapping
   * @return read byte
   */
  private def readByteFromChunk(fileOffset: Long, relOffset: Long): Byte = {
    // calculate which chunk needs to be read and get it
    val chunkIndex = (relOffset / defaultChunkSize).toInt
    val chunk = chunks(chunkIndex)
    // assert that it was the right chunk
    assert(chunk.physStart <= fileOffset && chunk.physStart + chunk.size > fileOffset)
    // calculate the index of the byte within the chunk
    val byteIndex = (fileOffset - chunk.physStart).toInt
    // return byte
    chunk.bytes(byteIndex)
  }

  /**
   * Reads size bytes from the file.
   *
   * @param virtOffset the virtual address to read from
   * @param size number of bytes to read
   * @return array containing size bytes read from virtOffset
   */
  private def readBytesFromChunk(virtOffset: Long, size: Int): Array[Byte] = {
    val bytes = zeroBytes(size)
    // get every single byte via apply, TODO could be done more efficiently
    for (i <- 0 until size) {
      bytes(i) = apply(virtOffset + i)
    }
    bytes
  }

  /**
   * Returns size number of bytes at the virtual offset from mapping m.
   * Requires the offset + size to be within the virtual range of the mapping.
   *
   * @param virtOffset the virtual offset to start reading the bytes from
   * @param size of the returned array
   * @return array containing the bytes starting from virtOffset
   */
  def apply(virtOffset: Long, size: Int): Array[Byte] = {
    require(virtRange.contains(virtOffset) && virtRange.contains(virtOffset + size))
    /* read using the chunks */
    if (useChunks) {
      readBytesFromChunk(virtOffset, size)
    } else {
      /* read directly from file */
      readBytesFromFile(virtOffset, size)
    }
  }

}

object Mapping {

  /**
   * Turn chunk usage on or off.
   * TODO remove non-chunk usage entirely after testing this throughoughly
   * @Beta
   */
  var useChunks = true

  /**
   * The default size of a chunk.
   * This turned out to be a good value after some performance tests.
   *
   * TODO make this a val after performance tests are done
   * @Beta
   */
  var defaultChunkSize = 8192

  /**
   * A chunk of bytes with the given size. Loads the bytes lazily, but all bytes
   * at once. Improves performance for repeated access to bytes in the same area
   * compared to reading the file for every tiny slice of bytes.
   * 
   * @param physStart physical start of the chunk
   * @param size of the chunk in bytes
   * @param data the PEData object
   */
  private class Chunk(val physStart: Long, val size: Int, private val data: PEData) {
    lazy val bytes = {
      using(new RandomAccessFile(data.getFile, "r")) { raf =>
        val fileSize = data.getFile().length()
        val length = {
          if (physStart + size < fileSize) size
          else (fileSize - physStart).toInt
        }
        val array = Array.fill(length)(0.toByte)
        raf.seek(physStart)
        raf.readFully(array)
        val extended = array ++ zeroBytes(size - array.length)
        assert(extended.length == size)
        extended
      }
    }
  }
}

/**
 * Simply a range with start and end.
 *
 * @param start the start address
 * @param end the end address
 */
abstract class Range(val start: Long, val end: Long) {

  /**
   * Unpacking method to get a tuple
   * @return tuple consisting of start and end
   */
  def unpack(): (Long, Long) = (start, end)

  /**
   * Returns whether the value is within the range, including the values of
   * start and end.
   *
   * @param value the value to check
   * @return true iff value is within range (start and end inclusive)
   */
  def contains(value: Long): Boolean =
    start <= value && end >= value
    
  override def toString(): String = "Range(" + start + ", " + end + ")"
}

/**
 * Represents a range of in-memory addresses
 *
 * @param start the start address
 * @param end the end address
 */
class VirtRange(start: Long, end: Long) extends Range(start, end)

/**
 * Represents a range of physical addresses
 *
 * @param start the start address
 * @param end the end address
 */
class PhysRange(start: Long, end: Long) extends Range(start, end)