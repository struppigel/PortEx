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

import MemoryMappedPE._

/**
 * Represents the PE file content as it is mapped to memory.
 * <p>
 * Only maps section bytes for now. This is the first test with the content loaded
 * all at once. Will be changed later.
 */
class MemoryMappedPE(
  private val bytes: Array[Byte],
  private val mappings: List[Mapping],
  private val data: PEData) {

  /**Array-like methods**/

  /**
   * Returns byte at position i.
   * <p>
   * Scala only.
   * @param i index/position
   * @return byte at position i
   */
  //TODO test this
  def apply(i: Long): Byte = {

    val mapping = mappings.find(m => isWithin(i, m.va))
    mapping match {
      case Some(m) => readByteAt(m, i)
      case None => 0.toByte
    }
  }

  private def isWithin(value: Long, range: Range): Boolean =
    range.start <= value && range.end >= value

  private def readByteAt(m: Mapping, virtOffset: Long): Byte = {
    val pStart = m.physA.start
    val relOffset = virtOffset - m.va.start
    val readLocation = pStart + relOffset
    val file = data.getFile
    using(new RandomAccessFile(file, "r")) { raf =>
      raf.seek(readLocation)
      raf.readByte()
    }
  }

  private def readBytesAt(m: Mapping, virtOffset: Long, size: Int): Array[Byte] = {
    val pStart = m.physA.start
    val relOffset = virtOffset - m.va.start
    val readLocation = pStart + relOffset
    val file = data.getFile
    using(new RandomAccessFile(file, "r")) { raf =>
      raf.seek(readLocation)
      val bytes = Array.fill(size)(0.toByte)
      raf.readFully(bytes)
      bytes
    }
  }

  private def using[A, B <: { def close(): Unit }](closeable: B)(f: B => A): A =
    try { f(closeable) } finally { closeable.close() }

  /**
   * Returns byte at position i.
   *
   * @param i index/position
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
  def length(): Long = mappings.last.va.end

  /**
   * Creates an array of the specified segment.
   * <p>
   * The distance until-from has to be in Integer range.
   *
   * @param from
   * @param until
   * @return byte array containing the bytes from the specified segment
   */
  //TODO
  def slice(from: Long, until: Long): Array[Byte] = {
    if (from > length) {
      Array.fill((until - from).toInt)(0.toByte)
    } else if (until > length) {
      bytes.slice(from.toInt, length.toInt) ++ Array.fill((until - length).toInt)(0.toByte)
    } else
      bytes.slice(from.toInt, until.toInt)
  }

  /**
   * Returns the index of the first byte that satisfies the condition.
   *
   * @param p the function that specifies the condition
   * @param from offset to start searching from
   * @return index of the first byte that satisfies the condition
   */
  //TODO
  def indexWhere(p: Byte => Boolean, from: Long): Long = bytes.indexWhere(p, from.toInt)

  /**
   * Returns the index of the first byte that has the value.
   *
   * @param value value of the byte searched for
   * @param from offset to start searching from
   * @return index of the first byte that has the value
   */
  def indexOf(elem: Byte, from: Long): Long = bytes.indexOf(elem, from.toInt)

  /**ByteArrayUtil methods**/

  def getBytesIntValue(offset: Long, length: Int): Int =
    ByteArrayUtil.bytesToInt(this.slice(offset, offset + length))

  def getBytesLongValue(offset: Long, length: Int): Long =
    ByteArrayUtil.bytesToLong(this.slice(offset, offset + length))

}

object MemoryMappedPE {

  //in byte
  val chunkSize = 512

  /**defines largest parts for mapping physical -> virtual**/
  abstract class Range(val start: Long, val end: Long)
  class VirtRange(start: Long, end: Long) extends Range(start, end)
  class PhysRange(start: Long, end: Long) extends Range(start, end)

  case class Mapping(va: VirtRange, physA: PhysRange)

  def newInstance(data: PEData, secLoader: SectionLoader): MemoryMappedPE =
    apply(data, secLoader)

  /**
   * Creates a representation of the PE content as it is mapped into memory
   */
  def apply(data: PEData, secLoader: SectionLoader): MemoryMappedPE = {
    val bytes = readMemoryMappedSectionBytes(data, secLoader)
    val mappings = readMemoryMappings(data, secLoader)
    new MemoryMappedPE(bytes, mappings, data)
  }

  /**
   * Reads memory mappings for the sections. This shall replace the bytes read
   */
  private def readMemoryMappings(data: PEData, secLoader: SectionLoader): List[Mapping] = {
    val optHeader = data.getOptionalHeader
    if (optHeader.isLowAlignmentMode()) {
      val filesize = data.getFile.length
      List(Mapping(new VirtRange(0, filesize), new PhysRange(0, filesize)))
    } else {
      val table = data.getSectionTable
      val mappings = ListBuffer[Mapping]()
      val maxVA = getMaxVA(table, secLoader)
      for (header <- table.getSectionHeaders().asScala) {
        if (secLoader.isValidSection(header)) {
          val start = header.getAlignedVirtualAddress()
          val end = start + header.getAlignedVirtualSize()
          val virtRange = new VirtRange(start, end)
          val pStart = header.getAlignedPointerToRaw()
          val pEnd = pStart + secLoader.getReadSize(header)
          val physRange = new PhysRange(pStart, pEnd)
          mappings += Mapping(virtRange, physRange)
        }
      }
      mappings.toList
    }
  }

  /**
   * Reads all section bytes at once into a byte array.
   */
  private def readMemoryMappedSectionBytes(data: PEData, secLoader: SectionLoader): Array[Byte] = {
    val optHeader = data.getOptionalHeader
    val table = data.getSectionTable
    if (optHeader.isLowAlignmentMode()) {
      Files.readAllBytes(data.getFile.toPath)
    } else {
      val maxVA = getMaxVA(table, secLoader)
      //TODO here is the problem -- it might be that it doesn't fit in an Int
      val bytes = Array.fill(maxVA.toInt)(0.toByte)
      for (header <- table.getSectionHeaders().asScala) {
        if (secLoader.isValidSection(header)) {
          val start = header.getAlignedVirtualAddress()
          val end = start + header.getAlignedVirtualSize()
          val secBytes = secLoader.loadSectionFrom(header).getBytes()
          for (i <- start until Math.min(end, secBytes.length + start)) {
            bytes(i.toInt) = secBytes((i - start).toInt)
          }
        }
      }
      bytes
    }
  }

  private def getMaxVA(table: SectionTable, secLoader: SectionLoader): Long =
    table.getSectionHeaders().asScala.foldRight(0L) { (header, max) =>
      val headerEnd = header.getAlignedVirtualAddress() + header.getAlignedVirtualSize()
      if (secLoader.isValidSection(header) && headerEnd > max) headerEnd else max
    }

}