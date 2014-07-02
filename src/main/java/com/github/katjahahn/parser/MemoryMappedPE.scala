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

import com.github.katjahahn.parser.sections.SectionTable
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.sections.SectionHeaderKey._
import com.github.katjahahn.parser.sections.SectionLoader
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.optheader.OptionalHeader
import java.nio.file.Files

/**
 * Represents the PE file content as it is mapped to memory.
 * <p>
 * Only maps section bytes for now. This is the first test with the content loaded
 * all at once. Will be changed later.
 */
class MemoryMappedPE(private val bytes: Array[Byte]) {

  private var relativeVA = 0

  /**Java getters and setters**/

  def getRelativeVA() = relativeVA
  def setRelativeVA(value: Int): Unit = relativeVA = value

  /**Array-like methods**/

  /**
   * Returns byte at position i relative to relativeVA.
   * <p>
   * Scala only.
   * @param i index/position
   * @return byte at position i
   */
  def apply(i: Long): Byte = bytes((relativeVA + i).toInt)
  /**
   * Returns byte at position i relative to relativeVA.
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
  def length(): Int = bytes.length

  /**
   * Creates an array of the specified segment.
   * <p>
   * The distance until-from has to be in Integer range.
   *
   * @param from
   * @param until
   * @return byte array containing the bytes from the specified segment
   */
  def slice(from: Long, until: Long): Array[Byte] = {
    if (from > length) {
      Array.fill((until - from).toInt)(0.toByte)
    } else if (until > length) {
      bytes.slice(from.toInt, length) ++ Array.fill((until - length).toInt)(0.toByte)
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

  def newInstance(data: PEData, secLoader: SectionLoader): MemoryMappedPE =
    apply(data, secLoader)

  /**
   * Creates a representation of the PE content as it is mapped into memory
   */
  def apply(data: PEData, secLoader: SectionLoader): MemoryMappedPE = {
    val bytes = readMemoryMappedSectionBytes(data, secLoader)
    new MemoryMappedPE(bytes)
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