/**
 * *****************************************************************************
 * Copyright 2023 Karsten Hahn
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
package io.github.struppigel.parser.sections.clr

import BlobHeap.logger
import io.github.struppigel.parser.{ByteArrayUtil}
import io.github.struppigel.parser.{MemoryMappedPE, ScalaIOUtil}
import io.github.struppigel.parser.sections.idata.DelayLoadSection
import org.apache.logging.log4j.LogManager

/**
 * #Blob stream/heap
 *
 * @param indexSize
 * @param mmbytes
 * @param offset
 * @param size
 */
class BlobHeap(private val indexSize : Int,
                  private val mmbytes : MemoryMappedPE,
                  private val offset: Long,
                  private val size: Long) {

  private lazy val bytes = mmbytes.slice(offset, offset + size)

  /**
   * Retrieve byte array of blob at the given index, returns empty array if invalid blob
   * @param index
   * @return string at index
   */
  def get(index : Long): Array[Byte] = {
    require(index >= 0)
    require(index < size)
    // see II.24.2.4, page 272 in specification
    val (blobSize : Long, blobDataStart : Long) = {
      val sizeByte = mmbytes.get(offset + index).toLong
      if((Integer.parseInt("10000000",2) & sizeByte) == 0) { //smallest blob size
        (sizeByte, 1L + offset + index)
      } else if ((Integer.parseInt("11000000",2) & sizeByte) == 128) { //medium blob size
        //(bbbbbb << 8 + x)
        val s = (Integer.parseInt("00111111",2) & sizeByte).toLong << 8L
        val x = mmbytes.get(offset + index + 1).toLong
        val resultSize = s + x
        (resultSize, 2L + offset + index)
      } else if ((Integer.parseInt("11100000",2) & sizeByte) == 192) { //biggest blob size
        // (bbbbb << 24 + x << 16 + y << 8 + z)
        val s = (Integer.parseInt("00011111",2) & sizeByte).toLong << 24L
        val x = mmbytes.get(offset + index + 1).toLong << 16L
        val y = mmbytes.get(offset + index + 2).toLong << 8L
        val z = mmbytes.get(offset + index + 3).toLong
        val resultSize = s + x + y + z
        (resultSize, 4L + offset + index)
      } else {
        logger.warn("invalid blob entry size at index " + index + " !")
        (0L, 0L)  // unknown blob size!
      }
    }
    val blobArray = mmbytes.slice(blobDataStart, blobDataStart + blobSize)
    blobArray
  }

  def getIndexSize() : Int = indexSize

  def getSizeInBytes() : Long = size
}

object BlobHeap {

  private final val logger = LogManager.getLogger(BlobHeap.getClass().getName())

  def apply(size: Long, offset : Long, mmbytes: MemoryMappedPE, indexSize : Int): BlobHeap = {
    new BlobHeap(indexSize, mmbytes, offset, size)
  }
}
