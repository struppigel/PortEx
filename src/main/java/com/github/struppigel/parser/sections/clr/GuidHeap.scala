/**
 * *****************************************************************************
 * Copyright 2022 Karsten Hahn
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

package com.github.struppigel.parser.sections.clr

import com.github.struppigel.parser.{MemoryMappedPE, ScalaIOUtil}

import java.util.UUID

class GuidHeap(private val indexSize : Int,
               private val mmbytes : MemoryMappedPE,
               private val offset: Long,
               private val size: Long) {

  private lazy val bytes = mmbytes.slice(offset, offset + size)
  val uuidSize = 16
  val nrOfGuids = (size.toDouble / uuidSize.toDouble).floor.toInt

  /**
   * returns the VA of the GUID heap
   * @return va - offset of heap start
   */
  def getOffset() : Long = offset

  /**
   * Array containing all bytes of the GUID heap
   * @return heap dump array
   */
  def getHeapDump() : Array[Byte] = bytes

  /**
   * How many bytes are used to save an index, usually this value is 2 unless the guid heap is very large.
   * @return
   */
  def getIndexSize() : Int = indexSize

  /**
   * The size of the GUID heap in bytes
   * @return
   */
  def getSizeInBytes() : Long = size

  /**
   * The number of GUIDs saved in the GUID heap
   * @return
   */
  def getNumberOfGuids() : Int = nrOfGuids

  /**
   * The GUID at the given offset. The offset is relative to the start of the GUID heap
   * @param guidOffset
   * @return
   */
  def getGUIDAtHeapOffset(guidOffset : Long) : UUID = {
    require(guidOffset >= 0 && guidOffset <= (size-uuidSize))
    val guidStartVA = getOffset + guidOffset
    val uuidBytes = mmbytes.slice(guidStartVA, guidStartVA + uuidSize)
    ScalaIOUtil.convertBytesToUUID(uuidBytes)
  }

  def indexToHeapOffset(index : Long) : Long = (index - 1) * uuidSize

  def get(index : Long) : UUID = {
    require(index > 0 && index <= nrOfGuids)
    getGUIDAtHeapOffset(indexToHeapOffset(index))
  }

}

object GuidHeap {

  def apply(size: Long, offset : Long, mmbytes: MemoryMappedPE, indexSize : Int): GuidHeap = {
    new GuidHeap(indexSize, mmbytes, offset, size)
  }
}