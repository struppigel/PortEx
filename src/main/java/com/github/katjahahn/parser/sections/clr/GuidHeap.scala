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

package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.MemoryMappedPE

import java.util.UUID

class GuidHeap(private val indexSize : Int,
               private val mmbytes : MemoryMappedPE,
               private val offset: Long,
               private val size: Long) {

  private lazy val bytes = mmbytes.slice(offset, offset + size)
  val uuidSize = 16

  def getIndexSize() : Int = indexSize

  def get(index : Long) : UUID = {
    assert(index > 0)
    assert(index < size)
    UUID.nameUUIDFromBytes(mmbytes.slice(offset + index, offset + index + uuidSize))
  }

}

object GuidHeap {

  def apply(size: Long, offset : Long, mmbytes: MemoryMappedPE, indexSize : Int): GuidHeap = {
    new GuidHeap(indexSize, mmbytes, offset, size)
  }
}