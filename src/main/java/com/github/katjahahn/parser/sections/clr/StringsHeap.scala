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

/**
 * #Strings stream/heap
 *
 * @param strings the array with the UTF-8 strings on the heap
 */
class StringsHeap(private val indexSize : Int,
                  private val mmbytes : MemoryMappedPE,
                  private val offset: Long,
                  private val size: Long) {

  private lazy val bytes = mmbytes.slice(offset, offset + size)
  private val maxStrOffset = offset + size

  /**
   * Retrieve string at the given index, starting with index 1 as it is customary for .NET table indices
   * @param index
   * @return string at index
   */
  def get(index : Long): String = {
    assert(index > 0)
    assert(index < size)
    new String(mmbytes.slice(offset + index, maxStrOffset).takeWhile(_ != 0), "UTF-8")
  }

  def getArray() : Array[String] = new String(bytes, "UTF-8").split("\0")

  def getIndexSize() : Int = indexSize
}

object StringsHeap {

  def apply(size: Long, offset : Long, mmbytes: MemoryMappedPE, indexSize : Int): StringsHeap = {
    new StringsHeap(indexSize, mmbytes, offset, size)
  }
}
