/**
 * *****************************************************************************
 * Copyright 2022 Karsten Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ****************************************************************************
 */

package com.github.katjahahn.parser.sections.clr

import com.github.katjahahn.parser.{ByteArrayUtil, MemoryMappedPE}

class ModuleTable(private val generation : Int,
                  private val name : StringIndex,
                  private val mvid : GuidIndex,
                  private val encId : GuidIndex,
                  private val encBaseId : GuidIndex) {

  def getMvid(): GuidIndex = mvid

  def getEncId(): GuidIndex = encId

  def getEncBaseId(): GuidIndex = encBaseId

  def getGeneration(): Int = generation

  def getName(): String = name.toString

  override def toString(): String = {
    "Generation: " + generation + ", Name: " + name + ", MVID: " + mvid + ", EncId: " +
     encId + ", EncBaseId: " + encBaseId
  }

}

object ModuleTable {
  def apply(offset : Long, mmbytes : MemoryMappedPE, stringsHeap: Option[StringsHeap], guidHeap : Option[GuidHeap]): ModuleTable = {
    // TODO set proper index sizes using the guid and string heap
    val strIndexSize = 2
    val guidIndexSize = 2
    val generation = ByteArrayUtil.bytesToInt(mmbytes.slice(offset, offset + 2))

    val nameOffset = offset + 2
    val nameIdx = ByteArrayUtil.bytesToInt(mmbytes.slice(nameOffset, nameOffset + strIndexSize))
    val name = new StringIndex(nameIdx, stringsHeap)

    val mvidOffset = nameOffset + strIndexSize
    val mvidIdx = ByteArrayUtil.bytesToInt(mmbytes.slice(mvidOffset, mvidOffset + guidIndexSize))
    val mvid = new GuidIndex(mvidIdx, guidHeap)

    val encIdOffset = mvidOffset + guidIndexSize
    val encIdx = ByteArrayUtil.bytesToInt(mmbytes.slice(encIdOffset, encIdOffset + guidIndexSize))
    val encId = new GuidIndex(encIdx, guidHeap)

    val encBaseOffset = encIdOffset + guidIndexSize
    val encBaseIdIdx = ByteArrayUtil.bytesToInt(mmbytes.slice(encBaseOffset, encBaseOffset + guidIndexSize))
    val encBaseId = new GuidIndex(encBaseIdIdx, guidHeap)

    new ModuleTable(generation, name, mvid, encId, encBaseId)
  }
}
