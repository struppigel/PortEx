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

import com.github.katjahahn.parser.MemoryMappedPE

class ModuleTable(val generation : Int,
                  val name : StringIndex,
                  val mvid : GuidIndex,
                  val encId : GuidIndex,
                  val encBaseId : GuidIndex) {

}

object ModuleTable {
  def apply(offset : Long, mmbytes : MemoryMappedPE, stringsHeap: Option[StringsHeap], guidHeap : Option[GuidHeap]): ModuleTable = {
    val generation = 0
    val name = new StringIndex(0, stringsHeap)
    val mvid = new GuidIndex(0, guidHeap)
    val encId = new GuidIndex(0, guidHeap)
    val encBaseId = new GuidIndex(0, guidHeap)
    new ModuleTable(generation, name, mvid, encId, encBaseId)
  }
}
