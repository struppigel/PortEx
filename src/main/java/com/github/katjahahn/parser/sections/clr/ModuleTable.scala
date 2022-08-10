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

import com.github.katjahahn.parser.{MemoryMappedPE, ScalaIOUtil}
import com.github.katjahahn.parser.ByteArrayUtil._

import scala.collection.JavaConverters._

class ModuleTable(val nameIndex: Long, val name: String, val mvid: Int) {

}

object ModuleTable {
  def apply(stringHeapOffset: Long, moduleTblOffset : Long, mmbytes: MemoryMappedPE, guidHeapSize : Int, stringHeapSize : Int): ModuleTable = {
    val mvid = 0
    var currOffset = moduleTblOffset + 2 // skip Generation value
    val nameIndex = getBytesLongValue(mmbytes.slice(currOffset, currOffset + stringHeapSize).toArray, 0, stringHeapSize)
    val strVA = mmbytes._physToVirtAddresses(stringHeapOffset + nameIndex)(0)
    println("strPhys: 0x" + (stringHeapOffset + nameIndex).toHexString) // should be 4D0BD
    println("name Index 0x" + nameIndex.toHexString)
    println("bsjb 0x" + stringHeapOffset.toHexString)
    val name = "not implemented"
   // val name = ScalaIOUtil.readZeroTerminatedUTF8StringAtRVA(strVA, mmbytes, 100)
    println("NAME: " + name)
    new ModuleTable(nameIndex, name, mvid)
  }
}
