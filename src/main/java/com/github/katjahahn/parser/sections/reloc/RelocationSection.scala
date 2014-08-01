/*******************************************************************************
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
 ******************************************************************************/

package com.github.katjahahn.parser.sections.reloc

import com.github.katjahahn.parser.sections.SectionLoader.LoadInfo
import com.github.katjahahn.parser.optheader.WindowsEntryKey
import com.github.katjahahn.parser.optheader.StandardFieldEntryKey
import com.github.katjahahn.parser.optheader.DataDirectoryKey
import scala.collection.mutable.ListBuffer

class RelocationSection(blocks : List[BaseRelocBlock]) {

}

object RelocationSection {
  
  def apply(loadInfo: LoadInfo): RelocationSection = {
    val opt = loadInfo.data.getOptionalHeader
    val tableSize = opt.getDataDirEntries().get(DataDirectoryKey.BASE_RELOCATION_TABLE).getDirectorySize()
    val blocks = readBlocks(tableSize, loadInfo)
    new RelocationSection(blocks)
  }
  
  private def readBlocks(tableSize: Long, loadInfo: LoadInfo): List[BaseRelocBlock] = {
    val mmBytes = loadInfo.memoryMapped
    val va = loadInfo.va
    val buf = ListBuffer[BaseRelocBlock]()
    var offset = 0
    while(offset < tableSize) {
      val length = 4
      val pageRVA = mmBytes.getBytesLongValue(va + offset, length)
      offset += length
      val blockSize = mmBytes.getBytesIntValue(offset, length)
      
    }
    buf.toList
  }
  
  def newInstance(loadInfo: LoadInfo): RelocationSection = 
    apply(loadInfo)
}