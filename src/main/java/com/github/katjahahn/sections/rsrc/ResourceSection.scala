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
package com.github.katjahahn.sections.rsrc

import com.github.katjahahn.sections.PESection
import scala.collection.JavaConverters._
import com.github.katjahahn.IOUtil

//TODO levels

class ResourceSection(
  private val rsrcbytes: Array[Byte],
  private val virtualAddress: Long) extends PESection {
  
  private var resourceTable: ResourceDirectoryTable = null
  
  //TODO super(rsrc bytes) call
  
  override def read(): Unit = {
    val initialLevel = 1
    val initialOffset = 0
    resourceTable = ResourceDirectoryTable(initialLevel, rsrcbytes, initialOffset)
  }

  override def getInfo(): String = resourceTable.getInfo
}
