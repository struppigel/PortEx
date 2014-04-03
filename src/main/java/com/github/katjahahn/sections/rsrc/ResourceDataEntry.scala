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
import com.github.katjahahn.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.ByteArrayUtil._
import com.github.katjahahn.StandardEntry

class ResourceDataEntry(val data: Map[ResourceDataEntryKey, StandardEntry]) {
  override def toString(): String = 
    s"""data entry
       |..........
       |
       |${data.values.map(_.toString()).mkString("\n")}
       |""".stripMargin
       
  def readResourceBytes(virtualAddress: Long, rsrcBytes: Array[Byte]): Array[Byte] = {
    val address = data(ResourceDataEntryKey.DATA_RVA).value - virtualAddress
    val length = data(ResourceDataEntryKey.SIZE).value + address
    rsrcBytes.slice(address.toInt, length.toInt)
  }

}

object ResourceDataEntry {
  val size = 16
  private val specLocation = "resourcedataentryspec"

  def apply(entryBytes: Array[Byte]): ResourceDataEntry = {
    val spec = IOUtil.readMap(specLocation).asScala.toMap
    val data = for ((sKey, sVal) <- spec) yield {
      val key = ResourceDataEntryKey.valueOf(sKey)
      val value = getBytesLongValue(entryBytes,
        Integer.parseInt(sVal(1)), Integer.parseInt(sVal(2)))
      val description = sVal(0)
      (key, new StandardEntry(key, description, value))
    }
    new ResourceDataEntry(data)
  }
}
