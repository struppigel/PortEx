/**
 * *****************************************************************************
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
 * ****************************************************************************
 */
package com.github.katjahahn.sections.rsrc

import com.github.katjahahn.IOUtil
import com.github.katjahahn.StandardEntry
import com.github.katjahahn.ByteArrayUtil._
import scala.collection.JavaConverters._
import com.github.katjahahn.sections.rsrc.ResourceDirectoryTableKey._
import scala.collection.mutable.ListBuffer

class ResourceDirectoryTable(
  private val header: Map[ResourceDirectoryTableKey, StandardEntry],
  private val entries: List[ResourceDirectoryEntry]) {

  def getInfo(): String =
    s"""|Resource Dir Table Header
        |-------------------------
        |
        |${header.values.map(_.toString()).mkString("\n")}
        |
        |${entries.map(_.toString()).mkString("\n")}
        |""".stripMargin
}

object ResourceDirectoryTable {

  type Header = Map[ResourceDirectoryTableKey, StandardEntry]
  type Specification = Map[String, Array[String]]

  private val entrySize = 8;
  private val resourceDirOffset = 16;
  private val specLocation = "rsrcdirspec"

  def apply(tableBytes: Array[Byte], offset: Long): ResourceDirectoryTable = {
    val spec = IOUtil.readMap(specLocation).asScala.toMap
    val header = readHeader(spec, tableBytes)
//    println("\ncreated header! \n\n" + header.values.map(_.toString()).mkString("\n"))
    val nameEntries = header(NR_OF_NAME_ENTRIES).value.toInt
    val idEntries = header(NR_OF_ID_ENTRIES).value.toInt
    val entries = readEntries(header, nameEntries, idEntries, tableBytes, offset)
    return new ResourceDirectoryTable(header, entries)
  }

  private def readHeader(spec: Specification,
    tableBytes: Array[Byte]): Header = {
    for ((s1, s2) <- spec) yield {
      val key = ResourceDirectoryTableKey.valueOf(s1)
      val value = getBytesLongValue(tableBytes,
        Integer.parseInt(s2(1)), Integer.parseInt(s2(2)))
      val standardEntry = new StandardEntry(key, s2(0), value)
      (key, standardEntry)
    }
  }

  private def readEntries(header: Header, nameEntries: Int, idEntries: Int,
    tableBytes: Array[Byte], tableOffset: Long): List[ResourceDirectoryEntry] = {
    val entriesSum = nameEntries + idEntries
//    println("\nreading all " + entriesSum + " entries for header with offset " + tableOffset + "\n")
    var entries = ListBuffer.empty[ResourceDirectoryEntry]
    for (i <- 0 until entriesSum) {
//      println("reading entry " + i);
      val offset = resourceDirOffset + i * entrySize
//      println("offset for entry " + i + " = " + offset)
      val endpoint = offset + entrySize
      val entryNr = i + 1
      val entryBytes = tableBytes.slice(offset, endpoint)
      val isNameEntry = i < nameEntries
      entries += ResourceDirectoryEntry(isNameEntry, entryBytes, entryNr,
        tableBytes, tableOffset)
    }
    entries.toList
  }
}
