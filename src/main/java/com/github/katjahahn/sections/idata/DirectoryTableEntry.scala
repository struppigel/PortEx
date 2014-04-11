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
package com.github.katjahahn.sections.idata

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.PEModule
import com.github.katjahahn.IOUtil
import com.github.katjahahn.StandardEntry
import scala.collection.JavaConverters._
import com.github.katjahahn.PEModule._
import com.github.katjahahn.ByteArrayUtil._

/**
 * Represents a directory table entry. Contains all lookup table entries that 
 * belong to it and allows to access them.
 * 
 * @author Katja Hahn
 * 
 * @constructor instanciates a directory table entry with the map of entries that 
 * represent the information belonging to the directory table entry. This map is 
 * created by the {@link #apply} method of companion object
 * 
 * @param entries that represent the information of the directory table entry
 */
class DirectoryTableEntry (
  private val entries: Map[DirectoryTableEntryKey, StandardEntry]) extends PEModule {

  private var lookupTableEntries: List[LookupTableEntry] = Nil
  var name: String = _

  def addLookupTableEntry(e: LookupTableEntry): Unit = {
    lookupTableEntries = lookupTableEntries :+ e
  }

  /**
   * No use here, because object is used as factory instead
   */
  override def read(): Unit = {}

  def apply(key: DirectoryTableEntryKey): Long = {
    entries(key).value
  }

  override def getInfo(): String = s"""${entries.values.mkString(NL)} 
  |ASCII name: $name
  |
  |lookup table entries for $name
  |--------------------------------------
  |
  |${lookupTableEntries.mkString(NL)}""".stripMargin

  override def toString(): String = getInfo()

}

object DirectoryTableEntry {
  
   private final val I_DIR_ENTRY_SPEC = "idataentryspec"

  /**
   * Instantiates the directory table entry based on the given entry bytes
   * 
   * @param entrybytes the bytes that represent the directory table entry and are
   * used to read the information
   * @return the constructed directory table entry
   */
  def apply(entrybytes: Array[Byte]): DirectoryTableEntry = {
    val specification = IOUtil.readMap(I_DIR_ENTRY_SPEC).asScala.toMap
    val buffer = ListBuffer.empty[StandardEntry]
    for ((key, specs) <- specification) {
      val description = specs(0)
      val offset = Integer.parseInt(specs(1))
      val size = Integer.parseInt(specs(2))
      val value = getBytesLongValue(entrybytes.clone, offset, size)
      val entry = new StandardEntry(key, description, value) //TODO key
      buffer += entry
    }
    val entries: Map[DirectoryTableEntryKey, StandardEntry] = (buffer map { t => (t.key.asInstanceOf[DirectoryTableEntryKey], t) }).toMap;
    new DirectoryTableEntry(entries)
  }
}
