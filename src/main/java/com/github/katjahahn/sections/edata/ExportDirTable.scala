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
package com.github.katjahahn.sections.edata

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.StandardEntry
import com.github.katjahahn.IOUtil
import scala.collection.JavaConverters._
import com.github.katjahahn.ByteArrayUtil._
import com.github.katjahahn.PEModule._
import com.github.katjahahn.PEModule
import com.github.katjahahn.HeaderKey

/**
 * @author Katja Hahn
 * 
 * Represents the directory table of the export section and provides access to the
 * header values.
 * 
 * The export directory table should be loaded by an {@link ExportSection} instance.
 * 
 * @constructor instanciates an export directory table. 
 */
class ExportDirTable private (
    private val entries: Map[ExportDirTableKey, StandardEntry]) {
  
  def apply(key: ExportDirTableKey): Long = entries(key).value
 
  /**
   * Returns the {@link StandardEntry} for a given {@link ExportDirTableKey}
   * 
   * @param key a key of the export directory table
   * @return the standard entry for the given key
   */
  def get(key: HeaderKey): java.lang.Long = apply(key.asInstanceOf[ExportDirTableKey])
  
  def getInfo(): String = entries.values.mkString(NL)
  
  override def toString(): String = getInfo

}

object ExportDirTable {

  private val edataTableSpec = "edatadirtablespec"

  /**
   * Loads the export directory table with the given bytes. It is assumed that the
   * table starts at offset 0 at the byte array.
   * 
   * @param entrybytes
   * @return export directory table instance
   */
  def apply(entrybytes: Array[Byte]): ExportDirTable = {
    val specification = IOUtil.readMap(edataTableSpec).asScala.toMap
    val buffer = ListBuffer.empty[StandardEntry]
    for ((key, specs) <- specification) {
      val description = specs(0)
      val offset = Integer.parseInt(specs(1))
      val size = Integer.parseInt(specs(2))
      val value = getBytesLongValue(entrybytes.clone, offset, size)
      val ekey = ExportDirTableKey.valueOf(key)
      val entry = new StandardEntry(ekey, description, value)
      buffer += entry
    }
    val entries: Map[ExportDirTableKey, StandardEntry] = (buffer map { t => (t.key.asInstanceOf[ExportDirTableKey], t) }).toMap;
    new ExportDirTable(entries)
  }

}
