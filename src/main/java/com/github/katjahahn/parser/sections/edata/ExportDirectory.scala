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
package com.github.katjahahn.parser.sections.edata

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.IOUtil.{ NL, readMap }
import scala.collection.JavaConverters._
import com.github.katjahahn.parser.ByteArrayUtil._
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.HeaderKey
import com.github.katjahahn.parser.IOUtil

/**
 * Represents the directory table of the export section and provides access to the
 * header values.
 * <p>
 * The export directory table should be loaded by an {@link ExportSection} instance.
 *
 * @author Katja Hahn
 *
 * instanciates an export directory table.
 */
class ExportDirectory private (
  private val entries: Map[ExportDirectoryKey, StandardField], 
  val fileOffset: Long) {
  
  def apply(key: ExportDirectoryKey): Long = entries(key).value
  def size(): Long = 40

  /**
   * Returns the {@link StandardEntry} for a given {@link ExportDirectoryKey}
   *
   * @param key a key of the export directory table
   * @return the standard entry for the given key
   */
  def get(key: HeaderKey): java.lang.Long = apply(key.asInstanceOf[ExportDirectoryKey])

  def getInfo(): String = entries.values.mkString(NL)

  override def toString(): String = getInfo

}

object ExportDirectory {

  private val edataTableSpec = "edatadirtablespec"

  /**
   * Loads the export directory table with the given bytes. It is assumed that the
   * table starts at offset 0 at the byte array.
   *
   * @param entrybytes
   * @return export directory table instance
   */
  def apply(entrybytes: Array[Byte], fileOffset: Long): ExportDirectory = {
    val format = new SpecificationFormat(0, 1, 2, 3)
    val entries = IOUtil.readHeaderEntries(classOf[ExportDirectoryKey], format, 
        edataTableSpec, entrybytes.clone, fileOffset).asScala.toMap
    new ExportDirectory(entries, fileOffset)
  }

}
