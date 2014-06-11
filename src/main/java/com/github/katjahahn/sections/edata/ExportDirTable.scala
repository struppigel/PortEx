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
package com.github.katjahahn.sections.edata

import scala.collection.mutable.ListBuffer
import com.github.katjahahn.StandardField
import com.github.katjahahn.IOUtil.{ NL, readMap }
import scala.collection.JavaConverters._
import com.github.katjahahn.ByteArrayUtil._
import com.github.katjahahn.HeaderKey
import com.github.katjahahn.IOUtil
import com.github.katjahahn.IOUtil.SpecificationFormat

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
class ExportDirTable private (
  private val entries: Map[ExportDirTableKey, StandardField]) {

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
    val format = new SpecificationFormat(0, 1, 2, 3)
    val entries = IOUtil.readHeaderEntries(classOf[ExportDirTableKey], format, 
        edataTableSpec, entrybytes.clone).asScala.toMap
    new ExportDirTable(entries)
  }

}
