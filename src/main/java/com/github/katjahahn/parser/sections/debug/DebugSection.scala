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
package com.github.katjahahn.parser.sections.debug

import com.github.katjahahn.parser.IOUtil._
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.ByteArrayUtil._
import DebugSection._
import java.io.File
import DebugDirectoryKey._
import java.util.Date
import com.github.katjahahn.parser.sections.SectionLoader
import com.github.katjahahn.parser.PELoader
import com.github.katjahahn.parser.sections.SpecialSection
import com.github.katjahahn.parser.PEData
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.IOUtil

/**
 * @author Katja Hahn
 *
 * Represents the debug section of the PE.
 */
class DebugSection private (
  private val directoryTable: DebugDirectory,
  private val typeDescription: String,
  val offset: Long) extends SpecialSection {

  override def getOffset(): Long = offset

  def getSize(): Long = 28

  override def getInfo(): String =
    s"""|-------------
        |Debug Section
        |-------------
        |
        |${
      directoryTable.values.map(s => s.key match {
        case TYPE => "Type: " + typeDescription
        case TIME_DATE_STAMP => "Time date stamp: " + getTimeDateStamp().toString
        case _ => s.toString
      }).mkString(NL)
    }""".stripMargin

  /**
   * Returns a date object of the time date stamp in the debug section.
   *
   * @return date of the time date stamp
   */
  def getTimeDateStamp(): Date = new Date(get(TIME_DATE_STAMP) * 1000)

  /**
   * Returns a long value of the given key or null if the value doesn't exist.
   *
   * @param key the header key
   * @return long value for the given key of null if it doesn't exist.
   */
  def get(key: DebugDirectoryKey): java.lang.Long =
    if (directoryTable.contains(key))
      directoryTable(key).value else null

  /**
   * Returns a string of the type description
   *
   * @return type description string
   */
  def getTypeDescription(): String = typeDescription

}

object DebugSection {

  type DebugDirectory = Map[DebugDirectoryKey, StandardField]

  private val debugspec = "debugdirentryspec"

  def main(args: Array[String]): Unit = {
    val file = new File("/home/deque/portextestfiles/testfiles/ntdll.dll")
    val data = PELoader.loadPE(file)
    val loader = new SectionLoader(data)
    val debug = loader.loadDebugSection()
    println(debug.getInfo())
  }

  /**
   * Creates an instance of the DebugSection for the given debug bytes.
   *
   * @param debugbytes the byte array that represents the debug section
   * @param offset the debug sections starts at
   * @return debugsection instance
   */
  def newInstance(debugbytes: Array[Byte], offset: Long): DebugSection = apply(debugbytes, offset)

  /**
   * Loads the debug section and returns it.
   *
   * This is just a shortcut to loading the section using the {@link SectionLoader}
   *
   * @return instance of the debug section
   */
  def load(data: PEData): DebugSection =
    new SectionLoader(data).loadDebugSection()

  def apply(debugbytes: Array[Byte], offset: Long): DebugSection = {
    val format = new SpecificationFormat(0, 1, 2, 3)
    val entries = IOUtil.readHeaderEntries(classOf[DebugDirectoryKey],
      format, debugspec, debugbytes.clone).asScala.toMap
    val types = getCharacteristicsDescriptions(entries(DebugDirectoryKey.TYPE).value, "debugtypes").asScala.toList
    new DebugSection(entries, types(0), offset)
  }
}