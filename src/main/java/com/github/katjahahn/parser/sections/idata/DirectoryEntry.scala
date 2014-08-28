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
package com.github.katjahahn.parser.sections.idata

import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import com.github.katjahahn.parser.ByteArrayUtil._
import com.github.katjahahn.parser.IOUtil.{ NL }
import com.github.katjahahn.parser.StandardField
import com.github.katjahahn.parser.IOUtil.SpecificationFormat
import com.github.katjahahn.parser.HeaderKey
import com.github.katjahahn.parser.IOUtil
import com.github.katjahahn.parser.Location
import com.github.katjahahn.parser.PhysicalLocation

/**
 * Represents a directory table entry. Contains all lookup table entries that
 * belong to it and allows to access them.
 *
 * @author Katja Hahn
 *
 * Instanciates a directory table entry with the map of entries that
 * represent the information belonging to the directory table entry. This map is
 * created by the {@link #apply} method of companion object
 *
 * @param entries that represent the information of the directory table entry
 */
class DirectoryEntry private (
  private val entries: Map[DirectoryEntryKey, StandardField], val offset: Long) {

  /**
   * The size of a directory entry is {@value}
   */
  val size = 20

  private var lookupTableEntries: List[LookupTableEntry] = Nil
  var name: String = _
  var forwarderString: String = _

  /**
   * adds a lookup table entry to the directory entry
   */
  def addLookupTableEntry(e: LookupTableEntry): Unit = {
    lookupTableEntries = lookupTableEntries :+ e
  }

  /**
   * Returns a list of all file locations where directory entries are found
   */
  def getLocations(): List[Location] = new PhysicalLocation(offset, size) ::
    //collect lookupTableEntry locations
    (for (entry <- lookupTableEntries) yield new PhysicalLocation(entry.offset, entry.size)) :::
    //collect HintNameEntry locations
    (lookupTableEntries collect { case e: NameEntry => 
      new PhysicalLocation(e.hintNameEntry.fileOffset, e.hintNameEntry.size) })

  def apply(key: DirectoryEntryKey): Long = {
    entries(key).value
  }

  /**
   * Converts the directory entry to an ImportDLL instance
   */
  def toImportDLL(): ImportDLL = {
    val nameImports = lookupTableEntries collect { case i: NameEntry => i.toImport.asInstanceOf[NameImport] }
    val ordImports = lookupTableEntries collect { case i: OrdinalEntry => i.toImport.asInstanceOf[OrdinalImport] }
    new ImportDLL(name, nameImports.asJava, ordImports.asJava)
  }

  def get(key: HeaderKey): java.lang.Long = apply(key.asInstanceOf[DirectoryEntryKey])

  def getEntries(): java.util.Map[DirectoryEntryKey, StandardField] = entries.asJava

  def getLookupTableEntries(): java.util.List[LookupTableEntry] = lookupTableEntries.asJava

  def getInfo(): String = s"""${entries.values.mkString(NL)} 
  |ASCII name: $name
  |${if (forwarderString != null) "Forwarder string: " + forwarderString + IOUtil.NL else ""}
  |lookup table entries for $name
  |--------------------------------------
  |
  |${lookupTableEntries.mkString(NL)}""".stripMargin

  override def toString(): String = getInfo()

}

object DirectoryEntry {

  private final val I_DIR_ENTRY_SPEC = "idataentryspec"

  /**
   * Instantiates the directory table entry based on the given entry bytes.
   *
   * @param entrybytes the bytes that represent the directory table entry and are
   * used to read the information
   * @return the constructed directory table entry
   */
  def apply(entrybytes: Array[Byte], offset: Long): DirectoryEntry = {
    val format = new SpecificationFormat(0, 1, 2, 3)
    val entries = IOUtil.readHeaderEntries(classOf[DirectoryEntryKey],
      format, I_DIR_ENTRY_SPEC, entrybytes.clone, offset).asScala.toMap
    new DirectoryEntry(entries, offset)
  }
}
